// Disables xHCI (USB host controller) Interrupt Moderation (IMOD) for every
// interrupter on every xHCI controller found in the system, by writing 0 to
// each controller's IMOD register(s) directly in MMIO space.
//
// Run once per boot; the controllers are found through Windows PnP and the
// interrupter layout is read fresh from the xHCI capability registers every run.
//
// Interactively it shows a menu (disable / test at 62.5Hz / startup options
// / exit) before loading any driver or touching a register, and returns to
// it after each option until Exit. Startup options (add to Task Scheduler /
// add to Registry Run / remove from startup) copy this exe and its drivers
// to C:\Windows\IMOD first and point the entry at that copy. Pass -silent
// for unattended use: no console, no menu, IMOD is disabled directly. Every
// run is logged to %LOCALAPPDATA%\xHCI IMOD\Log.txt.
//
// The exe is manifested to require administrator privileges, so launching
// it interactively triggers UAC on its own.
//
// Two drivers are used:
//   - WinRing0 (WinRing0x64.dll/.sys): PCI config space access, to read each
//     controller's BAR0 and memory-enable state. It is the primary way the
//     registers are located; if it is not present or cannot start, the address
//     Windows assigned to the controller is used as a fallback.
//   - InpOutX64 (inpoutx64.dll/.sys): MMIO reads/writes of the actual
//     capability/runtime/interrupter registers. Required.
// Both must sit next to this executable.

#include <windows.h>
#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <conio.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <fstream>
#include <initializer_list>
#include <string>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

// Driver export signatures

using InitializeOls_t        = BOOL(WINAPI*)();
using DeinitializeOls_t      = VOID(WINAPI*)();
using GetDllStatus_t         = DWORD(WINAPI*)();
using ReadPciConfigDwordEx_t = BOOL(WINAPI*)(DWORD pciAddress, DWORD regAddress, PDWORD value);
using MapPhysToLin_t         = PBYTE(WINAPI*)(PBYTE physAddress, DWORD size, PHANDLE physMemHandle);
using UnmapPhysicalMemory_t  = BOOL(WINAPI*)(HANDLE physMemHandle, PBYTE linAddress);

// Text helpers

static std::string ToUtf8(const std::wstring& value) {
    if (value.empty()) return "";
    const int wideLen = static_cast<int>(value.size());
    const int len = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), wideLen, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), wideLen, result.data(), len, nullptr, nullptr);
    return result;
}

// Dynamic driver loading

// Resolves <exe directory>\<fileName>, so a failed load reports the exact
// path tried regardless of working directory or how the process was launched.
static std::wstring DllPathNextToExe(const std::string& fileName) {
    wchar_t exePathBuf[MAX_PATH];
    GetModuleFileNameW(nullptr, exePathBuf, MAX_PATH);
    std::wstring path(exePathBuf);
    size_t slash = path.find_last_of(L"\\/");
    std::wstring dir = (slash == std::wstring::npos) ? L"" : path.substr(0, slash + 1);

    int wideLen = MultiByteToWideChar(CP_UTF8, 0, fileName.c_str(), -1, nullptr, 0);
    std::wstring wideName(wideLen > 0 ? static_cast<size_t>(wideLen - 1) : 0, L'\0');
    if (wideLen > 0) {
        MultiByteToWideChar(CP_UTF8, 0, fileName.c_str(), -1, &wideName[0], wideLen);
    }
    return dir + wideName;
}

// Loads a DLL next to the exe and resolves a fixed list of exports from it.
// Shared by WinRing0 and InpOut below so both give the same specific errors.
struct DynamicDll {
    HMODULE module = nullptr;
    std::string lastError;

    struct Export { std::string name; void** target; };

    DynamicDll() = default;
    DynamicDll(const DynamicDll&) = delete;
    DynamicDll& operator=(const DynamicDll&) = delete;
    ~DynamicDll() { Unload(); }

    bool Load(const std::string& fileName, std::initializer_list<Export> exports) {
        std::wstring dllPath = DllPathNextToExe(fileName);
        std::string narrowPath = ToUtf8(dllPath);

        module = LoadLibraryExW(dllPath.c_str(), nullptr, 0);
        if (!module) {
            DWORD err = GetLastError();
            char sysMsg[512] = {};
            DWORD msgLen = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err,
                                          MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), sysMsg, sizeof(sysMsg), nullptr);
            // System messages end in ".\r\n"; drop that so the text reads inline.
            while (msgLen > 0 && strchr(".\r\n ", sysMsg[msgLen - 1])) sysMsg[--msgLen] = '\0';

            char buf[1024];
            sprintf_s(buf, "LoadLibrary failed for \"%s\" (error %lu: %s)", narrowPath.c_str(), err, sysMsg);
            lastError = buf;

            if (err == ERROR_BAD_EXE_FORMAT) {
                lastError += " -- this usually means it's actually a 32-bit build renamed to look like "
                              "the x64 one; you need the real x64 build to match this x64 exe";
            } else if (err == ERROR_MOD_NOT_FOUND || err == ERROR_FILE_NOT_FOUND) {
                lastError += " -- the file isn't at that exact path (check the name/extension match exactly, "
                              "and it's not a copy in a different folder)";
            } else if (err == ERROR_ACCESS_DENIED) {
                lastError += " -- right-click the dll -> Properties -> check for \"Unblock\" near the bottom "
                              "(Mark-of-the-Web), or check antivirus quarantine";
            }
            return false;
        }

        for (const Export& e : exports) {
            *e.target = reinterpret_cast<void*>(GetProcAddress(module, e.name.c_str()));
            if (*e.target == nullptr) {
                char buf[512];
                sprintf_s(buf, "\"%s\" loaded but is missing the export \"%s\" -- this looks like a "
                                "different/incompatible build", narrowPath.c_str(), e.name.c_str());
                lastError = buf;
                Unload();
                return false;
            }
        }

        return true;
    }

    void Unload() {
        if (module) { FreeLibrary(module); module = nullptr; }
    }
};

// Driver wrappers

// WinRing0 (or an equivalent OLS-API driver): PCI config space access, used to
// read each controller's BAR0 and memory-enable state. It is the primary way
// the registers are located; if it is not present or cannot start (Defender
// often quarantines WinRing0x64.sys), the address Windows assigned is used as
// a fallback. Many redistributed builds have had their MMIO functions
// stripped out, so MMIO is delegated to InpOut instead (below).
struct WinRing0 : DynamicDll {
    InitializeOls_t InitializeOls = nullptr;
    DeinitializeOls_t DeinitializeOls = nullptr;
    GetDllStatus_t GetDllStatus = nullptr;
    ReadPciConfigDwordEx_t ReadPciConfigDwordEx = nullptr;
    bool initialized = false;

    ~WinRing0() {
        if (initialized) DeinitializeOls();
    }

    // Loads the DLL and starts the driver. On failure lastError says why.
    bool Start() {
        if (!DynamicDll::Load("WinRing0x64.dll", {
                {"InitializeOls", reinterpret_cast<void**>(&InitializeOls)},
                {"DeinitializeOls", reinterpret_cast<void**>(&DeinitializeOls)},
                {"GetDllStatus", reinterpret_cast<void**>(&GetDllStatus)},
                {"ReadPciConfigDwordEx", reinterpret_cast<void**>(&ReadPciConfigDwordEx)},
            })) {
            return false;
        }

        if (!InitializeOls()) {
            char buf[256];
            sprintf_s(buf, "InitializeOls failed (dll status = %lu); check the Microsoft Vulnerable Driver "
                            "Blocklist setting and antivirus quarantine", GetDllStatus());
            lastError = buf;
            Unload();
            return false;
        }

        initialized = true;
        return true;
    }

    bool ReadConfig(DWORD pciAddress, DWORD offset, DWORD& value) const {
        return initialized && ReadPciConfigDwordEx(pciAddress, offset, &value);
    }
};

// InpOutX64 (or an equivalent WinIo-descended driver): MMIO reads/writes of
// the xHCI capability/runtime/interrupter registers via MapPhysToLin/
// UnmapPhysicalMemory. The official InpOutX64 API is just Inp32/Out32 port
// I/O; this pair is instead carried over from WinIo, which several
// redistributed builds descend from. GetPhysLong/SetPhysLong wrappers exist
// on some builds too but crash on at least one, so aren't used here.
struct InpOut : DynamicDll {
    MapPhysToLin_t MapPhysToLin = nullptr;
    UnmapPhysicalMemory_t UnmapPhysicalMemory = nullptr;

    bool Load() {
        return DynamicDll::Load("inpoutx64.dll", {
            {"MapPhysToLin", reinterpret_cast<void**>(&MapPhysToLin)},
            {"UnmapPhysicalMemory", reinterpret_cast<void**>(&UnmapPhysicalMemory)},
        });
    }
};

// Maps a physical address range and allows DWORD read/write through it by
// absolute physical address. Unmaps itself when it goes out of scope.
struct PhysMemWindow {
    InpOut* driver = nullptr;
    HANDLE handle = nullptr;
    PBYTE linBase = nullptr;
    uint64_t physBase = 0;

    PhysMemWindow() = default;
    PhysMemWindow(const PhysMemWindow&) = delete;
    PhysMemWindow& operator=(const PhysMemWindow&) = delete;
    ~PhysMemWindow() { Unmap(); }

    bool Map(InpOut& io, uint64_t physAddr, DWORD size) {
        Unmap();
        driver = &io;
        physBase = physAddr;
        linBase = io.MapPhysToLin(reinterpret_cast<PBYTE>(physAddr), size, &handle);
        return linBase != nullptr;
    }

    DWORD ReadDword(uint64_t physAddr) const {
        return *reinterpret_cast<volatile DWORD*>(linBase + (physAddr - physBase));
    }

    void WriteDword(uint64_t physAddr, DWORD value) const {
        *reinterpret_cast<volatile DWORD*>(linBase + (physAddr - physBase)) = value;
    }

    void Unmap() {
        if (linBase && driver) {
            driver->UnmapPhysicalMemory(handle, linBase);
            linBase = nullptr;
        }
    }
};

// PCI / xHCI register layout

constexpr DWORD PCI_REG_VENDOR_DEVICE = 0x00;
constexpr DWORD PCI_REG_COMMAND       = 0x04;
constexpr DWORD PCI_REG_CLASS_CODE    = 0x08;
constexpr DWORD PCI_REG_BAR0          = 0x10;
constexpr DWORD PCI_REG_BAR1          = 0x14;

// PCI COMMAND register, bit 1: Memory Space Enable. If clear, the BAR reads
// back a plausible address but nothing answers there (open-bus, typically
// 0xFFFFFFFF) -- typical of a controller Windows has disabled or the
// platform has parked.
constexpr DWORD PCI_COMMAND_MEMORY_SPACE = 0x0002;

constexpr DWORD XHCI_CLASS_CODE = 0x0C0330;

constexpr DWORD XHCI_HCSPARAMS1_OFFSET = 0x04;
constexpr DWORD XHCI_RTSOFF_OFFSET     = 0x18;
constexpr DWORD XHCI_IR0_OFFSET        = 0x20;
constexpr DWORD XHCI_IR_SIZE           = 0x20;
constexpr DWORD XHCI_IMOD_OFFSET       = 0x04;
constexpr DWORD XHCI_MAX_INTERRUPTERS  = 1024;

// IMOD register: bits 15:0 are the interval (IMODI), bits 31:16 are a live
// countdown (IMODC), so only the low 16 bits are compared.
constexpr DWORD XHCI_IMODI_MASK = 0x0000FFFF;

// An xHCI controller as Windows PnP reports it.
struct xHCIController {
    std::wstring name;
    std::wstring deviceId;          // device instance path, e.g. PCI\VEN_8086&DEV_9D2F&...
    DWORD problemCode = 0;          // Device Manager problem code, 0 if none
    bool hasLocation = false;
    DWORD pciAddress = 0;           // bus << 8 | device << 3 | function
    uint64_t resourceAddress = 0;   // first memory range Windows assigned (BAR0)
};

struct xHCIRuntimeInfo {
    bool valid = false;
    uint64_t capabilityBase = 0;
    uint64_t runtimeBase = 0;
    DWORD runtimeOffset = 0;
    DWORD maxIntrs = 0;
    // Why ResolveRuntimeInfo() gave up; empty when valid is true.
    const char* failReason = "";
};

// Logging

static std::string TimestampNow() {
    time_t t = time(nullptr);
    tm localTm{};
    localtime_s(&localTm, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &localTm);
    return std::string(buf);
}

// Logs timestamped run details to %LOCALAPPDATA%\xHCI IMOD\Log.txt.
// Each run overwrites the file rather than appending, so it never grows.
struct Logger {
    FILE* file = nullptr;
    std::wstring path;
    std::string lastError;

    ~Logger() { Close(); }

    bool Open() {
        wchar_t localAppData[MAX_PATH];
        DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            lastError = "LOCALAPPDATA environment variable is not set";
            return false;
        }

        std::wstring dir = std::wstring(localAppData) + L"\\xHCI IMOD";
        CreateDirectoryW(dir.c_str(), nullptr); // fine if it already exists

        path = dir + L"\\Log.txt";
        _wfopen_s(&file, path.c_str(), L"w");
        if (!file) {
            lastError = "failed to open log file at the expected path";
            return false;
        }
        return true;
    }

    void Line(const char* fmt, ...) {
        if (!file) return;
        char buf[1024];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        fprintf(file, "[%s] %s\n", TimestampNow().c_str(), buf);
        fflush(file);
    }

    void Close() {
        if (file) { fclose(file); file = nullptr; }
    }
};

// Privilege check

static bool IsElevated() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

// xHCI controller discovery

static std::vector<BYTE> GetDeviceProperty(HDEVINFO devInfo, SP_DEVINFO_DATA& devData, DWORD property, DWORD& type) {
    DWORD size = 0;
    SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, property, &type, nullptr, 0, &size);
    if (size == 0) return {};

    // Two spare zeroed wchar_t so strings are always terminated.
    std::vector<BYTE> buffer(size + sizeof(wchar_t) * 2, 0);
    if (!SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, property, &type, buffer.data(), size, nullptr)) return {};
    return buffer;
}

static std::wstring GetDeviceString(HDEVINFO devInfo, SP_DEVINFO_DATA& devData, DWORD property) {
    DWORD type = 0;
    std::vector<BYTE> buffer = GetDeviceProperty(devInfo, devData, property, type);
    if (buffer.empty() || (type != REG_SZ && type != REG_MULTI_SZ)) return L"";
    return reinterpret_cast<const wchar_t*>(buffer.data());
}

// PnP IDs carry the PCI class code, e.g. "PCI\CC_0C0330" in the compatible IDs.
static bool IsXhciDevice(HDEVINFO devInfo, SP_DEVINFO_DATA& devData) {
    for (DWORD property : { SPDRP_HARDWAREID, SPDRP_COMPATIBLEIDS }) {
        DWORD type = 0;
        std::vector<BYTE> buffer = GetDeviceProperty(devInfo, devData, property, type);
        if (buffer.empty() || type != REG_MULTI_SZ) continue;

        for (auto id = reinterpret_cast<wchar_t*>(buffer.data()); *id; id += wcslen(id) + 1) {
            std::wstring upper(id);
            CharUpperBuffW(upper.data(), static_cast<DWORD>(upper.size()));
            if (upper.find(L"CC_0C0330") != std::wstring::npos) return true;
        }
    }
    return false;
}

// The first memory range in the allocated configuration is BAR0.
static uint64_t GetAllocatedMemoryAddress(DEVINST devInst) {
    LOG_CONF logConf = 0;
    if (CM_Get_First_Log_Conf(&logConf, devInst, ALLOC_LOG_CONF) != CR_SUCCESS) return 0;

    uint64_t address = 0;
    RES_DES descriptor = 0;
    RESOURCEID resourceId = 0;
    CONFIGRET result = CM_Get_Next_Res_Des(&descriptor, logConf, ResType_All, &resourceId, 0);

    while (result == CR_SUCCESS && address == 0) {
        ULONG size = 0;
        if ((resourceId == ResType_Mem || resourceId == ResType_MemLarge) &&
            CM_Get_Res_Des_Data_Size(&size, descriptor, 0) == CR_SUCCESS && size > 0) {
            std::vector<BYTE> data(size);
            if (CM_Get_Res_Des_Data(descriptor, data.data(), size, 0) == CR_SUCCESS) {
                if (resourceId == ResType_Mem && size >= sizeof(MEM_DES))
                    address = reinterpret_cast<const MEM_DES*>(data.data())->MD_Alloc_Base;
                else if (resourceId == ResType_MemLarge && size >= sizeof(MEM_LARGE_DES))
                    address = reinterpret_cast<const MEM_LARGE_DES*>(data.data())->MLD_Alloc_Base;
            }
        }

        RES_DES next = 0;
        if (address == 0) result = CM_Get_Next_Res_Des(&next, descriptor, ResType_All, &resourceId, 0);
        CM_Free_Res_Des_Handle(descriptor);
        descriptor = next;
    }

    CM_Free_Log_Conf_Handle(logConf);
    return address;
}

// Every present PCI device with class code 0C0330 (USB xHCI), as Windows sees it.
static std::vector<xHCIController> FindxHCIControllers() {
    std::vector<xHCIController> found;
    HDEVINFO devInfo = SetupDiGetClassDevsW(nullptr, L"PCI", nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return found;

    SP_DEVINFO_DATA devData = {};
    devData.cbSize = sizeof(devData);

    for (DWORD index = 0; SetupDiEnumDeviceInfo(devInfo, index, &devData); ++index) {
        if (!IsXhciDevice(devInfo, devData)) continue;

        wchar_t instanceId[MAX_DEVICE_ID_LEN] = {};
        if (!SetupDiGetDeviceInstanceIdW(devInfo, &devData, instanceId, MAX_DEVICE_ID_LEN, nullptr)) continue;

        xHCIController controller;
        controller.deviceId = instanceId;
        controller.name = GetDeviceString(devInfo, devData, SPDRP_FRIENDLYNAME);
        if (controller.name.empty()) controller.name = GetDeviceString(devInfo, devData, SPDRP_DEVICEDESC);
        if (controller.name.empty()) controller.name = L"USB xHCI Compliant Host Controller";

        ULONG status = 0, problem = 0;
        if (CM_Get_DevNode_Status(&status, &problem, devData.DevInst, 0) == CR_SUCCESS && (status & DN_HAS_PROBLEM)) {
            controller.problemCode = problem;
        }

        // For PCI devices SPDRP_ADDRESS is (device << 16) | function.
        DWORD bus = 0, address = 0, type = 0;
        if (SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_BUSNUMBER, &type,
                                              reinterpret_cast<PBYTE>(&bus), sizeof(bus), nullptr) &&
            SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_ADDRESS, &type,
                                              reinterpret_cast<PBYTE>(&address), sizeof(address), nullptr)) {
            DWORD device = address >> 16, function = address & 0xFFFF;
            if (bus < 256 && device < 32 && function < 8) {
                controller.hasLocation = true;
                controller.pciAddress = (bus << 8) | (device << 3) | function;
            }
        }

        controller.resourceAddress = GetAllocatedMemoryAddress(devData.DevInst);
        found.push_back(controller);
    }

    SetupDiDestroyDeviceInfoList(devInfo);
    return found;
}

// Reads the 4 hex digits after a key such as "VEN_" in a device instance path.
static bool ParseIdField(const std::wstring& deviceId, const wchar_t* key, DWORD& value) {
    size_t pos = deviceId.find(key);
    if (pos == std::wstring::npos) return false;
    pos += wcslen(key);
    if (pos + 4 > deviceId.size()) return false;

    value = 0;
    for (size_t i = pos; i < pos + 4; ++i) {
        wchar_t c = deviceId[i];
        DWORD digit;
        if (c >= L'0' && c <= L'9') digit = c - L'0';
        else if (c >= L'A' && c <= L'F') digit = c - L'A' + 10;
        else if (c >= L'a' && c <= L'f') digit = c - L'a' + 10;
        else return false;
        value = (value << 4) | digit;
    }
    return true;
}

// Guards against the bus/device/function pointing at a different device,
// e.g. on systems with more than one PCI segment.
static bool MatchesDeviceId(const std::wstring& deviceId, DWORD vendorDevice) {
    DWORD vendor = 0, device = 0;
    if (!ParseIdField(deviceId, L"VEN_", vendor) || !ParseIdField(deviceId, L"DEV_", device)) return true;
    return (vendorDevice & 0xFFFF) == vendor && (vendorDevice >> 16) == device;
}

// Reads BAR0 from PCI config space via WinRing0. Returns 0 if it can't be
// read with confidence, so the caller falls back to the PnP resource.
static uint64_t ReadBar0(const WinRing0& ols, const xHCIController& controller, bool& memorySpaceDisabled) {
    memorySpaceDisabled = false;
    if (!ols.initialized || !controller.hasLocation) return 0;

    const DWORD pci = controller.pciAddress;
    DWORD vendorDevice = 0xFFFFFFFF, classReg = 0, command = 0, bar0 = 0;

    if (!ols.ReadConfig(pci, PCI_REG_VENDOR_DEVICE, vendorDevice) || (vendorDevice & 0xFFFF) == 0xFFFF) return 0;
    if (!MatchesDeviceId(controller.deviceId, vendorDevice)) return 0;
    if (!ols.ReadConfig(pci, PCI_REG_CLASS_CODE, classReg) || (classReg >> 8) != XHCI_CLASS_CODE) return 0;

    if (ols.ReadConfig(pci, PCI_REG_COMMAND, command) && (command & PCI_COMMAND_MEMORY_SPACE) == 0) {
        memorySpaceDisabled = true;
        return 0;
    }

    // Bit 0 set means an I/O BAR; bits 2:1 == 10b means a 64-bit BAR spanning BAR0 and BAR1.
    if (!ols.ReadConfig(pci, PCI_REG_BAR0, bar0) || (bar0 & 0x1)) return 0;
    uint64_t base = bar0 & 0xFFFFFFF0u;

    if (((bar0 >> 1) & 0x3) == 0x2) {
        DWORD bar1 = 0;
        if (!ols.ReadConfig(pci, PCI_REG_BAR1, bar1)) return 0;
        base |= static_cast<uint64_t>(bar1) << 32;
    }

    return base;
}

// HCSPARAMS1 (+0x04) and RTSOFF (+0x18) both fit in one page.
constexpr DWORD XHCI_CAP_WINDOW_SIZE = 0x1000;

static xHCIRuntimeInfo ResolveRuntimeInfo(const WinRing0& ols, InpOut& io, const xHCIController& controller) {
    xHCIRuntimeInfo info;

    if (controller.problemCode == CM_PROB_DISABLED) {
        info.failReason = "disabled in Device Manager";
        return info;
    }

    bool memorySpaceDisabled = false;
    info.capabilityBase = ReadBar0(ols, controller, memorySpaceDisabled);

    if (memorySpaceDisabled) {
        info.failReason = "memory space disabled (controller likely disabled/parked)";
        return info;
    }
    if (info.capabilityBase == 0) {
        info.capabilityBase = controller.resourceAddress;
    }
    if (info.capabilityBase == 0) {
        info.failReason = "no memory address found for the controller";
        return info;
    }

    PhysMemWindow capWindow;
    if (!capWindow.Map(io, info.capabilityBase, XHCI_CAP_WINDOW_SIZE)) {
        info.failReason = "failed to map capability register window";
        return info;
    }

    DWORD capHeader = capWindow.ReadDword(info.capabilityBase);
    DWORD hcsparams1 = capWindow.ReadDword(info.capabilityBase + XHCI_HCSPARAMS1_OFFSET);
    DWORD rtsoff = capWindow.ReadDword(info.capabilityBase + XHCI_RTSOFF_OFFSET) & 0xFFFFFFE0u;
    capWindow.Unmap();

    info.maxIntrs = (hcsparams1 >> 8) & 0x7FF;
    DWORD capLength = capHeader & 0xFF;

    if (capHeader == 0xFFFFFFFFu || hcsparams1 == 0xFFFFFFFFu) {
        info.failReason = "capability registers read as open-bus (0xFFFFFFFF)";
        return info;
    }
    if (capLength < 0x20) {
        info.failReason = "CAPLENGTH is too small for an xHCI controller";
        return info;
    }
    if (info.maxIntrs == 0 || info.maxIntrs > XHCI_MAX_INTERRUPTERS) {
        info.failReason = "HCSPARAMS1 reported an implausible interrupter count";
        return info;
    }
    if (rtsoff < capLength || rtsoff > 0x00800000u) {
        info.failReason = "RTSOFF reported an implausible runtime register offset";
        return info;
    }

    info.runtimeOffset = rtsoff;
    info.runtimeBase = info.capabilityBase + rtsoff;
    info.valid = true;

    return info;
}

static uint64_t ImodAddress(const xHCIRuntimeInfo& info, DWORD interrupterIndex) {
    return info.runtimeBase + XHCI_IR0_OFFSET + (static_cast<uint64_t>(XHCI_IR_SIZE) * interrupterIndex) + XHCI_IMOD_OFFSET;
}

// Size of a window mapped from the (page-aligned) capability base that covers
// every interrupter, rounded up to a page. RTSOFF itself is only 32-byte
// aligned, so the runtime registers are not mapped on their own.
static DWORD InterrupterWindowSize(const xHCIRuntimeInfo& info) {
    DWORD needed = info.runtimeOffset + XHCI_IR0_OFFSET + (info.maxIntrs * XHCI_IR_SIZE);
    return (needed + 0xFFF) & ~0xFFFu;
}

// Configuration

// 0 disables interrupt moderation entirely (lowest latency, highest
// interrupt rate). Set from the startup menu, or forced to 0 by -silent.
static DWORD g_desiredImodInterval = 0x0;

// ~62.5Hz -- offered by the menu as "Test IMOD" to check the write lands.
constexpr DWORD TEST_IMOD_INTERVAL = 0xFA00;

// Output helpers

static bool g_silent = false;

static void Out(const char* fmt, ...) {
    if (g_silent) return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

static void ErrOut(const char* fmt, ...) {
    if (g_silent) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

static void ClearConsole() {
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (console == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(console, &info)) return;

    DWORD cellCount = static_cast<DWORD>(info.dwSize.X) * info.dwSize.Y;
    COORD origin = {0, 0};
    DWORD written;
    FillConsoleOutputCharacterA(console, ' ', cellCount, origin, &written);
    FillConsoleOutputAttribute(console, info.wAttributes, cellCount, origin, &written);
    SetConsoleCursorPosition(console, origin);
}

// Appends one argument to a Windows command line, quoting/escaping it only
// if needed, using the standard algorithm so embedded spaces and quotes
// survive being re-split by the child process's own argv parsing.
static void AppendQuotedArg(std::wstring& cmdLine, const std::wstring& arg) {
    if (!cmdLine.empty()) cmdLine += L' ';

    if (!arg.empty() && arg.find_first_of(L" \t\"") == std::wstring::npos) {
        cmdLine += arg;
        return;
    }

    cmdLine += L'"';
    for (auto it = arg.begin();; ++it) {
        size_t backslashes = 0;
        while (it != arg.end() && *it == L'\\') {
            ++backslashes;
            ++it;
        }
        if (it == arg.end()) {
            cmdLine.append(backslashes * 2, L'\\');
            break;
        } else if (*it == L'"') {
            cmdLine.append(backslashes * 2 + 1, L'\\');
            cmdLine += L'"';
        } else {
            cmdLine.append(backslashes, L'\\');
            cmdLine += *it;
        }
    }
    cmdLine += L'"';
}

// Startup entries

// Where the exe and drivers are copied before registering a startup entry,
// so it keeps working even if the original folder (e.g. Downloads) gets
// cleaned up later.
constexpr wchar_t INSTALL_DIR[] = L"C:\\Windows\\IMOD";

// Name of both the Task Scheduler entry and the Registry Run value.
constexpr wchar_t STARTUP_NAME[] = L"xHCI IMOD";

constexpr wchar_t RUN_KEY[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t UAC_POLICY_KEY[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

// The same task the basic schtasks command creates (SYSTEM, at logon,
// highest privileges), plus what that command cannot set:
//  - battery conditions off, otherwise the task never runs on a
//    laptop that is unplugged at logon;
//  - a second trigger on resume from sleep or hibernate (System log,
//    Power-Troubleshooter event 1), since IMOD can be reset when the
//    controller powers back up. The delay lets the USB driver finish
//    restoring the controller first.
constexpr wchar_t TASK_XML[] = LR"(<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger />
    <EventTrigger>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT5S</Delay>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  </Settings>
  <Actions>
    <Exec>
      <Command>{EXE}</Command>
      <Arguments>-silent</Arguments>
    </Exec>
  </Actions>
</Task>
)";

static std::wstring XmlEscape(const std::wstring& value) {
    std::wstring result;
    for (wchar_t c : value) {
        switch (c) {
            case L'&':  result += L"&amp;"; break;
            case L'<':  result += L"&lt;"; break;
            case L'>':  result += L"&gt;"; break;
            case L'"':  result += L"&quot;"; break;
            case L'\'': result += L"&apos;"; break;
            default:    result += c; break;
        }
    }
    return result;
}

// Runs schtasks.exe from System32 by full path, so a schtasks.exe placed
// next to this exe can never be started with admin rights instead. Returns
// its exit code, or -1 if it couldn't be started.
static int RunSchtasks(std::initializer_list<std::wstring> args, Logger& log) {
    wchar_t systemDir[MAX_PATH];
    UINT len = GetSystemDirectoryW(systemDir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return -1;

    std::wstring schtasks = std::wstring(systemDir) + L"\\schtasks.exe";
    std::wstring cmdLine;
    AppendQuotedArg(cmdLine, schtasks);
    for (const std::wstring& arg : args) {
        AppendQuotedArg(cmdLine, arg);
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    DWORD exitCode = 1;

    if (!CreateProcessW(schtasks.c_str(), cmdLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        log.Line("schtasks: CreateProcess failed (error %lu)", GetLastError());
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exitCode);
}

// Copies one file from srcDir to INSTALL_DIR, unless it's already there.
static bool CopyToInstallDir(const std::wstring& srcDir, const wchar_t* fileName, Logger& log) {
    std::wstring src = srcDir + L"\\" + fileName;
    std::wstring dst = std::wstring(INSTALL_DIR) + L"\\" + fileName;
    if (_wcsicmp(src.c_str(), dst.c_str()) == 0) return true;

    bool ok = CopyFileW(src.c_str(), dst.c_str(), FALSE) != FALSE;
    log.Line("copy %s to install dir: %s", ToUtf8(fileName).c_str(), ok ? "ok" : "failed");
    return ok;
}

// Copies this exe and its drivers to INSTALL_DIR and returns the installed
// exe's path, or an empty string on failure. WinRing0 is copied when present;
// without it the installed copy uses the fallback address.
static std::wstring InstallToInstallDir(Logger& log) {
    wchar_t exePathBuf[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, exePathBuf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        Out("error: could not determine this exe's path\n");
        return L"";
    }

    std::wstring exePath(exePathBuf);
    size_t slash = exePath.find_last_of(L"\\/");
    std::wstring srcDir = (slash == std::wstring::npos) ? L"." : exePath.substr(0, slash);
    std::wstring exeName = (slash == std::wstring::npos) ? exePath : exePath.substr(slash + 1);

    CreateDirectoryW(INSTALL_DIR, nullptr); // fine if it already exists

    for (const wchar_t* required : { exeName.c_str(), L"inpoutx64.dll", L"inpoutx64.sys" }) {
        if (!CopyToInstallDir(srcDir, required, log)) {
            Out("error: could not copy %s to %s\n", ToUtf8(required).c_str(), ToUtf8(INSTALL_DIR).c_str());
            log.Line("install: failed to copy %s, aborting", ToUtf8(required).c_str());
            return L"";
        }
    }

    for (const wchar_t* optional : { L"WinRing0x64.dll", L"WinRing0x64.sys" }) {
        if (GetFileAttributesW((srcDir + L"\\" + optional).c_str()) != INVALID_FILE_ATTRIBUTES) {
            CopyToInstallDir(srcDir, optional, log);
        }
    }

    return std::wstring(INSTALL_DIR) + L"\\" + exeName;
}

// Registers a Task Scheduler entry that runs the installed copy with -silent
// at logon and after resume from sleep. schtasks can only take the battery
// and resume settings from an XML definition, which is written to %TEMP% and
// deleted once the task is registered.
static int AddToTaskScheduler(Logger& log) {
    std::wstring installedExe = InstallToInstallDir(log);
    if (installedExe.empty()) return 1;

    wchar_t tempDir[MAX_PATH + 1];
    DWORD tempLen = GetTempPathW(MAX_PATH + 1, tempDir);
    if (tempLen == 0 || tempLen > MAX_PATH) {
        Out("error: could not find the temp folder\n");
        return 1;
    }

    std::wstring xml = TASK_XML;
    xml.replace(xml.find(L"{EXE}"), 5, XmlEscape(installedExe));
    std::wstring xmlPath = std::wstring(tempDir) + L"xHCI IMOD Task.xml";

    {
        std::ofstream file(xmlPath, std::ios::binary | std::ios::trunc);
        const unsigned char bom[] = {0xFF, 0xFE}; // UTF-16 LE, matching the XML declaration
        file.write(reinterpret_cast<const char*>(bom), sizeof(bom));
        file.write(reinterpret_cast<const char*>(xml.data()), static_cast<std::streamsize>(xml.size() * sizeof(wchar_t)));
        if (!file.good()) {
            Out("error: could not write the task definition to %s\n", ToUtf8(xmlPath).c_str());
            return 1;
        }
    }

    int exitCode = RunSchtasks({L"/create", L"/tn", STARTUP_NAME, L"/xml", xmlPath, L"/f"}, log);
    DeleteFileW(xmlPath.c_str());

    bool ok = (exitCode == 0);
    if (ok) {
        Out("Installed to %s and created Task Scheduler entry \"%s\": runs at logon and after sleep with -silent.\n",
            ToUtf8(INSTALL_DIR).c_str(), ToUtf8(STARTUP_NAME).c_str());
    } else {
        Out("Failed to create the Task Scheduler entry (schtasks exit code %d).\n", exitCode);
    }
    log.Line("add to Task Scheduler: schtasks exit code %d", exitCode);

    return ok ? 0 : 1;
}

static bool IsUacEnabled() {
    DWORD value = 1;
    DWORD size = sizeof(value);
    // A missing value means the Windows default, which is enabled.
    if (RegGetValueW(HKEY_LOCAL_MACHINE, UAC_POLICY_KEY, L"EnableLUA", RRF_RT_REG_DWORD, nullptr, &value, &size) != ERROR_SUCCESS) {
        return true;
    }
    return value != 0;
}

// Adds a Registry Run value that runs the installed copy with -silent at
// logon. Windows does not start Run entries that require admin rights while
// UAC is on, so UAC is disabled (takes effect after a restart); Task
// Scheduler is the option that works with UAC on.
static int AddToRegistryRun(Logger& log) {
    std::wstring installedExe = InstallToInstallDir(log);
    if (installedExe.empty()) return 1;

    std::wstring command = L"\"" + installedExe + L"\" -silent";
    LSTATUS result = RegSetKeyValueW(HKEY_LOCAL_MACHINE, RUN_KEY, STARTUP_NAME, REG_SZ, command.c_str(),
                                     static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    log.Line("add to Registry Run: result %ld", result);

    if (result != ERROR_SUCCESS) {
        Out("Failed to create the Registry Run entry (error %ld).\n", result);
        return 1;
    }

    Out("Installed to %s and created Registry Run entry \"%s\": runs at logon with -silent.\n",
        ToUtf8(INSTALL_DIR).c_str(), ToUtf8(STARTUP_NAME).c_str());

    if (IsUacEnabled()) {
        const DWORD disabled = 0;
        LSTATUS uacResult = RegSetKeyValueW(HKEY_LOCAL_MACHINE, UAC_POLICY_KEY, L"EnableLUA", REG_DWORD,
                                            &disabled, sizeof(disabled));
        log.Line("disable UAC: result %ld", uacResult);

        if (uacResult == ERROR_SUCCESS) {
            Out("UAC disabled so the entry can start as admin at logon. Restart your PC for this to take effect.\n");
        } else {
            Out("Failed to disable UAC (error %ld), so Windows will not start the entry as admin at logon. "
                "Use the Task Scheduler option instead.\n", uacResult);
            return 1;
        }
    }

    return 0;
}

// Deletes both the Task Scheduler entry and the Registry Run value, whichever exist.
static int RemoveFromStartup(Logger& log) {
    int taskResult = RunSchtasks({L"/delete", L"/tn", STARTUP_NAME, L"/f"}, log);
    LSTATUS runResult = RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, RUN_KEY, STARTUP_NAME);
    log.Line("remove from startup: schtasks exit code %d, Run value result %ld", taskResult, runResult);

    Out(taskResult == 0 ? "Removed the Task Scheduler entry \"%s\".\n" : "No Task Scheduler entry \"%s\" was found.\n",
        ToUtf8(STARTUP_NAME).c_str());

    if (runResult == ERROR_SUCCESS) {
        Out("Removed the Registry Run entry \"%s\".\n", ToUtf8(STARTUP_NAME).c_str());
    } else if (runResult == ERROR_FILE_NOT_FOUND) {
        Out("No Registry Run entry \"%s\" was found.\n", ToUtf8(STARTUP_NAME).c_str());
    } else {
        Out("Failed to remove the Registry Run entry (error %ld).\n", runResult);
        return 1;
    }

    return 0;
}

// Patch routine

// Registers found on a controller, and how many were verified updated.
struct PatchResult {
    DWORD total = 0;
    int updated = 0;
    bool failed = false;    // the controller couldn't be patched, or a write didn't verify
};

// Patches every register on one controller.
static PatchResult DisableImod(const WinRing0& ols, InpOut& io, Logger& log, const xHCIController& controller, int index) {
    int displayNumber = index + 1;
    std::string name = ToUtf8(controller.name);
    xHCIRuntimeInfo info = ResolveRuntimeInfo(ols, io, controller);

    Out("Controller %d: %s\n", displayNumber, name.c_str());
    log.Line("controller #%d: %s [%s] max_interrupters=%lu", index, name.c_str(),
             ToUtf8(controller.deviceId).c_str(), info.maxIntrs);

    PatchResult result;

    // A controller Windows has disabled isn't a failure, just nothing to do.
    if (!info.valid) {
        Out("  Could not be accessed, skipped (%s).\n\n", info.failReason);
        log.Line("controller #%d: %s, skipping", index, info.failReason);
        result.failed = controller.problemCode != CM_PROB_DISABLED;
        return result;
    }

    PhysMemWindow window;
    if (!window.Map(io, info.capabilityBase, InterrupterWindowSize(info))) {
        Out("  Could not be accessed, skipped (failed to map runtime register window).\n\n");
        log.Line("controller #%d: failed to map runtime register window, skipping", index);
        result.failed = true;
        return result;
    }

    result.total = info.maxIntrs;
    for (DWORD i = 0; i < info.maxIntrs; ++i) {
        uint64_t addr = ImodAddress(info, i);
        DWORD before = window.ReadDword(addr);
        window.WriteDword(addr, g_desiredImodInterval);
        DWORD after = window.ReadDword(addr);
        bool ok = (after & XHCI_IMODI_MASK) == g_desiredImodInterval;
        result.updated += ok ? 1 : 0;
        result.failed |= !ok;

        Out("  Register %lu: %08lX -> %08lX  [%s]\n", i + 1, before, after, ok ? "OK" : "FAILED");
        log.Line("controller #%d interrupter %2lu @ 0x%016llX: IMOD 0x%08lX -> 0x%08lX [%s]",
                  index, i, static_cast<unsigned long long>(addr), before, after, ok ? "OK" : "FAILED");
    }
    Out("\n");

    log.Line("controller #%d: patched %lu interrupters, %d verified", index, info.maxIntrs, result.updated);
    return result;
}

// Entry point

static bool CheckElevated(Logger& log) {
    if (IsElevated()) return true;
    ErrOut("error: administrator privileges required\n");
    log.Line("error: administrator privileges required");
    return false;
}

// Patches every controller with g_desiredImodInterval. Returns the exit code.
static int PatchAllControllers(Logger& log) {
    InpOut io;
    if (!io.Load()) {
        ErrOut("error (InpOutX64): %s\n", io.lastError.c_str());
        log.Line("error (InpOutX64): %s", io.lastError.c_str());
        return 1;
    }

    WinRing0 ols;
    if (!ols.Start()) {
        log.Line("WinRing0 unavailable, using the addresses Windows assigned: %s", ols.lastError.c_str());
    }

    std::vector<xHCIController> controllers = FindxHCIControllers();
    if (controllers.empty()) {
        Out("No USB controllers were found.\n");
        log.Line("no xHCI controllers found");
    }

    int updatedTotal = 0;
    DWORD registerTotal = 0;
    bool anyFailed = false;
    for (size_t i = 0; i < controllers.size(); ++i) {
        PatchResult result = DisableImod(ols, io, log, controllers[i], static_cast<int>(i));
        updatedTotal += result.updated;
        registerTotal += result.total;
        anyFailed |= result.failed;
    }

    if (!controllers.empty()) {
        Out("Done: %d of %lu register%s updated successfully across %zu controller%s.\n",
            updatedTotal, registerTotal, registerTotal == 1 ? "" : "s",
            controllers.size(), controllers.size() == 1 ? "" : "s");
    }
    log.Line("run complete: %d of %lu registers updated successfully across %zu controllers",
              updatedTotal, registerTotal, controllers.size());

    return (!anyFailed && (updatedTotal > 0 || controllers.empty())) ? 0 : 1;
}

// Startup submenu. Returns true if an option ran (its exit code goes in
// result), or false for Back.
static bool RunStartupMenu(Logger& log, int& result) {
    for (;;) {
        ClearConsole();
        Out("xHCI IMOD Disabler - Startup options\n");
        Out("  1) Add to Task Scheduler (installs to C:\\Windows\\IMOD, runs at logon and after sleep)\n");
        Out("  2) Add to Registry Run (installs to C:\\Windows\\IMOD, runs at logon, disables UAC)\n");
        Out("  3) Remove from startup\n");
        Out("  4) Back\n");
        Out("Choice: ");
        int choice = _getch();

        if (choice == '4') return false;
        if (choice < '1' || choice > '3') continue;

        ClearConsole();
        if (!CheckElevated(log)) {
            result = 1;
        } else if (choice == '1') {
            result = AddToTaskScheduler(log);
        } else if (choice == '2') {
            result = AddToRegistryRun(log);
        } else {
            result = RemoveFromStartup(log);
        }
        return true;
    }
}

// Main menu. Nothing is loaded or touched until an option is picked, and
// every option returns here; Exit closes the program. Returns the exit
// code of the last option that ran.
static int RunMenu(Logger& log) {
    int result = 0;
    bool anythingRan = false;

    for (;;) {
        ClearConsole();
        Out("xHCI IMOD Disabler\n");
        Out("  1) Disable IMOD\n");
        Out("  2) Test IMOD (62.5Hz)\n");
        Out("  3) Startup options\n");
        Out("  4) Exit\n");
        Out("Choice: ");
        int choice = _getch();

        if (choice == '4') {
            ClearConsole();
            if (!anythingRan) {
                Out("Exiting, nothing was patched.\n");
                log.Line("user chose Exit from the menu, nothing patched");
            }
            return result;
        }

        bool ran = false;
        if (choice == '1' || choice == '2') {
            ClearConsole();
            g_desiredImodInterval = (choice == '2') ? TEST_IMOD_INTERVAL : 0x0;
            result = CheckElevated(log) ? PatchAllControllers(log) : 1;
            ran = true;
        } else if (choice == '3') {
            ran = RunStartupMenu(log, result);
        }

        if (ran) {
            anythingRan = true;
            Out("\nPress any key...");
            (void)_getch();
        }
    }
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "-silent") == 0) {
            g_silent = true;
        }
    }

    // Detach the console before anything else, so no window lingers on an
    // unattended run.
    if (g_silent) {
        FreeConsole();
    }

    // Controller names can be non-ASCII; restore the caller's code page on exit.
    UINT originalCodePage = GetConsoleOutputCP();
    if (!g_silent) SetConsoleOutputCP(CP_UTF8);

    Logger log;
    if (!log.Open()) {
        ErrOut("warning: could not open log file (%s); continuing without logging\n", log.lastError.c_str());
    }
    log.Line("xHCIImodDisable run started");

    int result = g_silent ? (CheckElevated(log) ? PatchAllControllers(log) : 1) : RunMenu(log);
    log.Close();

    if (!g_silent && originalCodePage != 0) SetConsoleOutputCP(originalCodePage);

    return result;
}
