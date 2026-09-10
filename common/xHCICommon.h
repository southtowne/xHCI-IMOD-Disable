// xHCICommon.h
//
// Shared xHCI/PCI/driver plumbing used by xHCIImodDisable to find every xHCI
// controller and patch its IMOD register(s) to 0.

#pragma once

#include <windows.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

// Driver export signatures

using InitializeOls_t        = BOOL(WINAPI*)();
using DeinitializeOls_t      = VOID(WINAPI*)();
using GetDllStatus_t         = DWORD(WINAPI*)();
using ReadPciConfigDwordEx_t = BOOL(WINAPI*)(DWORD pciAddress, DWORD regAddress, PDWORD value);
using MapPhysToLin_t         = PBYTE(WINAPI*)(PBYTE physAddress, DWORD size, PHANDLE physMemHandle);
using UnmapPhysicalMemory_t  = BOOL(WINAPI*)(HANDLE physMemHandle, PBYTE linAddress);

// Dynamic driver loading

// Resolves <exe directory>\<fileName>. LoadLibrary would find a bare filename
// in the exe's directory anyway, but building the full path removes any
// ambiguity from how the process was launched (working directory, shortcuts,
// Task Scheduler, etc.) and makes a failed load report the exact path tried.
inline std::wstring DllPathNextToExe(const std::string& fileName) {
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
// Shared by WinRing0 and InpOut below so both surface the same specific,
// diagnosable error messages on failure.
struct DynamicDll {
    HMODULE module = nullptr;
    std::string lastError;

    struct Export { std::string name; void** target; };

    bool Load(const std::string& fileName, std::initializer_list<Export> exports) {
        std::wstring dllPath = DllPathNextToExe(fileName);
        char narrowPath[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, dllPath.c_str(), -1, narrowPath, sizeof(narrowPath), nullptr, nullptr);

        module = LoadLibraryExW(dllPath.c_str(), nullptr, 0);
        if (!module) {
            DWORD err = GetLastError();
            char sysMsg[512] = {};
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err,
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), sysMsg, sizeof(sysMsg), nullptr);

            char buf[1024];
            sprintf_s(buf, "LoadLibrary failed for \"%s\" (error %lu: %s)", narrowPath, err, sysMsg);
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
                                "different/incompatible build", narrowPath, e.name.c_str());
                lastError = buf;
                FreeLibrary(module);
                module = nullptr;
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

// WinRing0 (or an equivalent OLS-API driver): PCI config space access only,
// used to locate each xHCI controller and read its BAR. Many redistributed
// WinRing0 builds have had their MMIO functions stripped out, so MMIO access
// is delegated to InpOut instead (below) rather than assumed to be present here.
struct WinRing0 : DynamicDll {
    InitializeOls_t InitializeOls = nullptr;
    DeinitializeOls_t DeinitializeOls = nullptr;
    GetDllStatus_t GetDllStatus = nullptr;
    ReadPciConfigDwordEx_t ReadPciConfigDwordEx = nullptr;

    bool Load() {
        return DynamicDll::Load("WinRing0x64.dll", {
            {"InitializeOls", reinterpret_cast<void**>(&InitializeOls)},
            {"DeinitializeOls", reinterpret_cast<void**>(&DeinitializeOls)},
            {"GetDllStatus", reinterpret_cast<void**>(&GetDllStatus)},
            {"ReadPciConfigDwordEx", reinterpret_cast<void**>(&ReadPciConfigDwordEx)},
        });
    }
};

// InpOutX64 (or an equivalent WinIo-descended driver): physical memory (MMIO)
// access, used for the actual xHCI capability/runtime/interrupter register
// reads and writes via MapPhysToLin/UnmapPhysicalMemory. The official
// InpOutX64 API is just Inp32/Out32 port I/O; this instead relies on the
// MapPhysToLin/UnmapPhysicalMemory pair that several widely-redistributed
// builds descended from Yariv Kaplan's WinIo also carry. (GetPhysLong/
// SetPhysLong convenience wrappers exist on some builds too but are
// deliberately not used here -- they crash on at least one common build.)
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

// Maps a physical address range once and allows DWORD read/write through it,
// keyed by absolute physical address so callers don't do their own pointer
// arithmetic.
struct PhysMemWindow {
    InpOut* driver = nullptr;
    HANDLE handle = nullptr;
    PBYTE linBase = nullptr;
    uint64_t physBase = 0;

    bool Map(InpOut& io, uint64_t physAddr, DWORD size) {
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
constexpr DWORD PCI_REG_CLASS_CODE    = 0x08;
constexpr DWORD PCI_REG_HEADER_TYPE   = 0x0C;
constexpr DWORD PCI_REG_BAR0          = 0x10;
constexpr DWORD PCI_REG_BAR1          = 0x14;

constexpr DWORD XHCI_CLASS_CODE = 0x0C0330;

constexpr DWORD XHCI_HCSPARAMS1_OFFSET = 0x04;
constexpr DWORD XHCI_RTSOFF_OFFSET     = 0x18;
constexpr DWORD XHCI_IR0_OFFSET        = 0x20;
constexpr DWORD XHCI_IR_SIZE           = 0x20;
constexpr DWORD XHCI_IMOD_OFFSET       = 0x04;

struct xHCIController {
    DWORD pciAddress = 0;
};

struct xHCIRuntimeInfo {
    bool valid = false;
    uint64_t capabilityBase = 0;
    uint64_t runtimeBase = 0;
    DWORD maxIntrs = 0;
};

// Logging

inline std::string TimestampNow() {
    time_t t = time(nullptr);
    tm localTm{};
    localtime_s(&localTm, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &localTm);
    return std::string(buf);
}

// Writes timestamped run details to %LOCALAPPDATA%\xHCI IMOD\Log.txt, so an
// unattended run's result can still be checked afterward even with -silent.
// Each run overwrites the file rather than appending, so it never grows.
struct Logger {
    FILE* file = nullptr;
    std::wstring path;
    std::string lastError;

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

inline bool IsElevated() {
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

inline std::vector<xHCIController> FindxHCIControllers(WinRing0& ols) {
    std::vector<xHCIController> found;

    for (int bus = 0; bus < 256; ++bus) {
        for (int device = 0; device < 32; ++device) {
            int numFunctions = 1;

            for (int function = 0; function < numFunctions; ++function) {
                DWORD pciAddress = (bus << 8) | (device << 3) | function;

                DWORD vendorDevice = 0;
                if (!ols.ReadPciConfigDwordEx(pciAddress, PCI_REG_VENDOR_DEVICE, &vendorDevice)) continue;
                if ((vendorDevice & 0xFFFF) == 0xFFFF) continue;

                if (function == 0) {
                    DWORD headerTypeReg = 0;
                    ols.ReadPciConfigDwordEx(pciAddress, PCI_REG_HEADER_TYPE, &headerTypeReg);
                    BYTE headerType = static_cast<BYTE>((headerTypeReg >> 16) & 0xFF);
                    if (headerType & 0x80) numFunctions = 8;
                }

                DWORD classReg = 0;
                ols.ReadPciConfigDwordEx(pciAddress, PCI_REG_CLASS_CODE, &classReg);
                DWORD classCode = classReg >> 8;

                if (classCode == XHCI_CLASS_CODE) {
                    found.push_back({pciAddress});
                }
            }
        }
    }

    return found;
}

inline uint64_t GetCapabilityBase(WinRing0& ols, DWORD pciAddress) {
    DWORD bar0 = 0;
    if (!ols.ReadPciConfigDwordEx(pciAddress, PCI_REG_BAR0, &bar0)) return 0;
    if (bar0 & 0x1) return 0;

    bool is64Bit = ((bar0 >> 1) & 0x3) == 0x2;
    uint64_t capabilityBase = bar0 & 0xFFFFFFF0u;

    if (is64Bit) {
        DWORD bar1 = 0;
        ols.ReadPciConfigDwordEx(pciAddress, PCI_REG_BAR1, &bar1);
        capabilityBase |= (static_cast<uint64_t>(bar1) << 32);
    }

    return capabilityBase;
}

// HCSPARAMS1 (+0x04) and RTSOFF (+0x18) both live in the first page of the
// capability register space, so one small mapped window covers both.
constexpr DWORD XHCI_CAP_WINDOW_SIZE = 0x1000;

inline xHCIRuntimeInfo ResolveRuntimeInfo(WinRing0& ols, InpOut& io, DWORD pciAddress) {
    xHCIRuntimeInfo info;

    info.capabilityBase = GetCapabilityBase(ols, pciAddress);
    if (info.capabilityBase == 0) return info;

    PhysMemWindow capWindow;
    if (!capWindow.Map(io, info.capabilityBase, XHCI_CAP_WINDOW_SIZE)) {
        return info;
    }

    DWORD hcsparams1 = capWindow.ReadDword(info.capabilityBase + XHCI_HCSPARAMS1_OFFSET);
    info.maxIntrs = (hcsparams1 >> 8) & 0x7FF;

    DWORD rtsoffRaw = capWindow.ReadDword(info.capabilityBase + XHCI_RTSOFF_OFFSET);
    DWORD rtsoff = rtsoffRaw & 0xFFFFFFE0u;

    capWindow.Unmap();

    info.runtimeBase = info.capabilityBase + rtsoff;
    info.valid = (info.maxIntrs > 0 && info.maxIntrs <= 1024);

    return info;
}

inline uint64_t ImodAddress(const xHCIRuntimeInfo& info, DWORD interrupterIndex) {
    return info.runtimeBase + XHCI_IR0_OFFSET + (static_cast<uint64_t>(XHCI_IR_SIZE) * interrupterIndex) + XHCI_IMOD_OFFSET;
}

// Size of the mapped window needed to cover every interrupter register set
// for a controller with the given interrupter count, rounded up to a page.
inline DWORD InterrupterWindowSize(DWORD maxIntrs) {
    DWORD needed = XHCI_IR0_OFFSET + (maxIntrs * XHCI_IR_SIZE);
    return (needed + 0xFFF) & ~0xFFFu;
}
