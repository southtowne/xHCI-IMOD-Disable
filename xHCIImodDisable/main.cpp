// Disables xHCI (USB host controller) Interrupt Moderation (IMOD) for every
// interrupter on every xHCI controller found in the system, by writing 0 to
// each controller's IMOD register(s) directly in MMIO space.
//
// Run once per boot; the interrupter layout is read fresh from PCI config
// space and the xHCI capability registers every run.
//
// Interactively it shows a menu (disable / test at 62.5Hz / add itself to
// Task Scheduler at logon / exit) before loading any driver or touching a
// register. The Task Scheduler option copies this exe and its drivers to
// C:\Windows\IMOD first and points the logon task at that copy. Pass
// -silent for unattended use (Task Scheduler): no console, no menu, IMOD is
// disabled directly. Every run is logged to %LOCALAPPDATA%\xHCI IMOD\Log.txt.
//
// The exe is manifested to require administrator privileges, so launching
// it (interactively or via the logon task) triggers UAC on its own.
//
// Two drivers are used:
//   - WinRing0 (WinRing0x64.dll/.sys): PCI config space access, to find each
//     xHCI controller and its BAR. Many redistributed builds have had MMIO
//     access stripped out, so it isn't relied on for anything else.
//   - InpOutX64 (inpoutx64.dll/.sys): MMIO reads/writes of the actual
//     capability/runtime/interrupter registers.
// Both must sit next to this executable. If InitializeOls fails, check the
// Vulnerable Driver Blocklist setting.

#include "../common/xHCICommon.h"
#include <conio.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>

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

// Where the exe and drivers are copied before registering the logon task,
// so the task keeps working even if the original folder (e.g. Downloads)
// gets cleaned up later.
constexpr wchar_t INSTALL_DIR[] = L"C:\\Windows\\IMOD";

// Copies one file from srcDir to INSTALL_DIR, unless it's already there.
static bool CopyToInstallDir(const std::wstring& srcDir, const wchar_t* fileName, Logger& log) {
    std::wstring src = srcDir + L"\\" + fileName;
    std::wstring dst = std::wstring(INSTALL_DIR) + L"\\" + fileName;
    if (_wcsicmp(src.c_str(), dst.c_str()) == 0) return true;

    bool ok = CopyFileW(src.c_str(), dst.c_str(), FALSE) != FALSE;
    log.Line("copy %ls to install dir: %s", fileName, ok ? "ok" : "failed");
    return ok;
}

// Copies this exe and its drivers to INSTALL_DIR, then registers a Task
// Scheduler entry that runs the installed copy with -silent at logon.
static int AddToTaskScheduler(Logger& log) {
    wchar_t exePathBuf[MAX_PATH];
    GetModuleFileNameW(nullptr, exePathBuf, MAX_PATH);
    std::wstring exePath(exePathBuf);

    size_t slash = exePath.find_last_of(L"\\/");
    std::wstring srcDir = (slash == std::wstring::npos) ? L"." : exePath.substr(0, slash);
    std::wstring exeName = (slash == std::wstring::npos) ? exePath : exePath.substr(slash + 1);

    CreateDirectoryW(INSTALL_DIR, nullptr); // fine if it already exists

    if (!CopyToInstallDir(srcDir, exeName.c_str(), log)) {
        Out("error: could not copy %ls to %ls\n", exeName.c_str(), INSTALL_DIR);
        log.Line("add to Task Scheduler: failed to copy exe to install dir, aborting");
        return 1;
    }
    CopyToInstallDir(srcDir, L"WinRing0x64.dll", log);
    CopyToInstallDir(srcDir, L"WinRing0x64.sys", log);
    CopyToInstallDir(srcDir, L"inpoutx64.dll", log);
    CopyToInstallDir(srcDir, L"inpoutx64.sys", log);

    std::wstring installedExe = std::wstring(INSTALL_DIR) + L"\\" + exeName;
    std::wstring taskRun = L"\"" + installedExe + L"\" -silent";

    std::wstring cmdLine;
    for (const std::wstring& arg : {
             std::wstring(L"schtasks"), std::wstring(L"/create"),
             std::wstring(L"/tn"), std::wstring(L"xHCI IMOD"),
             std::wstring(L"/tr"), taskRun,
             std::wstring(L"/sc"), std::wstring(L"onlogon"),
             std::wstring(L"/rl"), std::wstring(L"highest"),
             std::wstring(L"/f")}) {
        AppendQuotedArg(cmdLine, arg);
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    DWORD exitCode = 1;

    if (CreateProcessW(nullptr, cmdLine.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        log.Line("add to Task Scheduler: CreateProcess failed (error %lu)", GetLastError());
    }

    bool ok = (exitCode == 0);
    if (ok) {
        Out("Installed to %ls and created Task Scheduler entry \"xHCI IMOD\": runs at logon with -silent.\n", INSTALL_DIR);
    } else {
        Out("Failed to create the Task Scheduler entry (schtasks exit code %lu).\n", exitCode);
    }
    log.Line("add to Task Scheduler: schtasks exit code %lu", exitCode);

    return ok ? 0 : 1;
}

// Patch routine

// Registers found on a controller, and how many were verified updated.
struct PatchResult {
    DWORD total = 0;
    int updated = 0;
};

// Patches every register on one controller.
static PatchResult DisableImod(WinRing0& ols, InpOut& io, Logger& log, const xHCIController& controller, int index) {
    xHCIRuntimeInfo info = ResolveRuntimeInfo(ols, io, controller.pciAddress);
    int displayNumber = index + 1;

    log.Line("controller #%d (pci 0x%04X): max_interrupters=%lu", index, controller.pciAddress, info.maxIntrs);

    if (!info.valid) {
        Out("Controller %d: could not be accessed, skipped (%s).\n", displayNumber, info.failReason);
        log.Line("controller #%d: %s, skipping", index, info.failReason);
        return {};
    }

    PhysMemWindow rtWindow;
    if (!rtWindow.Map(io, info.runtimeBase, InterrupterWindowSize(info.maxIntrs))) {
        Out("Controller %d: could not be accessed, skipped (failed to map runtime register window).\n", displayNumber);
        log.Line("controller #%d: failed to map runtime register window, skipping", index);
        return {};
    }

    Out("Controller %d:\n", displayNumber);

    PatchResult result;
    result.total = info.maxIntrs;
    for (DWORD i = 0; i < info.maxIntrs; ++i) {
        uint64_t addr = ImodAddress(info, i);
        DWORD before = rtWindow.ReadDword(addr);
        rtWindow.WriteDword(addr, g_desiredImodInterval);
        DWORD after = rtWindow.ReadDword(addr);
        bool ok = (after == g_desiredImodInterval);
        result.updated += ok ? 1 : 0;

        Out("  Register %lu: %08lX -> %08lX  [%s]\n", i + 1, before, after, ok ? "OK" : "FAILED");
        log.Line("controller #%d interrupter %2lu @ 0x%016llX: IMOD 0x%08lX -> 0x%08lX [%s]",
                  index, i, static_cast<unsigned long long>(addr), before, after, ok ? "OK" : "FAILED");
    }
    rtWindow.Unmap();
    Out("\n");

    log.Line("controller #%d: patched %lu interrupters, %d verified", index, info.maxIntrs, result.updated);
    return result;
}

// Entry point

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "-silent") == 0) {
            g_silent = true;
        }
    }

    // Detach the console before anything else, so no window flashes on an
    // unattended run.
    if (g_silent) {
        FreeConsole();
    }

    Logger log;
    if (!log.Open()) {
        ErrOut("warning: could not open log file (%s); continuing without logging\n", log.lastError.c_str());
    }
    log.Line("xHCIImodDisable run started");

    // Ask before touching anything, so exiting has zero side effects.
    bool scheduleTask = false;
    if (!g_silent) {
        for (;;) {
            ClearConsole();
            Out("xHCI IMOD Disabler\n");
            Out("  1) Disable IMOD\n");
            Out("  2) Test IMOD (62.5Hz)\n");
            Out("  3) Add to Task Scheduler (installs to C:\\Windows\\IMOD, runs at logon)\n");
            Out("  4) Exit\n");
            Out("Choice: ");
            int choice = _getch();

            if (choice == '1') {
                g_desiredImodInterval = 0x0;
                break;
            } else if (choice == '2') {
                g_desiredImodInterval = TEST_IMOD_INTERVAL;
                break;
            } else if (choice == '3') {
                scheduleTask = true;
                break;
            } else if (choice == '4') {
                ClearConsole();
                Out("Exiting, nothing was patched.\n");
                log.Line("user chose Exit from startup menu, nothing patched");
                log.Close();
                return 0;
            }
        }
        ClearConsole();
    }

    if (!IsElevated()) {
        ErrOut("error: administrator privileges required\n");
        log.Line("error: administrator privileges required");
        log.Close();
        return 1;
    }

    if (scheduleTask) {
        int result = AddToTaskScheduler(log);
        log.Close();
        if (!g_silent) {
            printf("\nPress any key to exit...");
            _getch();
        }
        return result;
    }

    WinRing0 ols;
    if (!ols.Load()) {
        ErrOut("error (WinRing0): %s\n", ols.lastError.c_str());
        log.Line("error (WinRing0): %s", ols.lastError.c_str());
        log.Close();
        return 1;
    }

    if (!ols.InitializeOls()) {
        ErrOut("error: InitializeOls failed (dll status = %lu)\n", ols.GetDllStatus());
        ErrOut("       if the driver failed to load, check the Microsoft Vulnerable Driver\n");
        ErrOut("       Blocklist setting (VulnerableDriverBlocklistEnable in the CI\\Config key)\n");
        log.Line("error: InitializeOls failed (dll status = %lu)", ols.GetDllStatus());
        ols.Unload();
        log.Close();
        return 1;
    }

    InpOut io;
    if (!io.Load()) {
        ErrOut("error (InpOutX64): %s\n", io.lastError.c_str());
        log.Line("error (InpOutX64): %s", io.lastError.c_str());
        ols.DeinitializeOls();
        ols.Unload();
        log.Close();
        return 1;
    }

    std::vector<xHCIController> controllers = FindxHCIControllers(ols);
    if (controllers.empty()) {
        Out("No USB controllers were found.\n");
        log.Line("no xHCI controllers found");
    }

    int updatedTotal = 0;
    DWORD registerTotal = 0;
    for (size_t i = 0; i < controllers.size(); ++i) {
        PatchResult result = DisableImod(ols, io, log, controllers[i], static_cast<int>(i));
        updatedTotal += result.updated;
        registerTotal += result.total;
    }

    io.Unload();
    ols.DeinitializeOls();
    ols.Unload();

    if (!controllers.empty()) {
        Out("Done: %d of %lu register%s updated successfully across %zu controller%s.\n",
            updatedTotal, registerTotal, registerTotal == 1 ? "" : "s",
            controllers.size(), controllers.size() == 1 ? "" : "s");
    }
    log.Line("run complete: %d of %lu registers updated successfully across %zu controllers",
              updatedTotal, registerTotal, controllers.size());
    log.Close();

    if (!g_silent) {
        printf("\nPress any key to exit...");
        _getch();
    }

    return (updatedTotal > 0 || controllers.empty()) ? 0 : 1;
}
