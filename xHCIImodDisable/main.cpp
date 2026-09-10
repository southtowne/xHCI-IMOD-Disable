// Disables xHCI (USB host controller) Interrupt Moderation (IMOD) for every
// interrupter on every xHCI controller found in the system, by writing 0 to
// each controller's IMOD register(s) directly in MMIO space.
//
// Meant to be run once per boot (e.g. via Task Scheduler, "At log on" or "At
// startup"): the interrupter layout is read fresh from PCI config space and
// the xHCI capability registers every run, so it does not depend on any
// address staying the same across reboots.
//
// By default it prints every register it touches (old value -> new value,
// verified or not) and waits for a keypress before closing so the result is
// visible. Pass -silent for unattended/autostart use (Task Scheduler, a
// startup batch file, a Run registry key) to suppress the console window
// entirely. Every run -- silent or not -- is also appended to
// %LOCALAPPDATA%\xHCI IMOD\Log.txt, so an unattended run's result can still
// be checked afterward.
//
// Two drivers are used, each for what it can actually do:
//   - WinRing0 (WinRing0x64.dll/.sys): PCI config space access only, to find
//     each xHCI controller and its BAR. Many redistributed WinRing0 builds
//     have had physical-memory access stripped out, so it is not relied on
//     for anything else.
//   - InpOutX64 (inpoutx64.dll/.sys): physical memory (MMIO) reads/writes of
//     the actual capability/runtime/interrupter registers.
// Both must be present next to this executable, and it needs administrator
// privileges. If InitializeOls fails, check the Vulnerable Driver Blocklist
// setting (see the error message below).

#include "../common/xHCICommon.h"
#include <conio.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>

// Configuration

// Desired IMOD interval in 250ns units. 0 disables interrupt moderation
// entirely (lowest latency, highest interrupt rate).
constexpr DWORD DESIRED_IMOD_INTERVAL = 0x0;

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

// Patch routine

// Number of registers found on a controller, and how many were successfully
// updated. The console only ever sees these plain numbers; the full
// technical detail (PCI address, physical register address, etc.) still
// goes to the log file for troubleshooting.
struct PatchResult {
    DWORD total = 0;
    int updated = 0;
};

// Patches every register on one controller. Prints and logs each register's
// original value and new value; the console view is kept in plain language,
// the log entry keeps full technical detail.
static PatchResult DisableImod(WinRing0& ols, InpOut& io, Logger& log, const xHCIController& controller, int index) {
    xHCIRuntimeInfo info = ResolveRuntimeInfo(ols, io, controller.pciAddress);
    int displayNumber = index + 1;

    log.Line("controller #%d (pci 0x%04X): max_interrupters=%lu", index, controller.pciAddress, info.maxIntrs);

    if (!info.valid) {
        Out("Controller %d: could not be accessed, skipped.\n", displayNumber);
        log.Line("controller #%d: invalid/unresolved, skipping", index);
        return {};
    }

    PhysMemWindow rtWindow;
    if (!rtWindow.Map(io, info.runtimeBase, InterrupterWindowSize(info.maxIntrs))) {
        Out("Controller %d: could not be accessed, skipped.\n", displayNumber);
        log.Line("controller #%d: failed to map runtime register window, skipping", index);
        return {};
    }

    Out("Controller %d:\n", displayNumber);

    PatchResult result;
    result.total = info.maxIntrs;
    for (DWORD i = 0; i < info.maxIntrs; ++i) {
        uint64_t addr = ImodAddress(info, i);
        DWORD before = rtWindow.ReadDword(addr);
        rtWindow.WriteDword(addr, DESIRED_IMOD_INTERVAL);
        DWORD after = rtWindow.ReadDword(addr);
        bool ok = (after == DESIRED_IMOD_INTERVAL);
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

    // Detach from the console (closing its window if this process owns it)
    // before anything else, so no window ever flashes on an unattended run.
    if (g_silent) {
        FreeConsole();
    }

    Logger log;
    if (!log.Open()) {
        ErrOut("warning: could not open log file (%s); continuing without logging\n", log.lastError.c_str());
    }
    log.Line("xHCIImodDisable run started");

    if (!IsElevated()) {
        ErrOut("error: administrator privileges required\n");
        log.Line("error: administrator privileges required");
        log.Close();
        return 1;
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
