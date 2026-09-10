# xHCI IMOD Disabler
Disables xHCI Interrupt Moderation (IMOD) on every USB host controller found in the system by patching each interrupter's IMOD register to 0 via PCI/MMIO access (WinRing0 + InpOutX64). Features a log file located at %LOCALAPPDATA%\xHCI IMOD\Log.txt.

<img width="978" height="512" alt="xHCI" src="https://github.com/user-attachments/assets/e231dcb6-f3e5-4528-9821-5a9659180812" />

![GitHub Release Downloads](https://img.shields.io/github/downloads/southtowne/xHCI-IMOD-Disable/total)

# Usage
Simply follow the quick and easy steps below ↓

1. Download [Release.7z](https://github.com/southtowne/xHCI-IMOD-Disable/releases/download/IMOD/Release.7z).
2. Right-click & extract to a folder like C:\Windows\Misc
3. Right-click xHCIImodDisable.exe -> Run as administrator. Add -silent as a launch argument for [Task Scheduler](https://www.windowscentral.com/how-create-automated-task-using-task-scheduler-windows-10) use.

# Build instructions:

1. Prerequisites: Windows 10/11 x64, Visual Studio 2022+ with the "Desktop development with C++" workload (MSVC v143+ toolset, Windows 10/11 SDK).
2. Clone: git clone https://github.com/southtowne/xHCI-IMOD-Disable.git
3. Build: Open xHCIImodDisable.sln in Visual Studio and Build Solution
4. Output: the exe lands at x64\Release\xHCIImodDisable.exe.
5. Add the drivers: copy all four files from the repo's Drivers\ folder (WinRing0x64.dll, WinRing0x64.sys, inpoutx64.dll, inpoutx64.sys) into that same x64\Release\ folder, next to the exe — it won't run without them sitting right beside it.
6. Right-click xHCIImodDisable.exe -> Run as administrator. Add -silent as a launch argument for [Task Scheduler](https://www.windowscentral.com/how-create-automated-task-using-task-scheduler-windows-10) use.
