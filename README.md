# xHCI IMOD Disabler
Disables xHCI Interrupt Moderation (IMOD) on every USB host controller found in the system by patching each interrupter's IMOD register to 0 via PCI/MMIO access (WinRing0 + InpOutX64). Features a log file located at %LOCALAPPDATA%\xHCI IMOD\Log.txt.

<img width="978" height="512" alt="xHCI" src="https://github.com/user-attachments/assets/e231dcb6-f3e5-4528-9821-5a9659180812" />

![GitHub Release Downloads](https://img.shields.io/github/downloads/southtowne/xHCI-IMOD-Disable/total)

# Usage
Simply follow the quick and easy steps below ↓

1. Download [Release.zip](https://github.com/southtowne/xHCI-IMOD-Disable/releases/download/XHCI/Release.zip).
2. Right-click & extract
3. Right-click xHCIImodDisable.exe -> Run as administrator.

# Optional Build instructions:

1. Prerequisites: Windows 10/11 x64, Visual Studio 2022+ with the "Desktop development with C++" workload (MSVC v143+ toolset, Windows 10/11 SDK).
2. Clone: git clone https://github.com/southtowne/xHCI-IMOD-Disable.git
3. Build: Open xHCIImodDisable.sln in Visual Studio and Build Solution
4. Output: the exe lands at x64\Release\xHCIImodDisable.exe, automatically copying the drivers next to it.
5. Right-click xHCIImodDisable.exe -> Run as administrator.
