# xHCI IMOD Disabler
Disables xHCI Interrupt Moderation (IMOD) on every USB host controller found in the system by patching each interrupter's IMOD register to 0 via PCI/MMIO access (WinRing0 + InpOutX64). Features a log file located at %LOCALAPPDATA%\xHCI IMOD\Log.txt.

<img width="978" height="512" alt="xHCI" src="https://github.com/user-attachments/assets/e4073d72-abaf-4887-846a-223cfe34f572" />

![GitHub Release Downloads](https://img.shields.io/github/downloads/southtowne/xHCI-IMOD-Disable/total)

# Usage
Simply follow the quick and easy steps below ↓

1. Download [Release.7z](https://github.com/southtowne/xHCI-IMOD-Disable/releases/download/IMOD/Release.7z).
2. Right-click & extract to a folder like C:\Windows\Misc
3. Add xHCIImodDisable.exe to startup via [Task Scheduler](https://www.windowscentral.com/how-create-automated-task-using-task-scheduler-windows-10) as an admin, with the command line -silent to hide the console window.
