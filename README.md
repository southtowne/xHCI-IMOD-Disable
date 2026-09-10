# xHCI-IMOD-Disabler
Disables xHCI Interrupt Moderation (IMOD) on every USB host controller found in the system by patching each interrupter's IMOD register to 0 via PCI/MMIO access (WinRing0 + InpOutX64).
