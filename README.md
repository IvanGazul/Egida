# EGIDA - HWID Spoofer for Windows 10/11 x64

![Windows](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue)
![Status](https://img.shields.io/badge/status-development-orange)
![License](https://img.shields.io/badge/license-MIT-green)

EGIDA is a lightweight, kernel-level HWID spoofer for Windows 10/11 x64 systems.  
Designed for educational and research purposes, EGIDA can spoof several hardware identifiers to bypass basic hardware bans and fingerprinting techniques.

> ⚠️ This project is for **educational** purposes only. Using it to bypass restrictions in unauthorized ways may violate Terms of Service of third-party software or platforms.

---

## ✨ Features

- [x] Disk Serial Number Spoofing
- [x] SMBIOS (Motherboard/Baseboard) Serial Spoofing
- [x] CPU ID Patch (ProcessorId)
- [x] Computer Name and Username Randomization
- [x] Registry Traces Cleaner
- [x] Fully x64 Supported (Tested on Windows 10/11)
- [x] Supports UEFI-based systems
- [x] No dependency on external usermode applications
- [x] Profile System — create, save and apply custom spoofing profiles
---

## 📌 Planned Features
- [ ] Steam Deep Cleaning — remove residual Steam identifiers and traces
- [ ] NVIDIA Spoofing — clean or spoof GPU UUID, BIOS version, and driver strings
---

## 🔧 Requirements

- Windows 10 / 11 x64
- Test Signing Mode enabled (or use KDMapper / EFIGuard)
- Secure Boot **disabled**
- Administrator privileges

---

## 🧪 How It Works

EGIDA operates by loading a kernel-mode driver that temporarily modifies values returned by key Windows management interfaces like `wmic`, `GetVolumeInformation`, `GetSystemFirmwareTable`, and others.

It hooks and patches kernel functions and modifies SMBIOS tables and disk device descriptors in memory.

---

## ⚙️ Usage

```bash
1. Disable Secure Boot in BIOS
2. Map the driver with KDMapper or use EFIGuard
