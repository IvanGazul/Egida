# EGIDA - Hardware Telemetry Virtualizer for Windows 10/11 x64

⚠️ **CRITICAL DISCLAIMER:** This project is intended **STRICTLY for kernel developers and security researchers**. It involves hooking and patching undocumented Windows kernel structures. **DO NOT run this on your host machine.** All testing and execution must be performed in an isolated Virtual Machine (VM) environment. This project is provided "as is" for educational and privacy research purposes only.

## 🔬 About the Research
EGIDA is the result of deep reverse engineering of the Windows kernel. The primary goal of this repository is to demonstrate how undocumented internal OS structures (like SMBIOS tables in memory, disk device descriptors, and hardware telemetry caching) can be analyzed and manipulated. It serves as a practical reference for experts interested in advanced kernel-mode development, hooking techniques, and understanding how Windows manages hardware identity at the lowest level.

EGIDA is a lightweight, kernel-level driver designed to modify and virtualize system hardware identifiers on Windows 10/11 x64 systems. Designed strictly for research purposes, it allows security experts to evaluate system fingerprinting techniques, analyze OS telemetry, and test hardware-based software licensing mechanisms.

## ✨ Features
* **Disk Volume ID Virtualization:** Dynamically alters disk serial numbers returned by the system.
* **SMBIOS Table Modification:** Customizes Motherboard/Baseboard descriptors in memory.
* **CPU ID Masking:** Patches responses to `ProcessorId` queries.
* **System Identity Randomization:** Manages Computer Name and Username variables.
* **Registry Telemetry Cleaning:** Clears cached hardware traces in the registry.
* **Fully x64 Supported:** Tested on modern Windows 10/11 environments.
* **UEFI-compatible:** Supports UEFI-based systems.
* **Standalone Operation:** No dependency on external usermode applications.
* **Profile System:** Create, save, and apply custom hardware telemetry configurations.

## 📌 Planned Features
* **Application Telemetry Clearing:** Remove residual hardware identifiers cached by complex software platforms.
* **GPU Data Modification:** Clean or virtualize GPU UUIDs, BIOS versions, and driver strings for privacy research.

## 🔧 Requirements
* Windows 10 / 11 x64
* Test Signing Mode enabled (or use KDMapper / EFIGuard)
* Secure Boot disabled
* Administrator privileges
* **Isolated Virtual Machine (VM) for testing**

## 🧪 How It Works
EGIDA operates by loading a kernel-mode driver that temporarily intercepts and modifies values returned by key Windows management interfaces (such as `wmic`, `GetVolumeInformation`, `GetSystemFirmwareTable`, and others). 

It hooks and patches kernel functions, dynamically modifying SMBIOS tables and disk device descriptors directly in memory without permanent hardware alterations.
