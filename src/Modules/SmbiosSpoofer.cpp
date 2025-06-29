#include "SmbiosSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Utils/Randomizer.h"
#include "../Core/Logger.h"
#include "../Common/Globals.h"

// Static members
PVOID SmbiosSpoofer::s_NtoskrnlBase = nullptr;
PPHYSICAL_ADDRESS SmbiosSpoofer::s_SmbiosPhysicalAddress = nullptr;
PULONG SmbiosSpoofer::s_SmbiosTableLength = nullptr;
PBOOT_ENVIRONMENT_INFORMATION SmbiosSpoofer::s_BootEnvironmentInfo = nullptr;

NTSTATUS SmbiosSpoofer::Initialize(_In_ PEGIDA_CONTEXT Context) {
    EgidaLogInfo("Initializing SMBIOS Spoofer...");

    // Get ntoskrnl.exe base
    s_NtoskrnlBase = EgidaUtils::GetModuleBase("ntoskrnl.exe");
    if (!s_NtoskrnlBase) {
        EgidaLogError("Failed to find ntoskrnl.exe base");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("ntoskrnl.exe base: 0x%p", s_NtoskrnlBase);

    // Find SMBIOS physical address pointer
    PVOID smbiosPhysAddrCall = EgidaUtils::FindPatternInModule(
        s_NtoskrnlBase,
        "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8b\x15",
        "xxx????xxxx?xx"
    );

    if (!smbiosPhysAddrCall) {
        EgidaLogError("Failed to find SMBIOS physical address pattern");
        return EGIDA_FAILED;
    }

    s_SmbiosPhysicalAddress = EgidaUtils::TranslateAddress<PPHYSICAL_ADDRESS>(smbiosPhysAddrCall, 7);
    if (!s_SmbiosPhysicalAddress) {
        EgidaLogError("Failed to get SMBIOS physical address");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("SMBIOS Physical Address: 0x%p", s_SmbiosPhysicalAddress);

    // Find SMBIOS table length
    PVOID smbiosLengthCall = EgidaUtils::FindPatternInModule(
        s_NtoskrnlBase,
        "\x8B\x15\x00\x00\x00\x00\x48\x03\xD1\xC7\x44\x24\x00\x00\x00\x00\x00\x48\x3B\xCA\x73",
        "xx????xxxxxx?????xxxx"
    );

    if (!smbiosLengthCall) {
        EgidaLogError("Failed to find SMBIOS length pattern");
        return EGIDA_FAILED;
    }

    s_SmbiosTableLength = EgidaUtils::TranslateAddress<PULONG>(smbiosLengthCall, 6);
    if (!s_SmbiosTableLength) {
        EgidaLogError("Failed to get SMBIOS table length");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("SMBIOS Table Length: %lu", *s_SmbiosTableLength);

    // Find boot environment information
    PVOID bootInfoCall = EgidaUtils::FindPatternInModule(
        s_NtoskrnlBase,
        "\x0f\x10\x05\x00\x00\x00\x00\x0f\x11\x03\x8b\x05",
        "xxx????xxxxx"
    );

    if (bootInfoCall) {
        s_BootEnvironmentInfo = EgidaUtils::TranslateAddress<PBOOT_ENVIRONMENT_INFORMATION>(bootInfoCall, 7);
        EgidaLogDebug("Boot Environment Info: 0x%p", s_BootEnvironmentInfo);
    }
    else {
        EgidaLogWarning("Boot environment info not found (optional)");
    }

    // Store in context
    Context->SmbiosPhysicalAddress = s_SmbiosPhysicalAddress;
    Context->SmbiosTableSize = *s_SmbiosTableLength;
    Context->BootInfo = s_BootEnvironmentInfo;

    EgidaLogInfo("SMBIOS Spoofer initialized successfully");
    return EGIDA_SUCCESS;
}

VOID SmbiosSpoofer::RandomizeString(_In_ PCHAR String, _In_ UINT32 MaxLength) {
    if (!String) return;

    UINT32 length = MaxLength > 0 ? MaxLength : static_cast<UINT32>(strlen(String));
    if (length > 0) {
        EgidaRandomizer::GenerateRandomString(String, length + 1, TRUE);
    }
}

NTSTATUS SmbiosSpoofer::ChangeBootEnvironmentInfo(_In_ PEGIDA_CONTEXT Context) {
    if (!Context || !s_BootEnvironmentInfo) {
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Changing boot environment information");

    __try {
        // Save original GUID for logging
        GUID originalGuid = s_BootEnvironmentInfo->BootIdentifier;

        EgidaLogDebug("Original Boot GUID: {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
            originalGuid.Data1, originalGuid.Data2, originalGuid.Data3,
            originalGuid.Data4[0], originalGuid.Data4[1], originalGuid.Data4[2], originalGuid.Data4[3],
            originalGuid.Data4[4], originalGuid.Data4[5], originalGuid.Data4[6], originalGuid.Data4[7]);

        // Generate new GUID
        EgidaRandomizer::GenerateRandomUUID(&s_BootEnvironmentInfo->BootIdentifier);

        EgidaLogDebug("New Boot GUID: {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
            s_BootEnvironmentInfo->BootIdentifier.Data1, s_BootEnvironmentInfo->BootIdentifier.Data2,
            s_BootEnvironmentInfo->BootIdentifier.Data3,
            s_BootEnvironmentInfo->BootIdentifier.Data4[0], s_BootEnvironmentInfo->BootIdentifier.Data4[1],
            s_BootEnvironmentInfo->BootIdentifier.Data4[2], s_BootEnvironmentInfo->BootIdentifier.Data4[3],
            s_BootEnvironmentInfo->BootIdentifier.Data4[4], s_BootEnvironmentInfo->BootIdentifier.Data4[5],
            s_BootEnvironmentInfo->BootIdentifier.Data4[6], s_BootEnvironmentInfo->BootIdentifier.Data4[7]);

        EgidaLogInfo("Boot environment info changed successfully");
        return EGIDA_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogError("Exception while changing boot environment info");
        return EGIDA_FAILED;
    }
}

NTSTATUS SmbiosSpoofer::StopSpoof(_In_ PEGIDA_CONTEXT Context) {
    if (!Context) return EGIDA_SUCCESS;

    EgidaLogInfo("Stopping SMBIOS spoofing...");

    // Unmap SMBIOS tables if mapped
    if (Context->SmbiosTableBase) {
        MmUnmapIoSpace(Context->SmbiosTableBase, Context->SmbiosTableSize);
        Context->SmbiosTableBase = nullptr;
    }

    EgidaLogInfo("SMBIOS spoofing stopped");
    return EGIDA_SUCCESS;
}

VOID SmbiosSpoofer::Cleanup(_In_ PEGIDA_CONTEXT Context) {
    if (!Context) return;

    EgidaLogInfo("Cleaning up SMBIOS Spoofer...");

    StopSpoof(Context);

    // Reset static members
    s_NtoskrnlBase = nullptr;
    s_SmbiosPhysicalAddress = nullptr;
    s_SmbiosTableLength = nullptr;
    s_BootEnvironmentInfo = nullptr;

    EgidaLogInfo("SMBIOS Spoofer cleanup completed");
}

NTSTATUS SmbiosSpoofer::ExecuteSpoof(_In_ PEGIDA_CONTEXT Context) {
    if (!Context || !s_SmbiosPhysicalAddress || !s_SmbiosTableLength) {
        EgidaLogError("SMBIOS Spoofer not properly initialized");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Executing SMBIOS spoofing...");

    // Initialize randomizer
    EgidaRandomizer::InitializeSeed(Context->Config.RandomConfig.RandomSeed);

    // Map SMBIOS tables
    PVOID mappedBase = MmMapIoSpace(
        *s_SmbiosPhysicalAddress,
        *s_SmbiosTableLength,
        MmNonCached
    );

    if (!mappedBase) {
        EgidaLogError("Failed to map SMBIOS tables");
        return EGIDA_FAILED;
    }

    Context->SmbiosTableBase = mappedBase;

    __try {
        // Process all SMBIOS tables
        NTSTATUS status = LoopSmbiosTables(mappedBase, *s_SmbiosTableLength, Context);
        if (!NT_SUCCESS(status)) {
            EgidaLogError("Failed to process SMBIOS tables: 0x%08X", status);
            MmUnmapIoSpace(mappedBase, *s_SmbiosTableLength);
            return status;
        }

        // Change boot environment info if available
        if (Context->Config.EnableBootInfoSpoof && s_BootEnvironmentInfo) {
            ChangeBootEnvironmentInfo(Context);
        }

        EgidaLogInfo("SMBIOS spoofing completed successfully");

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogError("Exception during SMBIOS spoofing");
        MmUnmapIoSpace(mappedBase, *s_SmbiosTableLength);
        return EGIDA_FAILED;
    }

    // Keep mapping for potential restoration
    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::LoopSmbiosTables(_In_ PVOID MappedBase, _In_ ULONG TableSize, _In_ PEGIDA_CONTEXT Context) {
    PUCHAR endAddress = static_cast<PUCHAR>(MappedBase) + TableSize;
    PUCHAR currentPos = static_cast<PUCHAR>(MappedBase);

    while (currentPos < endAddress) {
        PSMBIOS_HEADER header = reinterpret_cast<PSMBIOS_HEADER>(currentPos);

        // Check for end of table
        if (header->Type == SMBIOS_TYPE_END && header->Length == 4) {
            break;
        }

        // Process this table
        NTSTATUS status = ProcessSmbiosTable(header, Context);
        if (!NT_SUCCESS(status)) {
            EgidaLogWarning("Failed to process SMBIOS table type %d", header->Type);
        }

        // Move to next table
        PUCHAR stringSection = currentPos + header->Length;

        // Skip to end of strings (double null terminator)
        while (*stringSection != 0 || *(stringSection + 1) != 0) {
            stringSection++;
            if (stringSection >= endAddress) {
                EgidaLogError("Malformed SMBIOS table - string section overflow");
                return EGIDA_FAILED;
            }
        }

        stringSection += 2; // Skip double null
        currentPos = stringSection;
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessSmbiosTable(_In_ PSMBIOS_HEADER Header, _In_ PEGIDA_CONTEXT Context) {
    if (!Header || !Context) {
        return EGIDA_FAILED;
    }

    switch (Header->Type) {
    //case SMBIOS_TYPE_BIOS:
    //    EgidaLogDebug("Processing BIOS Information (Type 0)");
    //    return ProcessBiosInfo(reinterpret_cast<PSMBIOS_BIOS_INFO>(Header), Context);

    case SMBIOS_TYPE_SYSTEM:
        EgidaLogDebug("Processing System Information (Type 1)");
        return ProcessSystemInfo(reinterpret_cast<PSMBIOS_SYSTEM_INFO>(Header), Context);

    case SMBIOS_TYPE_BASEBOARD:
        EgidaLogDebug("Processing Baseboard Information (Type 2)");
        return ProcessBaseboardInfo(reinterpret_cast<PSMBIOS_BASEBOARD_INFO>(Header), Context);

    case SMBIOS_TYPE_CHASSIS:
        EgidaLogDebug("Processing Chassis Information (Type 3)");
        return ProcessChassisInfo(reinterpret_cast<PSMBIOS_CHASSIS_INFO>(Header), Context);

    case SMBIOS_TYPE_PROCESSOR:
        EgidaLogDebug("Processing Processor Information (Type 4)");
        return ProcessProcessorInfo(reinterpret_cast<PSMBIOS_PROCESSOR_INFO>(Header), Context);

    case SMBIOS_TYPE_MEMORY_ARRAY:
        EgidaLogDebug("Processing Memory Array Information (Type 16)");
        return ProcessMemoryArrayInfo(reinterpret_cast<PSMBIOS_MEMORY_ARRAY_INFO>(Header), Context);

    case SMBIOS_TYPE_MEMORY_DEVICE:
        EgidaLogDebug("Processing Memory Device Information (Type 17)");
        return ProcessMemoryDeviceInfo(reinterpret_cast<PSMBIOS_MEMORY_DEVICE_INFO>(Header), Context);
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessBiosInfo(_In_ PSMBIOS_BIOS_INFO BiosInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!BiosInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing BIOS Information (Type 0)");

    if (Context->Config.RandomConfig.RandomizeStrings) {
        // Randomize BIOS vendor
        PCHAR vendor = EgidaUtils::GetSmbiosString(&BiosInfo->Header, BiosInfo->Vendor);
        if (vendor) {
            EgidaLogDebug("Original BIOS vendor: %s", vendor);
            RandomizeString(vendor);
            EgidaLogDebug("New BIOS vendor: %s", vendor);
        }

        // Randomize BIOS version
        PCHAR biosVersion = EgidaUtils::GetSmbiosString(&BiosInfo->Header, BiosInfo->BiosVersion);
        if (biosVersion) {
            EgidaLogDebug("Original BIOS version: %s", biosVersion);
            RandomizeString(biosVersion);
            EgidaLogDebug("New BIOS version: %s", biosVersion);
        }

        // Randomize BIOS release date
        PCHAR releaseDate = EgidaUtils::GetSmbiosString(&BiosInfo->Header, BiosInfo->BiosReleaseDate);
        if (releaseDate) {
            EgidaLogDebug("Original BIOS release date: %s", releaseDate);
            // Generate random date in MM/DD/YYYY format
            CHAR newDate[12];
            RtlStringCbPrintfA(newDate, sizeof(newDate), "%02d/%02d/%04d",
                EgidaRandomizer::GetRandomNumber(1, 12),
                EgidaRandomizer::GetRandomNumber(1, 28),
                EgidaRandomizer::GetRandomNumber(2020, 2024));
            RtlCopyMemory(releaseDate, newDate, min(strlen(newDate), strlen(releaseDate)));
            EgidaLogDebug("New BIOS release date: %s", releaseDate);
        }
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessSystemInfo(_In_ PSMBIOS_SYSTEM_INFO SystemInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!SystemInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing System Information (Type 1)");

    if (Context->Config.RandomConfig.RandomizeStrings) {
        // Randomize manufacturer
        PCHAR manufacturer = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->Manufacturer);
        if (manufacturer) {
            EgidaLogDebug("Original system manufacturer: %s", manufacturer);
            RandomizeString(manufacturer);
            EgidaLogDebug("New system manufacturer: %s", manufacturer);
        }

        // Randomize product name
        PCHAR productName = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->ProductName);
        if (productName) {
            EgidaLogDebug("Original product name: %s", productName);
            RandomizeString(productName);
            EgidaLogDebug("New product name: %s", productName);
        }

        // Randomize version
        PCHAR version = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->Version);
        if (version) {
            EgidaLogDebug("Original system version: %s", version);
            RandomizeString(version);
            EgidaLogDebug("New system version: %s", version);
        }

        // Randomize SKU number
        PCHAR skuNumber = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->SKUNumber);
        if (skuNumber) {
            EgidaLogDebug("Original SKU number: %s", skuNumber);
            RandomizeString(skuNumber);
            EgidaLogDebug("New SKU number: %s", skuNumber);
        }

        // Randomize family
        PCHAR family = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->Family);
        if (family) {
            EgidaLogDebug("Original system family: %s", family);
            RandomizeString(family);
            EgidaLogDebug("New system family: %s", family);
        }
    }

    if (Context->Config.RandomConfig.RandomizeSerials) {
        // Randomize serial number
        PCHAR serialNumber = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->SerialNumber);
        if (serialNumber) {
            EgidaLogDebug("Original system serial: %s", serialNumber);
            RandomizeString(serialNumber);
            EgidaLogDebug("New system serial: %s", serialNumber);
        }
    }

    if (Context->Config.RandomConfig.RandomizeUUID) {
        // Randomize UUID
        EgidaLogDebug("Randomizing system UUID");
        EgidaRandomizer::GenerateRandomBytes(SystemInfo->UUID, 16);

        // Set version (4) and variant bits according to RFC 4122
        SystemInfo->UUID[6] = (SystemInfo->UUID[6] & 0x0F) | 0x40; // Version 4
        SystemInfo->UUID[8] = (SystemInfo->UUID[8] & 0x3F) | 0x80; // Variant bits

        EgidaLogDebug("New system UUID generated");
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessBaseboardInfo(_In_ PSMBIOS_BASEBOARD_INFO BaseboardInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!BaseboardInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Baseboard Information (Type 2)");

    if (Context->Config.RandomConfig.RandomizeStrings) {
        // Randomize manufacturer
        PCHAR manufacturer = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->Manufacturer);
        if (manufacturer) {
            EgidaLogDebug("Original baseboard manufacturer: %s", manufacturer);
            RandomizeString(manufacturer);
            EgidaLogDebug("New baseboard manufacturer: %s", manufacturer);
        }

        // Randomize product
        PCHAR product = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->Product);
        if (product) {
            EgidaLogDebug("Original baseboard product: %s", product);
            RandomizeString(product);
            EgidaLogDebug("New baseboard product: %s", product);
        }

        // Randomize version
        PCHAR version = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->Version);
        if (version) {
            EgidaLogDebug("Original baseboard version: %s", version);
            RandomizeString(version);
            EgidaLogDebug("New baseboard version: %s", version);
        }

        // Randomize asset tag
        PCHAR assetTag = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->AssetTag);
        if (assetTag) {
            EgidaLogDebug("Original baseboard asset tag: %s", assetTag);
            RandomizeString(assetTag);
            EgidaLogDebug("New baseboard asset tag: %s", assetTag);
        }

        // Randomize location in chassis
        PCHAR location = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->LocationInChassis);
        if (location) {
            EgidaLogDebug("Original baseboard location: %s", location);
            RandomizeString(location);
            EgidaLogDebug("New baseboard location: %s", location);
        }
    }

    if (Context->Config.RandomConfig.RandomizeSerials) {
        // Randomize serial number
        PCHAR serialNumber = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->SerialNumber);
        if (serialNumber) {
            EgidaLogDebug("Original baseboard serial: %s", serialNumber);
            RandomizeString(serialNumber);
            EgidaLogDebug("New baseboard serial: %s", serialNumber);
        }
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessChassisInfo(_In_ PSMBIOS_CHASSIS_INFO ChassisInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!ChassisInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Chassis Information (Type 3)");

    if (Context->Config.RandomConfig.RandomizeStrings) {
        // Randomize manufacturer
        PCHAR manufacturer = EgidaUtils::GetSmbiosString(&ChassisInfo->Header, ChassisInfo->Manufacturer);
        if (manufacturer) {
            EgidaLogDebug("Original chassis manufacturer: %s", manufacturer);
            RandomizeString(manufacturer);
            EgidaLogDebug("New chassis manufacturer: %s", manufacturer);
        }

        // Randomize version
        PCHAR version = EgidaUtils::GetSmbiosString(&ChassisInfo->Header, ChassisInfo->Version);
        if (version) {
            EgidaLogDebug("Original chassis version: %s", version);
            RandomizeString(version);
            EgidaLogDebug("New chassis version: %s", version);
        }

        // Randomize asset tag number
        PCHAR assetTag = EgidaUtils::GetSmbiosString(&ChassisInfo->Header, ChassisInfo->AssetTagNumber);
        if (assetTag) {
            EgidaLogDebug("Original chassis asset tag: %s", assetTag);
            RandomizeString(assetTag);
            EgidaLogDebug("New chassis asset tag: %s", assetTag);
        }
    }

    if (Context->Config.RandomConfig.RandomizeSerials) {
        // Randomize serial number
        PCHAR serialNumber = EgidaUtils::GetSmbiosString(&ChassisInfo->Header, ChassisInfo->SerialNumber);
        if (serialNumber) {
            EgidaLogDebug("Original chassis serial: %s", serialNumber);
            RandomizeString(serialNumber);
            EgidaLogDebug("New chassis serial: %s", serialNumber);
        }
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessProcessorInfo(_In_ PSMBIOS_PROCESSOR_INFO ProcessorInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!ProcessorInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Processor Information (Type 4)");

    if (Context->Config.RandomConfig.RandomizeStrings) {
        // Randomize socket designation
        PCHAR socketDesignation = EgidaUtils::GetSmbiosString(&ProcessorInfo->Header, ProcessorInfo->SocketDesignation);
        if (socketDesignation) {
            EgidaLogDebug("Original socket designation: %s", socketDesignation);
            RandomizeString(socketDesignation);
            EgidaLogDebug("New socket designation: %s", socketDesignation);
        }

        // Randomize manufacturer
        PCHAR manufacturer = EgidaUtils::GetSmbiosString(&ProcessorInfo->Header, ProcessorInfo->ProcessorManufacturer);
        if (manufacturer) {
            EgidaLogDebug("Original processor manufacturer: %s", manufacturer);
            RandomizeString(manufacturer);
            EgidaLogDebug("New processor manufacturer: %s", manufacturer);
        }

        // Randomize processor version
        PCHAR version = EgidaUtils::GetSmbiosString(&ProcessorInfo->Header, ProcessorInfo->ProcessorVersion);
        if (version) {
            EgidaLogDebug("Original processor version: %s", version);
            RandomizeString(version);
            EgidaLogDebug("New processor version: %s", version);
        }

        // Randomize asset tag
        PCHAR assetTag = EgidaUtils::GetSmbiosString(&ProcessorInfo->Header, ProcessorInfo->AssetTag);
        if (assetTag) {
            EgidaLogDebug("Original processor asset tag: %s", assetTag);
            RandomizeString(assetTag);
            EgidaLogDebug("New processor asset tag: %s", assetTag);
        }

        // Randomize part number
        PCHAR partNumber = EgidaUtils::GetSmbiosString(&ProcessorInfo->Header, ProcessorInfo->PartNumber);
        if (partNumber) {
            EgidaLogDebug("Original processor part number: %s", partNumber);
            RandomizeString(partNumber);
            EgidaLogDebug("New processor part number: %s", partNumber);
        }
    }

    if (Context->Config.RandomConfig.RandomizeSerials) {
        // Randomize serial number
        PCHAR serialNumber = EgidaUtils::GetSmbiosString(&ProcessorInfo->Header, ProcessorInfo->SerialNumber);
        if (serialNumber) {
            EgidaLogDebug("Original processor serial: %s", serialNumber);
            RandomizeString(serialNumber);
            EgidaLogDebug("New processor serial: %s", serialNumber);
        }
    }

    // Randomize processor ID
    if (Context->Config.RandomConfig.RandomizeUUID) {
        EgidaLogDebug("Randomizing processor ID");
        EgidaRandomizer::GenerateRandomBytes(reinterpret_cast<PUCHAR>(&ProcessorInfo->ProcessorID), sizeof(ProcessorInfo->ProcessorID));
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessMemoryArrayInfo(_In_ PSMBIOS_MEMORY_ARRAY_INFO MemoryArrayInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!MemoryArrayInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Memory Array Information (Type 16)");

    // For memory array, we mainly randomize the error information handle
    if (Context->Config.RandomConfig.RandomizeSerials) {
        // Randomize memory error information handle
        MemoryArrayInfo->MemoryErrorInformationHandle = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFE));
        EgidaLogDebug("Randomized memory error information handle: 0x%04X", MemoryArrayInfo->MemoryErrorInformationHandle);
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessMemoryDeviceInfo(_In_ PSMBIOS_MEMORY_DEVICE_INFO MemoryDeviceInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!MemoryDeviceInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Memory Device Information (Type 17)");

    if (Context->Config.RandomConfig.RandomizeStrings) {
        // Randomize device locator
        PCHAR deviceLocator = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->DeviceLocator);
        if (deviceLocator) {
            EgidaLogDebug("Original device locator: %s", deviceLocator);
            RandomizeString(deviceLocator);
            EgidaLogDebug("New device locator: %s", deviceLocator);
        }

        // Randomize bank locator
        PCHAR bankLocator = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->BankLocator);
        if (bankLocator) {
            EgidaLogDebug("Original bank locator: %s", bankLocator);
            RandomizeString(bankLocator);
            EgidaLogDebug("New bank locator: %s", bankLocator);
        }

        // Randomize manufacturer
        PCHAR manufacturer = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->Manufacturer);
        if (manufacturer) {
            EgidaLogDebug("Original memory manufacturer: %s", manufacturer);
            RandomizeString(manufacturer);
            EgidaLogDebug("New memory manufacturer: %s", manufacturer);
        }

        // Randomize asset tag
        PCHAR assetTag = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->AssetTag);
        if (assetTag) {
            EgidaLogDebug("Original memory asset tag: %s", assetTag);
            RandomizeString(assetTag);
            EgidaLogDebug("New memory asset tag: %s", assetTag);
        }

        // Randomize part number
        PCHAR partNumber = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->PartNumber);
        if (partNumber) {
            EgidaLogDebug("Original memory part number: %s", partNumber);
            RandomizeString(partNumber);
            EgidaLogDebug("New memory part number: %s", partNumber);
        }

        // Randomize firmware version (if present)
        PCHAR firmwareVersion = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->FirmwareVersion);
        if (firmwareVersion) {
            EgidaLogDebug("Original firmware version: %s", firmwareVersion);
            RandomizeString(firmwareVersion);
            EgidaLogDebug("New firmware version: %s", firmwareVersion);
        }
    }

    if (Context->Config.RandomConfig.RandomizeSerials) {
        // Randomize serial number
        PCHAR serialNumber = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->SerialNumber);
        if (serialNumber) {
            EgidaLogDebug("Original memory serial: %s", serialNumber);
            RandomizeString(serialNumber);
            EgidaLogDebug("New memory serial: %s", serialNumber);
        }

        // Randomize memory array handle
        MemoryDeviceInfo->MemoryArrayHandle = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFE));

        // Randomize memory error information handle
        MemoryDeviceInfo->MemoryErrorInformationHandle = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFE));

        // Randomize manufacturer and module IDs
        MemoryDeviceInfo->ModuleManufacturerID = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFF));
        MemoryDeviceInfo->ModuleProductID = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFF));
        MemoryDeviceInfo->MemorySubsystemControllerManufacturerID = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFF));
        MemoryDeviceInfo->MemorySubsystemControllerProductID = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFF));

        // Randomize PMIC and RCD IDs
        MemoryDeviceInfo->Pmic0ManufacturerID = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFF));
        MemoryDeviceInfo->Pmic0RevisionNumber = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x01, 0xFF));
        MemoryDeviceInfo->RcdManufacturerID = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFF));
        MemoryDeviceInfo->RcdRevisionNumber = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x01, 0xFF));

        EgidaLogDebug("Randomized memory device handles and IDs");
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::AllocateAndSetSmbiosString(
    _In_ PSMBIOS_HEADER Header,
    _In_ SMBIOS_STRING StringNumber,
    _In_ PCSTR NewValue,
    _In_ PEGIDA_CONTEXT Context
) {
    if (!Header || !NewValue || !Context) {
        return EGIDA_FAILED;
    }

    // Получаем указатель на строку
    PCHAR existingString = EgidaUtils::GetSmbiosString(Header, StringNumber);

    SIZE_T newValueLength = strlen(NewValue);
    SIZE_T allocSize = newValueLength + 1;

    if (!existingString) {
        // Поле null - нужно выделить память
        EgidaLogDebug("SMBIOS string %d is null, allocating memory (size: %zu)", StringNumber, allocSize);

        PCHAR allocatedString = static_cast<PCHAR>(EGIDA_ALLOC_NON_PAGED(allocSize));
        if (!allocatedString) {
            EgidaLogError("Failed to allocate SMBIOS string memory");
            return EGIDA_INSUFFICIENT_RESOURCES;
        }

        RtlStringCbCopyA(allocatedString, allocSize, NewValue);

        // Добавляем в список отслеживания
        NTSTATUS status = TrackAllocatedSmbiosString(Context, allocatedString, allocSize, Header, StringNumber);
        if (!NT_SUCCESS(status)) {
            EGIDA_FREE(allocatedString);
            return status;
        }

        EgidaLogDebug("Allocated and set SMBIOS string: %s", NewValue);
    }
    else {
        // Поле существует - можем изменить на месте
        SIZE_T existingLength = strlen(existingString);

        if (newValueLength <= existingLength) {
            // Новая строка помещается в существующее место
            RtlZeroMemory(existingString, existingLength);
            RtlStringCbCopyA(existingString, existingLength + 1, NewValue);
            EgidaLogDebug("Modified existing SMBIOS string: %s", NewValue);
        }
        else {
            // Нужно больше места - выделяем новую память
            PCHAR allocatedString = static_cast<PCHAR>(EGIDA_ALLOC_NON_PAGED(allocSize));
            if (!allocatedString) {
                EgidaLogError("Failed to allocate larger SMBIOS string memory");
                return EGIDA_INSUFFICIENT_RESOURCES;
            }

            RtlStringCbCopyA(allocatedString, allocSize, NewValue);

            // Очищаем старую строку
            RtlZeroMemory(existingString, existingLength);

            // Отслеживаем новую выделенную память
            NTSTATUS status = TrackAllocatedSmbiosString(Context, allocatedString, allocSize, Header, StringNumber);
            if (!NT_SUCCESS(status)) {
                EGIDA_FREE(allocatedString);
                return status;
            }

            EgidaLogDebug("Allocated larger SMBIOS string: %s", NewValue);
        }
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::TrackAllocatedSmbiosString(
    _In_ PEGIDA_CONTEXT Context,
    _In_ PCHAR StringPointer,
    _In_ SIZE_T StringSize,
    _In_ PSMBIOS_HEADER Header,
    _In_ SMBIOS_STRING StringNumber
) {
    // Расширяем массив отслеживания
    ULONG newCount = Context->SmbiosAllocatedStringCount + 1;
    PSMBIOS_ALLOCATED_STRING newArray = static_cast<PSMBIOS_ALLOCATED_STRING>(
        EGIDA_ALLOC_NON_PAGED(newCount * sizeof(SMBIOS_ALLOCATED_STRING))
        );

    if (!newArray) {
        return EGIDA_INSUFFICIENT_RESOURCES;
    }

    // Копируем существующие записи
    if (Context->SmbiosAllocatedStrings) {
        RtlCopyMemory(newArray, Context->SmbiosAllocatedStrings,
            Context->SmbiosAllocatedStringCount * sizeof(SMBIOS_ALLOCATED_STRING));
        EGIDA_FREE(Context->SmbiosAllocatedStrings);
    }

    // Добавляем новую запись
    newArray[Context->SmbiosAllocatedStringCount].StringPointer = StringPointer;
    newArray[Context->SmbiosAllocatedStringCount].StringSize = StringSize;
    newArray[Context->SmbiosAllocatedStringCount].OwnerHeader = Header;
    newArray[Context->SmbiosAllocatedStringCount].StringNumber = StringNumber;

    Context->SmbiosAllocatedStrings = newArray;
    Context->SmbiosAllocatedStringCount = newCount;

    return EGIDA_SUCCESS;
}

VOID SmbiosSpoofer::FreeSmbiosAllocatedStrings(_In_ PEGIDA_CONTEXT Context) {
    if (!Context || !Context->SmbiosAllocatedStrings) {
        return;
    }

    EgidaLogDebug("Freeing %lu allocated SMBIOS strings", Context->SmbiosAllocatedStringCount);

    for (ULONG i = 0; i < Context->SmbiosAllocatedStringCount; i++) {
        if (Context->SmbiosAllocatedStrings[i].StringPointer) {
            EgidaLogDebug("Freeing SMBIOS string %d (size: %zu)",
                Context->SmbiosAllocatedStrings[i].StringNumber,
                Context->SmbiosAllocatedStrings[i].StringSize);

            EGIDA_FREE(Context->SmbiosAllocatedStrings[i].StringPointer);
            Context->SmbiosAllocatedStrings[i].StringPointer = nullptr;
        }
    }

    EGIDA_FREE(Context->SmbiosAllocatedStrings);
    Context->SmbiosAllocatedStrings = nullptr;
    Context->SmbiosAllocatedStringCount = 0;

    EgidaLogDebug("SMBIOS string cleanup completed");
}