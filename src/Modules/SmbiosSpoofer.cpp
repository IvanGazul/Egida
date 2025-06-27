#include "SmbiosSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Utils/Randomizer.h"
#include "../Core/Logger.h"

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
    case SMBIOS_TYPE_PROCESSOR:
        EgidaLogDebug("Processing Processor Information (Type 4)");
        return ProcessProcessorInfo(reinterpret_cast<PSMBIOS_PROCESSOR_INFO>(Header), Context);

    default:
        // Skip unknown types
        EgidaLogDebug("Skipping SMBIOS table type %d", Header->Type);
        return EGIDA_SUCCESS;
    }
}

NTSTATUS SmbiosSpoofer::ProcessBiosInfo(_In_ PSMBIOS_BIOS_INFO BiosInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!BiosInfo || !Context) return EGIDA_FAILED;

    if (Context->Config.RandomConfig.RandomizeStrings) {
        PCHAR vendor = EgidaUtils::GetSmbiosString(&BiosInfo->Header, BiosInfo->Vendor);
        if (vendor) {
            EgidaLogDebug("Original BIOS vendor: %s", vendor);
            RandomizeString(vendor);
            EgidaLogDebug("New BIOS vendor: %s", vendor);
        }
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessSystemInfo(_In_ PSMBIOS_SYSTEM_INFO SystemInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!SystemInfo || !Context) return EGIDA_FAILED;

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
        RtlZeroMemory(SystemInfo->UUID, 16);
        EgidaRandomizer::GenerateRandomBytes(SystemInfo->UUID, 16);
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessBaseboardInfo(_In_ PSMBIOS_BASEBOARD_INFO BaseboardInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!BaseboardInfo || !Context) return EGIDA_FAILED;

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

    if (Context->Config.RandomConfig.RandomizeStrings) {
        PCHAR manufacturer = EgidaUtils::GetSmbiosString(&ChassisInfo->Header, ChassisInfo->Manufacturer);
        if (manufacturer) {
            EgidaLogDebug("Original chassis manufacturer: %s", manufacturer);
            RandomizeString(manufacturer);
            EgidaLogDebug("New chassis manufacturer: %s", manufacturer);
        }
    }

    if (Context->Config.RandomConfig.RandomizeSerials) {
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

    if (Context->Config.RandomConfig.RandomizeStrings) {
        PCHAR manufacturer = EgidaUtils::GetSmbiosString(&ProcessorInfo->Header, ProcessorInfo->ProcessorManufacturer);
        if (manufacturer) {
            EgidaLogDebug("Original processor manufacturer: %s", manufacturer);
            RandomizeString(manufacturer);
            EgidaLogDebug("New processor manufacturer: %s", manufacturer);
        }
    }

    if (Context->Config.RandomConfig.RandomizeSerials) {
        PCHAR serialNumber = EgidaUtils::GetSmbiosString(&ProcessorInfo->Header, ProcessorInfo->SerialNumber);
        if (serialNumber) {
            EgidaLogDebug("Original processor serial: %s", serialNumber);
            RandomizeString(serialNumber);
            EgidaLogDebug("New processor serial: %s", serialNumber);
        }
    }

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