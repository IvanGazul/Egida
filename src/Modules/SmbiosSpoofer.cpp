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

VOID SmbiosSpoofer::SetStringFromProfile(_In_ PCHAR Buffer, _In_ PCSTR ProfileValue, _In_ UINT32 MaxLength) {
    if (!Buffer || !ProfileValue) return;

    SIZE_T profileLen = strlen(ProfileValue);
    SIZE_T maxLen = MaxLength > 0 ? MaxLength : strlen(Buffer);
    SIZE_T copyLen = min(profileLen, maxLen);

    // Direct character-by-character modification
    for (SIZE_T i = 0; i < copyLen; i++) {
        Buffer[i] = ProfileValue[i];
    }

    // Null terminate if we have space
    if (copyLen < maxLen) {
        Buffer[copyLen] = '\0';
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

        // Copy UUID from profile
        if (Context->HasProfileData) {
            RtlCopyMemory(&s_BootEnvironmentInfo->BootIdentifier, Context->CurrentProfile.SystemUUID, 16);
        }
        else {
            // Fallback to random if no profile
            EgidaRandomizer::GenerateRandomUUID(&s_BootEnvironmentInfo->BootIdentifier);
        }

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

    if (!Context->HasProfileData) {
        EgidaLogError("No profile data available for SMBIOS spoofing");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Executing SMBIOS spoofing with profile data...");

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
    case SMBIOS_TYPE_BIOS:
        EgidaLogDebug("Processing BIOS Information (Type 0)");
        return ProcessBiosInfo(reinterpret_cast<PSMBIOS_BIOS_INFO>(Header), Context);

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

    EgidaLogInfo("Processing BIOS Information (Type 0) with profile data");

    // Set BIOS vendor
    PCHAR vendor = EgidaUtils::GetSmbiosString(&BiosInfo->Header, BiosInfo->Vendor);
    if (vendor) {
        EgidaLogDebug("Original BIOS vendor: %s", vendor);
        SetStringFromProfile(vendor, Context->CurrentProfile.BiosVendor, strlen(vendor));
        EgidaLogDebug("New BIOS vendor: %s", vendor);
    }
    else if (strlen(Context->CurrentProfile.BiosVendor) > 0) {
        // Allocate new string for null field
        AllocateAndSetSmbiosString(&BiosInfo->Header, BiosInfo->Vendor, Context->CurrentProfile.BiosVendor, Context);
        EgidaLogDebug("Allocated BIOS vendor: %s", Context->CurrentProfile.BiosVendor);
    }

    // Set BIOS version
    PCHAR biosVersion = EgidaUtils::GetSmbiosString(&BiosInfo->Header, BiosInfo->BiosVersion);
    if (biosVersion) {
        EgidaLogDebug("Original BIOS version: %s", biosVersion);
        SetStringFromProfile(biosVersion, Context->CurrentProfile.BiosVersion, strlen(biosVersion));
        EgidaLogDebug("New BIOS version: %s", biosVersion);
    }
    else if (strlen(Context->CurrentProfile.BiosVersion) > 0) {
        AllocateAndSetSmbiosString(&BiosInfo->Header, BiosInfo->BiosVersion, Context->CurrentProfile.BiosVersion, Context);
        EgidaLogDebug("Allocated BIOS version: %s", Context->CurrentProfile.BiosVersion);
    }

    // Set BIOS release date
    PCHAR releaseDate = EgidaUtils::GetSmbiosString(&BiosInfo->Header, BiosInfo->BiosReleaseDate);
    if (releaseDate) {
        EgidaLogDebug("Original BIOS release date: %s", releaseDate);
        SetStringFromProfile(releaseDate, Context->CurrentProfile.BiosReleaseDate, strlen(releaseDate));
        EgidaLogDebug("New BIOS release date: %s", releaseDate);
    }
    else if (strlen(Context->CurrentProfile.BiosReleaseDate) > 0) {
        AllocateAndSetSmbiosString(&BiosInfo->Header, BiosInfo->BiosReleaseDate, Context->CurrentProfile.BiosReleaseDate, Context);
        EgidaLogDebug("Allocated BIOS release date: %s", Context->CurrentProfile.BiosReleaseDate);
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessSystemInfo(_In_ PSMBIOS_SYSTEM_INFO SystemInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!SystemInfo || !Context) {
        EgidaLogError("Invalid parameters for ProcessSystemInfo");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("=== PROCESSING SYSTEM INFORMATION (TYPE 1) ===");

    // Log original UUID first
    EgidaLogDebug("Original System UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        SystemInfo->UUID[0], SystemInfo->UUID[1], SystemInfo->UUID[2], SystemInfo->UUID[3],
        SystemInfo->UUID[4], SystemInfo->UUID[5], SystemInfo->UUID[6], SystemInfo->UUID[7],
        SystemInfo->UUID[8], SystemInfo->UUID[9], SystemInfo->UUID[10], SystemInfo->UUID[11],
        SystemInfo->UUID[12], SystemInfo->UUID[13], SystemInfo->UUID[14], SystemInfo->UUID[15]);

    // Set manufacturer
    PCHAR manufacturer = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->Manufacturer);
    if (manufacturer) {
        EgidaLogDebug("Original system manufacturer: %s", manufacturer);
        SetStringFromProfile(manufacturer, Context->CurrentProfile.SystemManufacturer, strlen(manufacturer));
        EgidaLogDebug("New system manufacturer: %s", manufacturer);
    }
    else if (strlen(Context->CurrentProfile.SystemManufacturer) > 0) {
        AllocateAndSetSmbiosString(&SystemInfo->Header, SystemInfo->Manufacturer, Context->CurrentProfile.SystemManufacturer, Context);
        EgidaLogDebug("Allocated system manufacturer: %s", Context->CurrentProfile.SystemManufacturer);
    }

    // Set product name
    PCHAR productName = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->ProductName);
    if (productName) {
        EgidaLogDebug("Original product name: %s", productName);
        SetStringFromProfile(productName, Context->CurrentProfile.SystemProductName, strlen(productName));
        EgidaLogDebug("New product name: %s", productName);
    }
    else if (strlen(Context->CurrentProfile.SystemProductName) > 0) {
        AllocateAndSetSmbiosString(&SystemInfo->Header, SystemInfo->ProductName, Context->CurrentProfile.SystemProductName, Context);
        EgidaLogDebug("Allocated product name: %s", Context->CurrentProfile.SystemProductName);
    }

    // Set version
    PCHAR version = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->Version);
    if (version) {
        EgidaLogDebug("Original system version: %s", version);
        SetStringFromProfile(version, Context->CurrentProfile.SystemVersion, strlen(version));
        EgidaLogDebug("New system version: %s", version);
    }
    else if (strlen(Context->CurrentProfile.SystemVersion) > 0) {
        AllocateAndSetSmbiosString(&SystemInfo->Header, SystemInfo->Version, Context->CurrentProfile.SystemVersion, Context);
        EgidaLogDebug("Allocated system version: %s", Context->CurrentProfile.SystemVersion);
    }

    // Set serial number
    PCHAR serialNumber = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->SerialNumber);
    if (serialNumber) {
        EgidaLogDebug("Original system serial: %s", serialNumber);
        SetStringFromProfile(serialNumber, Context->CurrentProfile.SystemSerialNumber, strlen(serialNumber));
        EgidaLogDebug("New system serial: %s", serialNumber);
    }
    else if (strlen(Context->CurrentProfile.SystemSerialNumber) > 0) {
        AllocateAndSetSmbiosString(&SystemInfo->Header, SystemInfo->SerialNumber, Context->CurrentProfile.SystemSerialNumber, Context);
        EgidaLogDebug("Allocated system serial: %s", Context->CurrentProfile.SystemSerialNumber);
    }

    // Set SKU number
    PCHAR skuNumber = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->SKUNumber);
    if (skuNumber) {
        EgidaLogDebug("Original SKU number: %s", skuNumber);
        SetStringFromProfile(skuNumber, Context->CurrentProfile.SystemSKU, strlen(skuNumber));
        EgidaLogDebug("New SKU number: %s", skuNumber);
    }
    else if (strlen(Context->CurrentProfile.SystemSKU) > 0) {
        AllocateAndSetSmbiosString(&SystemInfo->Header, SystemInfo->SKUNumber, Context->CurrentProfile.SystemSKU, Context);
        EgidaLogDebug("Allocated SKU number: %s", Context->CurrentProfile.SystemSKU);
    }

    // Set family
    PCHAR family = EgidaUtils::GetSmbiosString(&SystemInfo->Header, SystemInfo->Family);
    if (family) {
        EgidaLogDebug("Original system family: %s", family);
        SetStringFromProfile(family, Context->CurrentProfile.SystemFamily, strlen(family));
        EgidaLogDebug("New system family: %s", family);
    }
    else if (strlen(Context->CurrentProfile.SystemFamily) > 0) {
        AllocateAndSetSmbiosString(&SystemInfo->Header, SystemInfo->Family, Context->CurrentProfile.SystemFamily, Context);
        EgidaLogDebug("Allocated system family: %s", Context->CurrentProfile.SystemFamily);
    }

    // === CRITICAL: Set UUID ===
    EgidaLogInfo("=== SETTING SYSTEM UUID ===");

    // Log profile UUID
    EgidaLogDebug("Profile UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        Context->CurrentProfile.SystemUUID[0], Context->CurrentProfile.SystemUUID[1],
        Context->CurrentProfile.SystemUUID[2], Context->CurrentProfile.SystemUUID[3],
        Context->CurrentProfile.SystemUUID[4], Context->CurrentProfile.SystemUUID[5],
        Context->CurrentProfile.SystemUUID[6], Context->CurrentProfile.SystemUUID[7],
        Context->CurrentProfile.SystemUUID[8], Context->CurrentProfile.SystemUUID[9],
        Context->CurrentProfile.SystemUUID[10], Context->CurrentProfile.SystemUUID[11],
        Context->CurrentProfile.SystemUUID[12], Context->CurrentProfile.SystemUUID[13],
        Context->CurrentProfile.SystemUUID[14], Context->CurrentProfile.SystemUUID[15]);

    // Check if profile UUID is valid (not all zeros)
    BOOLEAN isValidUUID = FALSE;
    for (int i = 0; i < 16; i++) {
        if (Context->CurrentProfile.SystemUUID[i] != 0) {
            isValidUUID = TRUE;
            break;
        }
    }

    if (isValidUUID) {
        // Copy UUID from profile
        RtlCopyMemory(SystemInfo->UUID, Context->CurrentProfile.SystemUUID, 16);
        EgidaLogInfo("UUID set from profile successfully");
    }
    else {
        EgidaLogWarning("Profile UUID is invalid (all zeros), generating random UUID");
        EgidaRandomizer::GenerateRandomUUID(reinterpret_cast<GUID*>(SystemInfo->UUID));
        EgidaLogInfo("Generated random UUID");
    }

    // Log final UUID
    EgidaLogInfo("Final System UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        SystemInfo->UUID[0], SystemInfo->UUID[1], SystemInfo->UUID[2], SystemInfo->UUID[3],
        SystemInfo->UUID[4], SystemInfo->UUID[5], SystemInfo->UUID[6], SystemInfo->UUID[7],
        SystemInfo->UUID[8], SystemInfo->UUID[9], SystemInfo->UUID[10], SystemInfo->UUID[11],
        SystemInfo->UUID[12], SystemInfo->UUID[13], SystemInfo->UUID[14], SystemInfo->UUID[15]);

    EgidaLogInfo("=== SYSTEM INFORMATION PROCESSING COMPLETED ===");
    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessBaseboardInfo(_In_ PSMBIOS_BASEBOARD_INFO BaseboardInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!BaseboardInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Baseboard Information (Type 2) with profile data");

    // Set manufacturer
    PCHAR manufacturer = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->Manufacturer);
    if (manufacturer) {
        EgidaLogDebug("Original baseboard manufacturer: %s", manufacturer);
        SetStringFromProfile(manufacturer, Context->CurrentProfile.BaseboardManufacturer, strlen(manufacturer));
        EgidaLogDebug("New baseboard manufacturer: %s", manufacturer);
    }
    else if (strlen(Context->CurrentProfile.BaseboardManufacturer) > 0) {
        AllocateAndSetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->Manufacturer, Context->CurrentProfile.BaseboardManufacturer, Context);
        EgidaLogDebug("Allocated baseboard manufacturer: %s", Context->CurrentProfile.BaseboardManufacturer);
    }

    // Set product
    PCHAR product = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->Product);
    if (product) {
        EgidaLogDebug("Original baseboard product: %s", product);
        SetStringFromProfile(product, Context->CurrentProfile.BaseboardProduct, strlen(product));
        EgidaLogDebug("New baseboard product: %s", product);
    }
    else if (strlen(Context->CurrentProfile.BaseboardProduct) > 0) {
        AllocateAndSetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->Product, Context->CurrentProfile.BaseboardProduct, Context);
        EgidaLogDebug("Allocated baseboard product: %s", Context->CurrentProfile.BaseboardProduct);
    }

    // Set version
    PCHAR version = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->Version);
    if (version) {
        EgidaLogDebug("Original baseboard version: %s", version);
        SetStringFromProfile(version, Context->CurrentProfile.BaseboardVersion, strlen(version));
        EgidaLogDebug("New baseboard version: %s", version);
    }
    else if (strlen(Context->CurrentProfile.BaseboardVersion) > 0) {
        AllocateAndSetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->Version, Context->CurrentProfile.BaseboardVersion, Context);
        EgidaLogDebug("Allocated baseboard version: %s", Context->CurrentProfile.BaseboardVersion);
    }

    // Set serial number
    PCHAR serialNumber = EgidaUtils::GetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->SerialNumber);
    if (serialNumber) {
        EgidaLogDebug("Original baseboard serial: %s", serialNumber);
        SetStringFromProfile(serialNumber, Context->CurrentProfile.BaseboardSerial, strlen(serialNumber));
        EgidaLogDebug("New baseboard serial: %s", serialNumber);
    }
    else if (strlen(Context->CurrentProfile.BaseboardSerial) > 0) {
        AllocateAndSetSmbiosString(&BaseboardInfo->Header, BaseboardInfo->SerialNumber, Context->CurrentProfile.BaseboardSerial, Context);
        EgidaLogDebug("Allocated baseboard serial: %s", Context->CurrentProfile.BaseboardSerial);
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessChassisInfo(_In_ PSMBIOS_CHASSIS_INFO ChassisInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!ChassisInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Chassis Information (Type 3) with profile data");

    // Set manufacturer
    PCHAR manufacturer = EgidaUtils::GetSmbiosString(&ChassisInfo->Header, ChassisInfo->Manufacturer);
    if (manufacturer) {
        EgidaLogDebug("Original chassis manufacturer: %s", manufacturer);
        SetStringFromProfile(manufacturer, Context->CurrentProfile.ChassisManufacturer, strlen(manufacturer));
        EgidaLogDebug("New chassis manufacturer: %s", manufacturer);
    }
    else if (strlen(Context->CurrentProfile.ChassisManufacturer) > 0) {
        AllocateAndSetSmbiosString(&ChassisInfo->Header, ChassisInfo->Manufacturer, Context->CurrentProfile.ChassisManufacturer, Context);
        EgidaLogDebug("Allocated chassis manufacturer: %s", Context->CurrentProfile.ChassisManufacturer);
    }

    // Set version
    PCHAR version = EgidaUtils::GetSmbiosString(&ChassisInfo->Header, ChassisInfo->Version);
    if (version) {
        EgidaLogDebug("Original chassis version: %s", version);
        SetStringFromProfile(version, Context->CurrentProfile.ChassisVersion, strlen(version));
        EgidaLogDebug("New chassis version: %s", version);
    }
    else if (strlen(Context->CurrentProfile.ChassisVersion) > 0) {
        AllocateAndSetSmbiosString(&ChassisInfo->Header, ChassisInfo->Version, Context->CurrentProfile.ChassisVersion, Context);
        EgidaLogDebug("Allocated chassis version: %s", Context->CurrentProfile.ChassisVersion);
    }

    // Set serial number
    PCHAR serialNumber = EgidaUtils::GetSmbiosString(&ChassisInfo->Header, ChassisInfo->SerialNumber);
    if (serialNumber) {
        EgidaLogDebug("Original chassis serial: %s", serialNumber);
        SetStringFromProfile(serialNumber, Context->CurrentProfile.ChassisSerial, strlen(serialNumber));
        EgidaLogDebug("New chassis serial: %s", serialNumber);
    }
    else if (strlen(Context->CurrentProfile.ChassisSerial) > 0) {
        AllocateAndSetSmbiosString(&ChassisInfo->Header, ChassisInfo->SerialNumber, Context->CurrentProfile.ChassisSerial, Context);
        EgidaLogDebug("Allocated chassis serial: %s", Context->CurrentProfile.ChassisSerial);
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessProcessorInfo(_In_ PSMBIOS_PROCESSOR_INFO ProcessorInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!ProcessorInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Processor Information (Type 4) with profile data");

    if (strlen(Context->CurrentProfile.ProcessorId) > 0) {
        EgidaLogDebug("Setting processor ID from profile");
        UINT64 processorId = 0;
        for (int i = 0; i < strlen(Context->CurrentProfile.ProcessorId) && i < 16; i++) {
            char c = Context->CurrentProfile.ProcessorId[i];
            if (c >= '0' && c <= '9') {
                processorId = (processorId << 4) | (c - '0');
            }
            else if (c >= 'A' && c <= 'F') {
                processorId = (processorId << 4) | (c - 'A' + 10);
            }
            else if (c >= 'a' && c <= 'f') {
                processorId = (processorId << 4) | (c - 'a' + 10);
            }
        }
        ProcessorInfo->ProcessorID = processorId;
        EgidaLogDebug("Set processor ID: 0x%llx", processorId);
    }

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessMemoryArrayInfo(_In_ PSMBIOS_MEMORY_ARRAY_INFO MemoryArrayInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!MemoryArrayInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Memory Array Information (Type 16)");

    // Randomize memory error information handle
    MemoryArrayInfo->MemoryErrorInformationHandle = static_cast<UINT16>(EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFE));
    EgidaLogDebug("Randomized memory error information handle: 0x%04X", MemoryArrayInfo->MemoryErrorInformationHandle);

    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessMemoryDeviceInfo(_In_ PSMBIOS_MEMORY_DEVICE_INFO MemoryDeviceInfo, _In_ PEGIDA_CONTEXT Context) {
    if (!MemoryDeviceInfo || !Context) return EGIDA_FAILED;

    EgidaLogInfo("Processing Memory Device Information (Type 17)");

    // Randomize device locator
    PCHAR deviceLocator = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->DeviceLocator);
    if (deviceLocator) {
        EgidaLogDebug("Original device locator: %s", deviceLocator);
        EgidaRandomizer::RandomizeString(deviceLocator);
        EgidaLogDebug("New device locator: %s", deviceLocator);
    }

    // Randomize bank locator
    PCHAR bankLocator = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->BankLocator);
    if (bankLocator) {
        EgidaLogDebug("Original bank locator: %s", bankLocator);
        EgidaRandomizer::RandomizeString(bankLocator);
        EgidaLogDebug("New bank locator: %s", bankLocator);
    }

    // Randomize manufacturer
    PCHAR manufacturer = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->Manufacturer);
    if (manufacturer) {
        EgidaLogDebug("Original memory manufacturer: %s", manufacturer);
        EgidaRandomizer::RandomizeString(manufacturer);
        EgidaLogDebug("New memory manufacturer: %s", manufacturer);
    }

    // Randomize asset tag
    PCHAR assetTag = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->AssetTag);
    if (assetTag) {
        EgidaLogDebug("Original memory asset tag: %s", assetTag);
        EgidaRandomizer::RandomizeString(assetTag);
        EgidaLogDebug("New memory asset tag: %s", assetTag);
    }

    // Randomize part number
    PCHAR partNumber = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->PartNumber);
    if (partNumber) {
        EgidaLogDebug("Original memory part number: %s", partNumber);
        EgidaRandomizer::RandomizeString(partNumber);
        EgidaLogDebug("New memory part number: %s", partNumber);
    }

    // Randomize firmware version (if present)
    PCHAR firmwareVersion = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->FirmwareVersion);
    if (firmwareVersion) {
        EgidaLogDebug("Original firmware version: %s", firmwareVersion);
        EgidaRandomizer::RandomizeString(firmwareVersion);
        EgidaLogDebug("New firmware version: %s", firmwareVersion);
    }

    // Randomize serial number
    PCHAR serialNumber = EgidaUtils::GetSmbiosString(&MemoryDeviceInfo->Header, MemoryDeviceInfo->SerialNumber);
    if (serialNumber) {
        EgidaLogDebug("Original memory serial: %s", serialNumber);
        EgidaRandomizer::RandomizeString(serialNumber);
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

    // Get pointer to existing string
    PCHAR existingString = EgidaUtils::GetSmbiosString(Header, StringNumber);

    SIZE_T newValueLength = strlen(NewValue);
    SIZE_T allocSize = newValueLength + 1;

    if (!existingString) {
        // Field is null - need to allocate memory
        EgidaLogDebug("SMBIOS string %d is null, allocating memory (size: %zu)", StringNumber, allocSize);

        PCHAR allocatedString = static_cast<PCHAR>(EGIDA_ALLOC_NON_PAGED(allocSize));
        if (!allocatedString) {
            EgidaLogError("Failed to allocate SMBIOS string memory");
            return EGIDA_INSUFFICIENT_RESOURCES;
        }

        // Use direct character-by-character copy like the randomizer
        for (SIZE_T i = 0; i < newValueLength; i++) {
            allocatedString[i] = NewValue[i];
        }
        allocatedString[newValueLength] = '\0';

        // Track allocated memory
        NTSTATUS status = TrackAllocatedSmbiosString(Context, allocatedString, allocSize, Header, StringNumber);
        if (!NT_SUCCESS(status)) {
            EGIDA_FREE(allocatedString);
            return status;
        }

        EgidaLogDebug("Allocated and set SMBIOS string: %s", NewValue);
    }
    else {
        // Field exists - modify in place using direct character modification
        SIZE_T existingLength = strlen(existingString);
        SIZE_T copyLength = min(newValueLength, existingLength);

        // Direct character-by-character modification
        for (SIZE_T i = 0; i < copyLength; i++) {
            existingString[i] = NewValue[i];
        }

        // Null terminate if we have space
        if (copyLength < existingLength) {
            existingString[copyLength] = '\0';
        }

        EgidaLogDebug("Modified existing SMBIOS string: %s", NewValue);

        // If the new value is longer than existing space, we need to allocate
        if (newValueLength > existingLength) {
            PCHAR allocatedString = static_cast<PCHAR>(EGIDA_ALLOC_NON_PAGED(allocSize));
            if (!allocatedString) {
                EgidaLogError("Failed to allocate larger SMBIOS string memory");
                return EGIDA_INSUFFICIENT_RESOURCES;
            }

            // Use direct character copying
            for (SIZE_T i = 0; i < newValueLength; i++) {
                allocatedString[i] = NewValue[i];
            }
            allocatedString[newValueLength] = '\0';

            // Clear old string
            RtlZeroMemory(existingString, existingLength);

            // Track new allocated memory
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
    // Expand tracking array
    ULONG newCount = Context->SmbiosAllocatedStringCount + 1;
    PSMBIOS_ALLOCATED_STRING newArray = static_cast<PSMBIOS_ALLOCATED_STRING>(
        EGIDA_ALLOC_NON_PAGED(newCount * sizeof(SMBIOS_ALLOCATED_STRING))
        );

    if (!newArray) {
        return EGIDA_INSUFFICIENT_RESOURCES;
    }

    // Copy existing entries
    if (Context->SmbiosAllocatedStrings) {
        RtlCopyMemory(newArray, Context->SmbiosAllocatedStrings,
            Context->SmbiosAllocatedStringCount * sizeof(SMBIOS_ALLOCATED_STRING));
        EGIDA_FREE(Context->SmbiosAllocatedStrings);
    }

    // Add new entry
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