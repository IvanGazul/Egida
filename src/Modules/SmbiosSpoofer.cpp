#include "SmbiosSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Core/Logger.h"

// Static members
PVOID SmbiosSpoofer::s_NtoskrnlBase = nullptr;
PPHYSICAL_ADDRESS SmbiosSpoofer::s_SmbiosPhysicalAddress = nullptr;
PULONG SmbiosSpoofer::s_SmbiosTableLength = nullptr;
PBOOT_ENVIRONMENT_INFORMATION SmbiosSpoofer::s_BootEnvironmentInfo = nullptr;

#define GET_ORIGINAL_STRING(header, index) (index == 0 ? "" : EgidaUtils::GetSmbiosString(header, index))
#define GET_SPOOFED_OR_ORIGINAL(profile_str, original_str) (strlen(profile_str) > 0 ? profile_str : original_str)

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

static UCHAR AppendString(PUCHAR stringSectionStart, PUCHAR* currentStringEnd, PCSTR stringToWrite, PUCHAR bufferEnd) {
    EgidaLogDebug("AppendString ENTRY: string='%s', start=0x%p, currentEnd=0x%p, bufferEnd=0x%p",
        stringToWrite ? stringToWrite : "NULL", stringSectionStart, *currentStringEnd, bufferEnd);

    if (!stringToWrite) {
        EgidaLogDebug("AppendString: stringToWrite is NULL, returning 0");
        return 0;
    }

    if (*stringToWrite == '\0') {
        EgidaLogDebug("AppendString: stringToWrite is empty, returning 0");
        return 0;
    }

    EgidaLogDebug("AppendString: string is valid, proceeding...");

    UCHAR stringNumber = 1;
    PUCHAR scanner = stringSectionStart;

    EgidaLogDebug("AppendString: calculating string number, starting from 1");

    while (scanner < *currentStringEnd) {
        EgidaLogDebug("AppendString: found existing string at 0x%p: '%.20s'", scanner, scanner);
        SIZE_T len = strlen((PCSTR)scanner);
        scanner += len + 1;
        stringNumber++;
        EgidaLogDebug("AppendString: moved to next string, stringNumber now = %d", stringNumber);
    }

    EgidaLogDebug("AppendString: calculated stringNumber = %d", stringNumber);

    SIZE_T originalStringLen = strlen(stringToWrite);
    SIZE_T availableSpace = bufferEnd - *currentStringEnd;

    // Учитываем null terminator
    if (availableSpace < 2) { // Минимум 1 символ + null terminator
        EgidaLogError("AppendString: Not enough space even for 1 char + null terminator");
        return 0;
    }

    SIZE_T maxStringLen = availableSpace - 1; // Резервируем место для null terminator
    SIZE_T actualStringLen = min(originalStringLen, maxStringLen);

    EgidaLogDebug("AppendString: original len=%zu, available=%zu, actual len=%zu",
        originalStringLen, availableSpace, actualStringLen);

    if (actualStringLen < originalStringLen) {
        EgidaLogWarning("AppendString: Truncating string '%s' from %zu to %zu chars",
            stringToWrite, originalStringLen, actualStringLen);
    }

    EgidaLogDebug("AppendString: copying %zu bytes to 0x%p", actualStringLen, *currentStringEnd);

    // Копируем только actualStringLen символов
    RtlCopyMemory(*currentStringEnd, stringToWrite, actualStringLen);

    // Добавляем null terminator
    (*currentStringEnd)[actualStringLen] = '\0';

    *currentStringEnd += actualStringLen + 1;

    EgidaLogDebug("AppendString: SUCCESS! Returning stringNumber = %d, new currentStringEnd = 0x%p",
        stringNumber, *currentStringEnd);

    return stringNumber;
}

NTSTATUS SmbiosSpoofer::ChangeBootEnvironmentInfo(_In_ PEGIDA_CONTEXT Context) {
    if (!Context || !s_BootEnvironmentInfo || !Context->ProfileData) {
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

        // Set new GUID from profile (convert from byte array to GUID structure)
        RtlCopyMemory(&s_BootEnvironmentInfo->BootIdentifier, Context->ProfileData->BootIdentifier, sizeof(GUID));

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

    if (!Context->ProfileData) {
        EgidaLogError("No profile data available");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Executing SMBIOS spoofing...");

    // Map the original SMBIOS table
    PVOID mappedBase = MmMapIoSpace(*s_SmbiosPhysicalAddress, *s_SmbiosTableLength, MmNonCached);
    if (!mappedBase) {
        EgidaLogError("Failed to map SMBIOS tables");
        return EGIDA_FAILED;
    }
    Context->SmbiosTableBase = mappedBase;

    // Allocate a temporary buffer for the new table. Add some padding for safety.
    ULONG newTableBufferSize = *s_SmbiosTableLength + PAGE_SIZE;
    PVOID newTableBuffer = ExAllocatePoolWithTag(NonPagedPool, newTableBufferSize, 'SMBP');
    if (!newTableBuffer) {
        EgidaLogError("Failed to allocate buffer for new SMBIOS table");
        MmUnmapIoSpace(mappedBase, *s_SmbiosTableLength);
        return EGIDA_FAILED;
    }
    RtlZeroMemory(newTableBuffer, newTableBufferSize);

    NTSTATUS status = EGIDA_SUCCESS;
    ULONG finalTableSize = 0;

    __try {
        // Rebuild the entire SMBIOS table in our new buffer
        status = LoopAndRebuildSmbiosTables(mappedBase, *s_SmbiosTableLength, newTableBuffer, newTableBufferSize, &finalTableSize, Context);
        if (!NT_SUCCESS(status)) {
            EgidaLogError("Failed to process and rebuild SMBIOS tables: 0x%08X", status);
            __leave;
        }

        // Check if the new table fits into the original space
        if (finalTableSize > *s_SmbiosTableLength) {
            EgidaLogError("FATAL: Rebuilt SMBIOS table size (%lu) exceeds original size (%lu). Cannot spoof.", finalTableSize, *s_SmbiosTableLength);
            status = EGIDA_FAILED;
            __leave;
        }

        // Copy the new table over the original one
        RtlCopyMemory(mappedBase, newTableBuffer, finalTableSize);
        EgidaLogInfo("Successfully copied spoofed SMBIOS table. New size: %lu", finalTableSize);

        // Change boot environment info if available
        if (s_BootEnvironmentInfo) {
            ChangeBootEnvironmentInfo(Context);
        }

        EgidaLogInfo("SMBIOS spoofing completed successfully");

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogError("Exception during SMBIOS spoofing");
        status = EGIDA_FAILED;
    }

    // Cleanup
    ExFreePoolWithTag(newTableBuffer, 'SMBP');

    // Unmap the region on failure; on success, keep it mapped for potential restoration.
    if (!NT_SUCCESS(status)) {
        MmUnmapIoSpace(mappedBase, *s_SmbiosTableLength);
        Context->SmbiosTableBase = nullptr;
    }

    return status;
}

NTSTATUS SmbiosSpoofer::ProcessAndRebuildTable(_In_ PSMBIOS_HEADER ReadHeader, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context) {
    switch (ReadHeader->Type) {
    case SMBIOS_TYPE_BIOS:
        return ProcessBiosInfo(reinterpret_cast<PSMBIOS_BIOS_INFO>(ReadHeader), WritePtr, BufferEnd, Context);
    case SMBIOS_TYPE_SYSTEM:
        return ProcessSystemInfo(reinterpret_cast<PSMBIOS_SYSTEM_INFO>(ReadHeader), WritePtr, BufferEnd, Context);
    case SMBIOS_TYPE_BASEBOARD:
        return ProcessBaseboardInfo(reinterpret_cast<PSMBIOS_BASEBOARD_INFO>(ReadHeader), WritePtr, BufferEnd, Context);
    case SMBIOS_TYPE_CHASSIS:
        return ProcessChassisInfo(reinterpret_cast<PSMBIOS_CHASSIS_INFO>(ReadHeader), WritePtr, BufferEnd, Context);
    case SMBIOS_TYPE_PROCESSOR:
        return ProcessProcessorInfo(reinterpret_cast<PSMBIOS_PROCESSOR_INFO>(ReadHeader), WritePtr, BufferEnd, Context);
    case SMBIOS_TYPE_MEMORY_DEVICE:
        return ProcessMemoryDeviceInfo(reinterpret_cast<PSMBIOS_MEMORY_DEVICE_INFO>(ReadHeader), WritePtr, BufferEnd, Context);
        // These types are processed by just copying, as they have no strings to spoof in this implementation
    case SMBIOS_TYPE_MEMORY_ARRAY:
    default:
        // For unknown or unprocessed types, just copy them as-is
    {
        PUCHAR stringSection = (PUCHAR)ReadHeader + ReadHeader->Length;
        PUCHAR endOfStringSection = stringSection;
        while (endOfStringSection < (PUCHAR)ReadHeader + 4096 && (*endOfStringSection != 0 || *(endOfStringSection + 1) != 0)) {
            endOfStringSection++;
        }
        endOfStringSection += 2; // Include the double null-terminator

        ULONG totalStructSize = (ULONG)(endOfStringSection - (PUCHAR)ReadHeader);

        if (*WritePtr + totalStructSize > BufferEnd) {
            EgidaLogError("Not enough space to copy structure type %d", ReadHeader->Type);
            return EGIDA_FAILED;
        }

        RtlCopyMemory(*WritePtr, ReadHeader, totalStructSize);
        *WritePtr += totalStructSize;
    }
    return EGIDA_SUCCESS;
    }
}

NTSTATUS SmbiosSpoofer::LoopAndRebuildSmbiosTables(_In_ PVOID ReadBase, _In_ ULONG ReadSize, _In_ PVOID WriteBase, _In_ ULONG WriteSize, _Out_ PULONG FinalSize, _In_ PEGIDA_CONTEXT Context) {
    PUCHAR readPtr = (PUCHAR)ReadBase;
    PUCHAR readEnd = readPtr + ReadSize;
    PUCHAR writePtr = (PUCHAR)WriteBase;
    PUCHAR writeEnd = writePtr + WriteSize;

    while (readPtr < readEnd) {
        PSMBIOS_HEADER header = (PSMBIOS_HEADER)readPtr;
        if (header->Type == SMBIOS_TYPE_END && header->Length == 4) {
            // End of tables found, copy the end marker and finish.
            if (writePtr + 4 <= writeEnd) {
                RtlCopyMemory(writePtr, header, 4);
                writePtr += 4;
            }
            break;
        }

        if (header->Length < sizeof(SMBIOS_HEADER)) {
            EgidaLogError("Malformed SMBIOS table - invalid header length");
            return EGIDA_FAILED;
        }

        NTSTATUS status = ProcessAndRebuildTable(header, &writePtr, writeEnd, Context);
        if (!NT_SUCCESS(status)) {
            EgidaLogWarning("Failed to process SMBIOS table type %d", header->Type);
            // Even if one table fails, we try to continue. You might want to return EGIDA_FAILED here instead.
        }

        // Move read pointer to the next structure
        PUCHAR stringSection = readPtr + header->Length;
        while (stringSection < readEnd - 1 && (*stringSection != 0 || *(stringSection + 1) != 0)) {
            stringSection++;
        }
        stringSection += 2; // Move past the double null-terminator
        readPtr = stringSection;
    }

    *FinalSize = (ULONG)(writePtr - (PUCHAR)WriteBase);
    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessBiosInfo(_In_ PSMBIOS_BIOS_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context) {
    EgidaLogDebug("Rebuilding BIOS Information (Type 0)");
    if (*WritePtr + ReadInfo->Header.Length + 256 > BufferEnd) return EGIDA_FAILED; // Safety margin for strings

    PSMBIOS_BIOS_INFO writeInfo = (PSMBIOS_BIOS_INFO)*WritePtr;
    RtlCopyMemory(writeInfo, ReadInfo, ReadInfo->Header.Length);

    PUCHAR stringSectionStart = *WritePtr + ReadInfo->Header.Length;
    PUCHAR stringSectionEnd = stringSectionStart;

    PSMBIOS_PROFILE_DATA profile = Context->ProfileData;

    PCSTR vendor = GET_SPOOFED_OR_ORIGINAL(profile->BiosVendor, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Vendor));
    PCSTR version = GET_SPOOFED_OR_ORIGINAL(profile->BiosVersion, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->BiosVersion));
    PCSTR releaseDate = GET_SPOOFED_OR_ORIGINAL(profile->BiosReleaseDate, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->BiosReleaseDate));

    writeInfo->Vendor = AppendString(stringSectionStart, &stringSectionEnd, vendor, BufferEnd);
    writeInfo->BiosVersion = AppendString(stringSectionStart, &stringSectionEnd, version, BufferEnd);
    writeInfo->BiosReleaseDate = AppendString(stringSectionStart, &stringSectionEnd, releaseDate, BufferEnd);

    *stringSectionEnd++ = '\0'; // Final null terminator for the string section
    *WritePtr = stringSectionEnd;
    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessSystemInfo(_In_ PSMBIOS_SYSTEM_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context) {
    EgidaLogDebug("Rebuilding System Information (Type 1)");
    if (*WritePtr + ReadInfo->Header.Length + 512 > BufferEnd) return EGIDA_FAILED; // Safety margin for strings

    PSMBIOS_SYSTEM_INFO writeInfo = (PSMBIOS_SYSTEM_INFO)*WritePtr;
    RtlCopyMemory(writeInfo, ReadInfo, ReadInfo->Header.Length);

    PUCHAR stringSectionStart = *WritePtr + ReadInfo->Header.Length;
    PUCHAR stringSectionEnd = stringSectionStart;

    PSMBIOS_PROFILE_DATA profile = Context->ProfileData;

    PCSTR manufacturer = GET_SPOOFED_OR_ORIGINAL(profile->SystemManufacturer, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Manufacturer));
    PCSTR productName = GET_SPOOFED_OR_ORIGINAL(profile->SystemProductName, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->ProductName));
    PCSTR version = GET_SPOOFED_OR_ORIGINAL(profile->SystemVersion, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Version));
    PCSTR serialNumber = GET_SPOOFED_OR_ORIGINAL(profile->SystemSerialNumber, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->SerialNumber));
    PCSTR skuNumber = GET_SPOOFED_OR_ORIGINAL(profile->SystemSKUNumber, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->SKUNumber));
    PCSTR family = GET_SPOOFED_OR_ORIGINAL(profile->SystemFamily, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Family));

    writeInfo->Manufacturer = AppendString(stringSectionStart, &stringSectionEnd, manufacturer, BufferEnd);
    writeInfo->ProductName = AppendString(stringSectionStart, &stringSectionEnd, productName, BufferEnd);
    writeInfo->Version = AppendString(stringSectionStart, &stringSectionEnd, version, BufferEnd);
    writeInfo->SerialNumber = AppendString(stringSectionStart, &stringSectionEnd, serialNumber, BufferEnd);
    writeInfo->SKUNumber = AppendString(stringSectionStart, &stringSectionEnd, skuNumber, BufferEnd);
    writeInfo->Family = AppendString(stringSectionStart, &stringSectionEnd, family, BufferEnd);

    // Update UUID directly
    RtlCopyMemory(writeInfo->UUID, profile->SystemUUID, 16);
    EgidaLogDebug("Updated system UUID");

    *stringSectionEnd++ = '\0';
    *WritePtr = stringSectionEnd;
    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessBaseboardInfo(_In_ PSMBIOS_BASEBOARD_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context) {
    EgidaLogDebug("Rebuilding Baseboard Information (Type 2)");
    if (*WritePtr + ReadInfo->Header.Length + 512 > BufferEnd) return EGIDA_FAILED;

    PSMBIOS_BASEBOARD_INFO writeInfo = (PSMBIOS_BASEBOARD_INFO)*WritePtr;
    RtlCopyMemory(writeInfo, ReadInfo, ReadInfo->Header.Length);

    PUCHAR stringSectionStart = *WritePtr + ReadInfo->Header.Length;
    PUCHAR stringSectionEnd = stringSectionStart;

    PSMBIOS_PROFILE_DATA profile = Context->ProfileData;

    PCSTR manufacturer = GET_SPOOFED_OR_ORIGINAL(profile->BaseboardManufacturer, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Manufacturer));
    PCSTR product = GET_SPOOFED_OR_ORIGINAL(profile->BaseboardProduct, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Product));
    PCSTR version = GET_SPOOFED_OR_ORIGINAL(profile->BaseboardVersion, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Version));
    PCSTR serial = GET_SPOOFED_OR_ORIGINAL(profile->BaseboardSerialNumber, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->SerialNumber));
    PCSTR assetTag = GET_SPOOFED_OR_ORIGINAL(profile->BaseboardAssetTag, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->AssetTag));
    PCSTR location = GET_SPOOFED_OR_ORIGINAL(profile->BaseboardLocationInChassis, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->LocationInChassis));

    writeInfo->Manufacturer = AppendString(stringSectionStart, &stringSectionEnd, manufacturer, BufferEnd);
    writeInfo->Product = AppendString(stringSectionStart, &stringSectionEnd, product, BufferEnd);
    writeInfo->Version = AppendString(stringSectionStart, &stringSectionEnd, version, BufferEnd);
    writeInfo->SerialNumber = AppendString(stringSectionStart, &stringSectionEnd, serial, BufferEnd);
    writeInfo->AssetTag = AppendString(stringSectionStart, &stringSectionEnd, assetTag, BufferEnd);
    writeInfo->LocationInChassis = AppendString(stringSectionStart, &stringSectionEnd, location, BufferEnd);

    *stringSectionEnd++ = '\0';
    *WritePtr = stringSectionEnd;
    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessChassisInfo(_In_ PSMBIOS_CHASSIS_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context) {
    EgidaLogDebug("Rebuilding Chassis Information (Type 3)");
    if (*WritePtr + ReadInfo->Header.Length + 512 > BufferEnd) return EGIDA_FAILED;

    PSMBIOS_CHASSIS_INFO writeInfo = (PSMBIOS_CHASSIS_INFO)*WritePtr;
    RtlCopyMemory(writeInfo, ReadInfo, ReadInfo->Header.Length);

    PUCHAR stringSectionStart = *WritePtr + ReadInfo->Header.Length;
    PUCHAR stringSectionEnd = stringSectionStart;

    PSMBIOS_PROFILE_DATA profile = Context->ProfileData;

    PCSTR manufacturer = GET_SPOOFED_OR_ORIGINAL(profile->ChassisManufacturer, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Manufacturer));
    PCSTR version = GET_SPOOFED_OR_ORIGINAL(profile->ChassisVersion, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Version));
    PCSTR serial = GET_SPOOFED_OR_ORIGINAL(profile->ChassisSerialNumber, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->SerialNumber));
    PCSTR assetTag = GET_SPOOFED_OR_ORIGINAL(profile->ChassisAssetTag, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->AssetTagNumber));

    writeInfo->Manufacturer = AppendString(stringSectionStart, &stringSectionEnd, manufacturer, BufferEnd);
    writeInfo->Version = AppendString(stringSectionStart, &stringSectionEnd, version, BufferEnd);
    writeInfo->SerialNumber = AppendString(stringSectionStart, &stringSectionEnd, serial, BufferEnd);
    writeInfo->AssetTagNumber = AppendString(stringSectionStart, &stringSectionEnd, assetTag, BufferEnd);

    *stringSectionEnd++ = '\0';
    *WritePtr = stringSectionEnd;
    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessProcessorInfo(_In_ PSMBIOS_PROCESSOR_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context) {
    EgidaLogDebug("Rebuilding Processor Information (Type 4)");
    if (*WritePtr + ReadInfo->Header.Length + 512 > BufferEnd) return EGIDA_FAILED;

    PSMBIOS_PROCESSOR_INFO writeInfo = (PSMBIOS_PROCESSOR_INFO)*WritePtr;
    RtlCopyMemory(writeInfo, ReadInfo, ReadInfo->Header.Length);

    PUCHAR stringSectionStart = *WritePtr + ReadInfo->Header.Length;
    PUCHAR stringSectionEnd = stringSectionStart;

    PSMBIOS_PROFILE_DATA profile = Context->ProfileData;

    PCSTR socket = GET_SPOOFED_OR_ORIGINAL(profile->ProcessorSocketDesignation, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->SocketDesignation));
    PCSTR manufacturer = GET_SPOOFED_OR_ORIGINAL(profile->ProcessorManufacturer, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->ProcessorManufacturer));
    PCSTR version = GET_SPOOFED_OR_ORIGINAL(profile->ProcessorVersion, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->ProcessorVersion));
    PCSTR serial = GET_SPOOFED_OR_ORIGINAL(profile->ProcessorSerialNumber, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->SerialNumber));
    PCSTR assetTag = GET_SPOOFED_OR_ORIGINAL(profile->ProcessorAssetTag, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->AssetTag));
    PCSTR partNumber = GET_SPOOFED_OR_ORIGINAL(profile->ProcessorPartNumber, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->PartNumber));

    writeInfo->SocketDesignation = AppendString(stringSectionStart, &stringSectionEnd, socket, BufferEnd);
    writeInfo->ProcessorManufacturer = AppendString(stringSectionStart, &stringSectionEnd, manufacturer, BufferEnd);
    writeInfo->ProcessorVersion = AppendString(stringSectionStart, &stringSectionEnd, version, BufferEnd);
    writeInfo->SerialNumber = AppendString(stringSectionStart, &stringSectionEnd, serial, BufferEnd);
    writeInfo->AssetTag = AppendString(stringSectionStart, &stringSectionEnd, assetTag, BufferEnd);
    writeInfo->PartNumber = AppendString(stringSectionStart, &stringSectionEnd, partNumber, BufferEnd);

    // Update Processor ID directly
    writeInfo->ProcessorID = profile->ProcessorID;
    EgidaLogDebug("Updated processor ID");

    *stringSectionEnd++ = '\0';
    *WritePtr = stringSectionEnd;
    return EGIDA_SUCCESS;
}

NTSTATUS SmbiosSpoofer::ProcessMemoryDeviceInfo(_In_ PSMBIOS_MEMORY_DEVICE_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context) {
    EgidaLogDebug("Rebuilding Memory Device Information (Type 17)");
    if (*WritePtr + ReadInfo->Header.Length + 2048 > BufferEnd) return EGIDA_FAILED;

    PSMBIOS_MEMORY_DEVICE_INFO writeInfo = (PSMBIOS_MEMORY_DEVICE_INFO)*WritePtr;
    RtlCopyMemory(writeInfo, ReadInfo, ReadInfo->Header.Length);

    PUCHAR stringSectionStart = *WritePtr + ReadInfo->Header.Length;
    PUCHAR stringSectionEnd = stringSectionStart;

    PSMBIOS_PROFILE_DATA profile = Context->ProfileData;

    PCSTR deviceLocator = GET_SPOOFED_OR_ORIGINAL(profile->MemoryDeviceLocator, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->DeviceLocator));
    PCSTR bankLocator = GET_SPOOFED_OR_ORIGINAL(profile->MemoryBankLocator, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->BankLocator));
    PCSTR manufacturer = GET_SPOOFED_OR_ORIGINAL(profile->MemoryManufacturer, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->Manufacturer));
    PCSTR serial = GET_SPOOFED_OR_ORIGINAL(profile->MemorySerialNumber, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->SerialNumber));
    PCSTR partNumber = GET_SPOOFED_OR_ORIGINAL(profile->MemoryPartNumber, GET_ORIGINAL_STRING(&ReadInfo->Header, ReadInfo->PartNumber));

    EgidaLogDebug("Memory Serial: '%s', Memory PartNumber: '%s'", serial, partNumber);
    
    EgidaLogDebug("Serial string index: %d, PartNumber string index: %d",
        writeInfo->SerialNumber, writeInfo->PartNumber);
    
    EgidaLogDebug("SMBIOS offsets - SerialNumber: 0x%X, PartNumber: 0x%X",
        FIELD_OFFSET(SMBIOS_MEMORY_DEVICE_INFO, SerialNumber),
        FIELD_OFFSET(SMBIOS_MEMORY_DEVICE_INFO, PartNumber));
    
    writeInfo->DeviceLocator = AppendString(stringSectionStart, &stringSectionEnd, deviceLocator, BufferEnd);
    writeInfo->BankLocator = AppendString(stringSectionStart, &stringSectionEnd, bankLocator, BufferEnd);
    writeInfo->Manufacturer = AppendString(stringSectionStart, &stringSectionEnd, manufacturer, BufferEnd);
    writeInfo->SerialNumber = AppendString(stringSectionStart, &stringSectionEnd, serial, BufferEnd);
    writeInfo->PartNumber = AppendString(stringSectionStart, &stringSectionEnd, partNumber, BufferEnd);
    
    EgidaLogDebug("Updated memory device IDs");

    *stringSectionEnd++ = '\0';
    *WritePtr = stringSectionEnd;
    return EGIDA_SUCCESS;
}