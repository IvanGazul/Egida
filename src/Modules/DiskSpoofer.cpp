#include "DiskSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Utils/Randomizer.h"
#include "../Core/Logger.h"
#include "../Common/Globals.h"

extern "C" POBJECT_TYPE* IoDriverObjectType;

// Static members
PVOID DiskSpoofer::s_StorportBase = nullptr;
PVOID DiskSpoofer::s_DiskBase = nullptr;
RaidUnitRegisterInterfaces DiskSpoofer::s_RaidUnitRegisterInterfaces = nullptr;
DiskEnableDisableFailurePrediction DiskSpoofer::s_DiskEnableDisableFailurePrediction = nullptr;

NTSTATUS DiskSpoofer::Initialize(
    _In_ PEGIDA_CONTEXT Context
) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Initializing Disk Spoofer...");

    // Get storport.sys base
    s_StorportBase = EgidaUtils::GetModuleBase("storport.sys");
    if (!s_StorportBase) {
        EgidaLogError("Failed to find storport.sys");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("storport.sys base: 0x%p", s_StorportBase);

    // Find RaidUnitRegisterInterfaces
    PVOID raidRegisterPtr = EgidaUtils::FindPatternInModule(
        s_StorportBase,
        "\x48\x89\x5c\x24\x00\x55\x56\x57\x48\x83\xec\x00\x8b\x41\x00\x4c\x8d",
        "xxxx?xxxxxx?xx?xx"
    );

    if (!raidRegisterPtr) {
        EgidaLogError("Failed to find RaidUnitRegisterInterfaces");
        return EGIDA_FAILED;
    }

    s_RaidUnitRegisterInterfaces = reinterpret_cast<RaidUnitRegisterInterfaces>(raidRegisterPtr);
    EgidaLogDebug("RaidUnitRegisterInterfaces: 0x%p", s_RaidUnitRegisterInterfaces);

    // Get disk.sys base
    s_DiskBase = EgidaUtils::GetModuleBase("disk.sys");
    if (!s_DiskBase) {
        EgidaLogError("Failed to find disk.sys");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("disk.sys base: 0x%p", s_DiskBase);

    // Find DiskEnableDisableFailurePrediction
    PVOID diskFailurePtr = EgidaUtils::FindPatternInModule(
        s_DiskBase,
        "\x4c\x8b\xdc\x49\x89\x5b\x00\x49\x89\x7b\x00\x55\x49\x8d\x6b\xa1\x48\x81\xec",
        "xxxxxx?xxx?xxxxxxxx"
    );

    if (!diskFailurePtr) {
        EgidaLogError("Failed to find DiskEnableDisableFailurePrediction");
        return EGIDA_FAILED;
    }

    s_DiskEnableDisableFailurePrediction = reinterpret_cast<DiskEnableDisableFailurePrediction>(diskFailurePtr);
    EgidaLogDebug("DiskEnableDisableFailurePrediction: 0x%p", s_DiskEnableDisableFailurePrediction);

    EgidaLogInfo("Disk Spoofer initialized successfully");
    return EGIDA_SUCCESS;
}

NTSTATUS DiskSpoofer::ExecuteSpoof(
    _In_ PEGIDA_CONTEXT Context
) {
    if (!Context) {
        EgidaLogError("Invalid context");
        return EGIDA_FAILED;
    }

    if (!s_StorportBase || !s_DiskBase || !s_RaidUnitRegisterInterfaces || !s_DiskEnableDisableFailurePrediction) {
        EgidaLogError("Disk Spoofer not properly initialized");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Executing disk spoofing...");

	// Free any previously allocated disk strings
    FreeDiskAllocatedStrings(Context);

    // Initialize randomizer
    EgidaRandomizer::InitializeSeed(Context->Config.RandomConfig.RandomSeed);

    NTSTATUS status = EGIDA_SUCCESS;

    // Disable SMART on all disks
    status = DisableSmartOnAllDisks(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to disable SMART: 0x%08X", status);
        return status;
    }

    // Change disk serials
    status = ChangeDiskSerials(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to change disk serials: 0x%08X", status);
        return status;
    }

    EgidaLogInfo("Disk spoofing completed successfully");
    return EGIDA_SUCCESS;
}

NTSTATUS DiskSpoofer::ChangeDiskSerials(
    _In_ PEGIDA_CONTEXT Context
) {
    EgidaLogInfo("Starting disk serial modification...");
    
	//Free previously allocated strings
    FreeDiskAllocatedStrings(Context);

    NTSTATUS overallStatus = EGIDA_NOT_FOUND;

    // Try to find RAID ports
    for (INT32 i = 0; i < 4; i++) {
        WCHAR raidDeviceName[32];
        swprintf(raidDeviceName, L"\\Device\\RaidPort%d", i);

        PDEVICE_OBJECT raidDevice = GetRaidDevice(raidDeviceName);
        if (!raidDevice) {
            continue;
        }

        EgidaLogDebug("Found RAID device: %ws", raidDeviceName);

        NTSTATUS status = ProcessRaidDevices(raidDevice, Context);
        if (NT_SUCCESS(status)) {
            overallStatus = status;
        }
    }

    if (NT_SUCCESS(overallStatus)) {
        EgidaLogInfo("Disk serials changed successfully");
    }
    else {
        EgidaLogWarning("No disk serials were changed");
    }

    return overallStatus;
}

PDEVICE_OBJECT DiskSpoofer::GetRaidDevice(
    _In_ PCWSTR DeviceName
) {
    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, DeviceName);

    PFILE_OBJECT fileObject = nullptr;
    PDEVICE_OBJECT deviceObject = nullptr;

    NTSTATUS status = IoGetDeviceObjectPointer(
        &deviceName,
        FILE_READ_DATA,
        &fileObject,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        return nullptr;
    }

    PDEVICE_OBJECT targetDevice = deviceObject->DriverObject->DeviceObject;

    if (fileObject) {
        ObDereferenceObject(fileObject);
    }

    return targetDevice;
}

NTSTATUS DiskSpoofer::ProcessRaidDevices(
    _In_ PDEVICE_OBJECT DeviceArray, 
    _In_ PEGIDA_CONTEXT Context
) {
    NTSTATUS status = EGIDA_NOT_FOUND;

    PDEVICE_OBJECT currentDevice = DeviceArray;

    __try {
        while (currentDevice && currentDevice->NextDevice) {
            if (currentDevice->DeviceType == FILE_DEVICE_DISK) {
                PRAID_UNIT_EXTENSION extension = static_cast<PRAID_UNIT_EXTENSION>(currentDevice->DeviceExtension);

                if (extension && EgidaUtils::IsValidKernelPointer(extension)) {
                    status = ProcessSingleDiskDevice(extension, Context);
                    if (NT_SUCCESS(status)) {
                        EgidaLogInfo("Successfully processed disk device");
                    }
                }
            }

            currentDevice = currentDevice->NextDevice;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogError("Exception while processing RAID devices");
        return EGIDA_FAILED;
    }

    return status;
}

NTSTATUS DiskSpoofer::ProcessSingleDiskDevice(
    _In_ PRAID_UNIT_EXTENSION Extension, 
    _In_ PEGIDA_CONTEXT Context
) {
    if (!Extension || !Context) {
        return EGIDA_FAILED;
    }

    NTSTATUS status = EGIDA_SUCCESS;

	// Process disk identity
    PSTRING serialString = &Extension->_Identity.Identity.SerialNumber;
    if (Context->Config.RandomConfig.RandomizeSerials) {
        if (serialString->Buffer && serialString->Length > 0) {
			
            // Existing serial - log original
            CHAR originalSerial[EGIDA_MAX_SERIAL_LENGTH];
            RtlZeroMemory(originalSerial, sizeof(originalSerial));

            ULONG copyLength = min(serialString->Length, sizeof(originalSerial) - 1);
            RtlCopyMemory(originalSerial, serialString->Buffer, copyLength);
            originalSerial[copyLength] = '\0';

            EgidaLogDebug("Original disk serial: %s", originalSerial);

			// Generate new random serial
            CHAR newSerial[EGIDA_MAX_SERIAL_LENGTH];
            EgidaRandomizer::GenerateRandomSerial(newSerial, sizeof(newSerial));

			// Check if new serial fits in existing buffer
            SIZE_T newSerialLength = strlen(newSerial);
            if (newSerialLength <= serialString->MaximumLength) {
				// Fits in existing buffer - update in-place
                RtlZeroMemory(serialString->Buffer, serialString->MaximumLength);
                RtlCopyMemory(serialString->Buffer, newSerial, newSerialLength);
                serialString->Length = static_cast<USHORT>(newSerialLength);

                EgidaLogInfo("Updated disk serial in-place: %s -> %s", originalSerial, newSerial);
            }
            else {
				// Not enough space - allocate new memory
                status = AllocateAndSetDiskString(Extension, serialString, newSerial, Context, DISK_STRING_SERIAL);
                if (NT_SUCCESS(status)) {
                    EgidaLogInfo("Allocated new disk serial: %s -> %s", originalSerial, newSerial);
                }
            }
        }
        else {
            //Null serial
            CHAR newSerial[EGIDA_MAX_SERIAL_LENGTH];
            EgidaRandomizer::GenerateRandomSerial(newSerial, sizeof(newSerial));

            status = AllocateAndSetDiskString(Extension, serialString, newSerial, Context, DISK_STRING_SERIAL);
            if (NT_SUCCESS(status)) {
                EgidaLogInfo("Allocated disk serial for null field: %s", newSerial);
            }
        }
    }

    // Disable SMART for this device
    if (NT_SUCCESS(status)) {
        DisableSmartBit(Extension);

        // Register interfaces to update registry
        if (s_RaidUnitRegisterInterfaces) {
            s_RaidUnitRegisterInterfaces(Extension);
        }
    }

    return status;
}

NTSTATUS DiskSpoofer::AllocateAndSetDiskString(
    _In_ PRAID_UNIT_EXTENSION Extension,
    _In_ PSTRING TargetString,
    _In_ PCSTR NewValue,
    _In_ PEGIDA_CONTEXT Context,
    _In_ ULONG StringType
) {
    if (!Extension || !TargetString || !NewValue || !Context) {
        return EGIDA_FAILED;
    }

    SIZE_T newValueLength = strlen(NewValue);
    SIZE_T allocSize = newValueLength + 1;

    PCHAR allocatedString = static_cast<PCHAR>(EGIDA_ALLOC_NON_PAGED(allocSize));
    if (!allocatedString) {
        EgidaLogError("Failed to allocate disk string memory (size: %zu)", allocSize);
        return EGIDA_INSUFFICIENT_RESOURCES;
    }

    RtlStringCbCopyA(allocatedString, allocSize, NewValue);

    TargetString->Buffer = allocatedString;
    TargetString->Length = static_cast<USHORT>(newValueLength);
    TargetString->MaximumLength = static_cast<USHORT>(allocSize);

    NTSTATUS status = TrackAllocatedDiskString(Context, allocatedString, allocSize, Extension, StringType);
    if (!NT_SUCCESS(status)) {
        EGIDA_FREE(allocatedString);
        TargetString->Buffer = nullptr;
        TargetString->Length = 0;
        TargetString->MaximumLength = 0;
        return status;
    }

    EgidaLogDebug("Allocated and set disk string (type %lu): %s", StringType, NewValue);
    return EGIDA_SUCCESS;
}

NTSTATUS DiskSpoofer::TrackAllocatedDiskString(
    _In_ PEGIDA_CONTEXT Context,
    _In_ PCHAR StringPointer,
    _In_ SIZE_T StringSize,
    _In_ PRAID_UNIT_EXTENSION Extension,
    _In_ ULONG StringType
) {
    ULONG newCount = Context->DiskAllocatedStringCount + 1;
    PDISK_ALLOCATED_STRING newArray = static_cast<PDISK_ALLOCATED_STRING>(
        EGIDA_ALLOC_NON_PAGED(newCount * sizeof(DISK_ALLOCATED_STRING))
        );

    if (!newArray) {
        return EGIDA_INSUFFICIENT_RESOURCES;
    }

    if (Context->DiskAllocatedStrings) {
        RtlCopyMemory(newArray, Context->DiskAllocatedStrings,
            Context->DiskAllocatedStringCount * sizeof(DISK_ALLOCATED_STRING));
        EGIDA_FREE(Context->DiskAllocatedStrings);
    }

    newArray[Context->DiskAllocatedStringCount].StringPointer = StringPointer;
    newArray[Context->DiskAllocatedStringCount].StringSize = StringSize;
    newArray[Context->DiskAllocatedStringCount].OwnerExtension = Extension;
    newArray[Context->DiskAllocatedStringCount].StringType = StringType;

    Context->DiskAllocatedStrings = newArray;
    Context->DiskAllocatedStringCount = newCount;

    return EGIDA_SUCCESS;
}

VOID DiskSpoofer::FreeDiskAllocatedStrings(
    _In_ PEGIDA_CONTEXT Context
) {
    if (!Context || !Context->DiskAllocatedStrings) {
        return;
    }

    EgidaLogDebug("Freeing %lu allocated disk strings", Context->DiskAllocatedStringCount);

    for (ULONG i = 0; i < Context->DiskAllocatedStringCount; i++) {
        if (Context->DiskAllocatedStrings[i].StringPointer) {
            EgidaLogDebug("Freeing disk string type %d (size: %zu)",
                Context->DiskAllocatedStrings[i].StringType,
                Context->DiskAllocatedStrings[i].StringSize);

            __try {
                PRAID_UNIT_EXTENSION ext = Context->DiskAllocatedStrings[i].OwnerExtension;
                if (ext && EgidaUtils::IsValidKernelPointer(ext)) {
                    if (Context->DiskAllocatedStrings[i].StringType == DISK_STRING_SERIAL) {
                        if (ext->_Identity.Identity.SerialNumber.Buffer == Context->DiskAllocatedStrings[i].StringPointer) {
                            ext->_Identity.Identity.SerialNumber.Buffer = nullptr;
                            ext->_Identity.Identity.SerialNumber.Length = 0;
                            ext->_Identity.Identity.SerialNumber.MaximumLength = 0;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                EgidaLogWarning("Exception while clearing disk string reference");
            }

            EGIDA_FREE(Context->DiskAllocatedStrings[i].StringPointer);
            Context->DiskAllocatedStrings[i].StringPointer = nullptr;
        }
    }

    EGIDA_FREE(Context->DiskAllocatedStrings);
    Context->DiskAllocatedStrings = nullptr;
    Context->DiskAllocatedStringCount = 0;

    EgidaLogDebug("Disk string cleanup completed");
}

NTSTATUS DiskSpoofer::DisableSmartOnAllDisks(
    _In_ PEGIDA_CONTEXT Context
) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Disabling SMART on all disks...");

    UNICODE_STRING driverDisk;
    RtlInitUnicodeString(&driverDisk, L"\\Driver\\Disk");

    PDRIVER_OBJECT driverObject = nullptr;
    NTSTATUS status = ObReferenceObjectByName(
        &driverDisk,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        nullptr,
        0,
        *IoDriverObjectType,
        KernelMode,
        nullptr,
        reinterpret_cast<PVOID*>(&driverObject)
    );

    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to get disk driver object: 0x%08X", status);
        return status;
    }

    PDEVICE_OBJECT deviceObjectList[64];
    RtlZeroMemory(deviceObjectList, sizeof(deviceObjectList));

    ULONG numberOfDeviceObjects = 0;
    status = IoEnumerateDeviceObjectList(
        driverObject,
        deviceObjectList,
        sizeof(deviceObjectList),
        &numberOfDeviceObjects
    );

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(driverObject);
        EgidaLogError("Failed to enumerate disk devices: 0x%08X", status);
        return status;
    }

    EgidaLogDebug("Found %lu disk devices", numberOfDeviceObjects);

    for (ULONG i = 0; i < numberOfDeviceObjects; i++) {
        PDEVICE_OBJECT deviceObject = deviceObjectList[i];

        if (deviceObject && deviceObject->DeviceExtension) {
            __try {
                s_DiskEnableDisableFailurePrediction(deviceObject->DeviceExtension, FALSE);
                EgidaLogDebug("Disabled SMART on disk device %lu", i);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                EgidaLogWarning("Exception disabling SMART on disk device %lu", i);
            }
        }

        if (deviceObject) {
            ObDereferenceObject(deviceObject);
        }
    }

    ObDereferenceObject(driverObject);

    EgidaLogInfo("SMART disabled on all disks");
    return EGIDA_SUCCESS;
}

VOID DiskSpoofer::DisableSmartBit(
    _In_ PRAID_UNIT_EXTENSION Extension
) {
    if (!Extension) return;

    __try {
        Extension->_Smart.TelemetryExtension.Flags = 0;
        EgidaLogDebug("Disabled SMART bit for RAID extension");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogWarning("Exception while disabling SMART bit");
    }
}

NTSTATUS DiskSpoofer::StopSpoof(
    _In_ PEGIDA_CONTEXT Context
) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Stopping disk spoofing...");
    // Note: Disk serial changes are permanent until reboot
    return EGIDA_SUCCESS;
}

VOID DiskSpoofer::Cleanup(
    _In_ PEGIDA_CONTEXT Context
) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Cleaning up Disk Spoofer...");

    // Reset static members
    s_StorportBase = nullptr;
    s_DiskBase = nullptr;
    s_RaidUnitRegisterInterfaces = nullptr;
    s_DiskEnableDisableFailurePrediction = nullptr;

    EgidaLogInfo("Disk Spoofer cleanup completed");
}