#include "DiskSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Utils/Randomizer.h"
#include "../Core/Logger.h"

extern "C" POBJECT_TYPE* IoDriverObjectType;

// Static members
PVOID DiskSpoofer::s_StorportBase = nullptr;
PVOID DiskSpoofer::s_DiskBase = nullptr;
RaidUnitRegisterInterfaces DiskSpoofer::s_RaidUnitRegisterInterfaces = nullptr;
DiskEnableDisableFailurePrediction DiskSpoofer::s_DiskEnableDisableFailurePrediction = nullptr;

NTSTATUS DiskSpoofer::Initialize(_In_ PEGIDA_CONTEXT Context) {
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

NTSTATUS DiskSpoofer::ExecuteSpoof(_In_ PEGIDA_CONTEXT Context) {
    if (!Context) {
        EgidaLogError("Invalid context");
        return EGIDA_FAILED;
    }

    if (!s_StorportBase || !s_DiskBase || !s_RaidUnitRegisterInterfaces || !s_DiskEnableDisableFailurePrediction) {
        EgidaLogError("Disk Spoofer not properly initialized");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Executing disk spoofing...");

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

NTSTATUS DiskSpoofer::ChangeDiskSerials(_In_ PEGIDA_CONTEXT Context) {
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

PDEVICE_OBJECT DiskSpoofer::GetRaidDevice(_In_ PCWSTR DeviceName) {
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

NTSTATUS DiskSpoofer::ProcessRaidDevices(_In_ PDEVICE_OBJECT DeviceArray, _In_ PEGIDA_CONTEXT Context) {
    NTSTATUS status = EGIDA_NOT_FOUND;

    PDEVICE_OBJECT currentDevice = DeviceArray;

    __try {
        while (currentDevice && currentDevice->NextDevice) {
            if (currentDevice->DeviceType == FILE_DEVICE_DISK) {
                PRAID_UNIT_EXTENSION extension = static_cast<PRAID_UNIT_EXTENSION>(currentDevice->DeviceExtension);

                if (extension && EgidaUtils::IsValidKernelPointer(extension)) {
                    // Get current serial
                    ULONG serialLength = extension->_Identity.Identity.SerialNumber.Length;
                    if (serialLength > 0 && serialLength < EGIDA_MAX_SERIAL_LENGTH) {

                        CHAR originalSerial[EGIDA_MAX_SERIAL_LENGTH];
                        RtlZeroMemory(originalSerial, sizeof(originalSerial));

                        if (extension->_Identity.Identity.SerialNumber.Buffer) {
                            RtlCopyMemory(originalSerial, extension->_Identity.Identity.SerialNumber.Buffer, serialLength);
                            originalSerial[serialLength] = '\0';

                            EgidaLogDebug("Original disk serial: %s", originalSerial);

                            // Generate new serial
                            PCHAR newSerial = static_cast<PCHAR>(EGIDA_ALLOC_NON_PAGED(serialLength + 1));
                            if (newSerial) {
                                EgidaRandomizer::GenerateRandomSerial(newSerial, serialLength);
                                newSerial[serialLength] = '\0';

                                // Update the serial
                                RtlInitString(&extension->_Identity.Identity.SerialNumber, newSerial);

                                EgidaLogInfo("Changed disk serial from %s to %s", originalSerial, newSerial);

                                // Disable SMART for this device
                                DisableSmartBit(extension);

                                // Register interfaces to update registry
                                if (s_RaidUnitRegisterInterfaces) {
                                    s_RaidUnitRegisterInterfaces(extension);
                                }

                                status = EGIDA_SUCCESS;

                                // Don't free newSerial as it's now owned by the system
                            }
                        }
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

NTSTATUS DiskSpoofer::DisableSmartOnAllDisks(_In_ PEGIDA_CONTEXT Context) {
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

VOID DiskSpoofer::DisableSmartBit(_In_ PRAID_UNIT_EXTENSION Extension) {
    if (!Extension) return;

    __try {
        Extension->_Smart.TelemetryExtension.Flags = 0;
        EgidaLogDebug("Disabled SMART bit for RAID extension");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogWarning("Exception while disabling SMART bit");
    }
}

NTSTATUS DiskSpoofer::StopSpoof(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Stopping disk spoofing...");
    // Note: Disk serial changes are permanent until reboot
    return EGIDA_SUCCESS;
}

VOID DiskSpoofer::Cleanup(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Cleaning up Disk Spoofer...");

    // Reset static members
    s_StorportBase = nullptr;
    s_DiskBase = nullptr;
    s_RaidUnitRegisterInterfaces = nullptr;
    s_DiskEnableDisableFailurePrediction = nullptr;

    EgidaLogInfo("Disk Spoofer cleanup completed");
}