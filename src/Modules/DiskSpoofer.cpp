#include "DiskSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Core/Logger.h"

// Предполагается, что EGIDA_ALLOC_NON_PAGED определён где-то в твоих общих файлах
#ifndef EGIDA_ALLOC_NON_PAGED
#define EGIDA_ALLOC_NON_PAGED(Size) ExAllocatePoolWithTag(NonPagedPool, Size, 'egiD')
#endif

extern "C" POBJECT_TYPE* IoDriverObjectType;

// Static members
PVOID DiskSpoofer::s_StorportBase = nullptr;
PVOID DiskSpoofer::s_DiskBase = nullptr;
RaidUnitRegisterInterfaces DiskSpoofer::s_RaidUnitRegisterInterfaces = nullptr;
DiskEnableDisableFailurePrediction DiskSpoofer::s_DiskEnableDisableFailurePrediction = nullptr;

NTSTATUS DiskSpoofer::Initialize(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);
    EgidaLogInfo("Initializing Disk Spoofer...");

    s_StorportBase = EgidaUtils::GetModuleBase("storport.sys");
    if (!s_StorportBase) {
        EgidaLogError("Failed to find storport.sys");
        return EGIDA_FAILED;
    }
    s_DiskBase = EgidaUtils::GetModuleBase("disk.sys");
    if (!s_DiskBase) {
        EgidaLogError("Failed to find disk.sys");
        return EGIDA_FAILED;
    }

    PVOID raidRegisterPtr = EgidaUtils::FindPatternInModule(
        s_StorportBase, "\x48\x89\x5c\x24\x00\x55\x56\x57\x48\x83\xec\x00\x8b\x41\x00\x4c\x8d", "xxxx?xxxxxx?xx?xx");
    if (!raidRegisterPtr) {
        EgidaLogError("Failed to find RaidUnitRegisterInterfaces");
        return EGIDA_FAILED;
    }
    s_RaidUnitRegisterInterfaces = reinterpret_cast<RaidUnitRegisterInterfaces>(raidRegisterPtr);

    PVOID diskFailurePtr = EgidaUtils::FindPatternInModule(
        s_DiskBase, "\x4c\x8b\xdc\x49\x89\x5b\x00\x49\x89\x7b\x00\x55\x49\x8d\x6b\xa1\x48\x81\xec", "xxxxxx?xxx?xxxxxxxx");
    if (!diskFailurePtr) {
        EgidaLogError("Failed to find DiskEnableDisableFailurePrediction");
        return EGIDA_FAILED;
    }
    s_DiskEnableDisableFailurePrediction = reinterpret_cast<DiskEnableDisableFailurePrediction>(diskFailurePtr);

    EgidaLogInfo("Disk Spoofer initialized successfully");
    return EGIDA_SUCCESS;
}

NTSTATUS DiskSpoofer::ExecuteSpoof(_In_ PEGIDA_CONTEXT Context) {
    if (!Context) return EGIDA_FAILED;

    // Проверяем, что есть данные профиля
    if (!Context->ProfileData) {
        EgidaLogError("No profile data available for disk spoofing");
        return EGIDA_FAILED;
    }

    if (!s_RaidUnitRegisterInterfaces || !s_DiskEnableDisableFailurePrediction) {
        EgidaLogError("Disk Spoofer not properly initialized");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Executing disk spoofing...");

    NTSTATUS status = DisableSmartOnAllDisks(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to disable SMART: 0x%08X", status);
    }

    status = ChangeDiskSerials(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to change disk serials: 0x%08X", status);
        return status;
    }

    EgidaLogInfo("Disk spoofing completed successfully");
    return EGIDA_SUCCESS;
}

NTSTATUS DiskSpoofer::ChangeDiskSerials(_In_ PEGIDA_CONTEXT Context) {
    bool bSpoofed = false; // Флаг, чтобы спуфить только один раз
    NTSTATUS overallStatus = EGIDA_NOT_FOUND;

    // Ищем на первых 4 портах
    for (INT32 i = 0; i < 4 && !bSpoofed; i++) {
        WCHAR raidDeviceName[32];
        swprintf(raidDeviceName, L"\\Device\\RaidPort%d", i);

        PDEVICE_OBJECT raidDevice = GetRaidDevice(raidDeviceName);
        if (raidDevice) {
            EgidaLogDebug("Found RAID device: %ws", raidDeviceName);
            NTSTATUS status = ProcessRaidDevices(raidDevice, Context, &bSpoofed);
            if (NT_SUCCESS(status)) {
                overallStatus = status;
            }
        }
    }

    if (NT_SUCCESS(overallStatus)) {
        EgidaLogInfo("Disk serial changed successfully");
    }
    else {
        EgidaLogWarning("No disk serials were changed. Check profile or RAID devices.");
    }

    return overallStatus;
}

PDEVICE_OBJECT DiskSpoofer::GetRaidDevice(_In_ PCWSTR DeviceName) {
    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, DeviceName);

    PFILE_OBJECT fileObject = nullptr;
    PDEVICE_OBJECT deviceObject = nullptr;

    if (NT_SUCCESS(IoGetDeviceObjectPointer(&deviceName, FILE_READ_DATA, &fileObject, &deviceObject))) {
        PDEVICE_OBJECT targetDevice = deviceObject->DriverObject->DeviceObject;
        if (fileObject) {
            ObDereferenceObject(fileObject);
        }
        return targetDevice;
    }
    return nullptr;
}

NTSTATUS DiskSpoofer::ProcessRaidDevices(_In_ PDEVICE_OBJECT DeviceArray, _In_ PEGIDA_CONTEXT Context, _Inout_ bool* bSpoofed) {
    // Проверяем, что в профиле есть серийный номер для диска
    if (strnlen_s(Context->ProfileData->DiskSerials[0], EGIDA_MAX_SERIAL_LENGTH) == 0) {
        EgidaLogWarning("Disk serial in profile[0] is empty. Skipping.");
        return EGIDA_NOT_FOUND;
    }

    PDEVICE_OBJECT currentDevice = DeviceArray;
    __try {
        while (currentDevice && !*bSpoofed) {
            if (currentDevice->DeviceType == FILE_DEVICE_DISK) {
                PRAID_UNIT_EXTENSION extension = static_cast<PRAID_UNIT_EXTENSION>(currentDevice->DeviceExtension);

                if (extension && EgidaUtils::IsValidKernelPointer(extension)) {
                    PCSTR profileSerial = Context->ProfileData->DiskSerials[0];
                    SIZE_T profileSerialLen = strlen(profileSerial);

                    //ПАМЯТЬ НЕ ОСВОБОЖДАЕТСЯ!!!!!!
                    PCHAR newSerialBuffer = static_cast<PCHAR>(EGIDA_ALLOC_NON_PAGED(profileSerialLen + 1));
                    if (newSerialBuffer) {
                        RtlCopyMemory(newSerialBuffer, profileSerial, profileSerialLen);
                        newSerialBuffer[profileSerialLen] = '\0';

                        // Обновляем структуру
                        RtlInitAnsiString(&extension->_Identity.Identity.SerialNumber, newSerialBuffer);

                        EgidaLogInfo("Spoofed disk serial to: %s", profileSerial);

                        DisableSmartBit(extension);

                        if (s_RaidUnitRegisterInterfaces) {
                            s_RaidUnitRegisterInterfaces(extension);
                        }

                        *bSpoofed = true; // Устанавливаем флаг, чтобы выйти из всех циклов
                        return EGIDA_SUCCESS;
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
    return EGIDA_NOT_FOUND;
}

NTSTATUS DiskSpoofer::DisableSmartOnAllDisks(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);
    UNICODE_STRING driverDisk;
    RtlInitUnicodeString(&driverDisk, L"\\Driver\\Disk");
    PDRIVER_OBJECT driverObject = nullptr;
    NTSTATUS status = ObReferenceObjectByName(&driverDisk, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, reinterpret_cast<PVOID*>(&driverObject));
    if (!NT_SUCCESS(status)) return status;

    ULONG count = 0;
    IoEnumerateDeviceObjectList(driverObject, nullptr, 0, &count);

    ULONG size = sizeof(PDEVICE_OBJECT) * count;
    PDEVICE_OBJECT* deviceList = static_cast<PDEVICE_OBJECT*>(ExAllocatePoolWithTag(PagedPool, size, 'egiD'));
    if (!deviceList) {
        ObDereferenceObject(driverObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoEnumerateDeviceObjectList(driverObject, deviceList, size, &count);
    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < count; i++) {
            if (deviceList[i] && deviceList[i]->DeviceExtension) {
                __try {
                    s_DiskEnableDisableFailurePrediction(deviceList[i]->DeviceExtension, FALSE);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
            ObDereferenceObject(deviceList[i]);
        }
    }
    ExFreePoolWithTag(deviceList, 'egiD');
    ObDereferenceObject(driverObject);
    return EGIDA_SUCCESS;
}

VOID DiskSpoofer::DisableSmartBit(_In_ PRAID_UNIT_EXTENSION Extension) {
    if (!Extension) return;
    __try {
        Extension->_Smart.TelemetryExtension.Flags = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogWarning("Exception while disabling SMART bit");
    }
}

NTSTATUS DiskSpoofer::StopSpoof(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);
    EgidaLogInfo("Disk spoofing changes are persistent until reboot.");
    return EGIDA_SUCCESS;
}

VOID DiskSpoofer::Cleanup(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);
    EgidaLogInfo("Cleaning up Disk Spoofer...");
    s_StorportBase = nullptr;
    s_DiskBase = nullptr;
    s_RaidUnitRegisterInterfaces = nullptr;
    s_DiskEnableDisableFailurePrediction = nullptr;
}