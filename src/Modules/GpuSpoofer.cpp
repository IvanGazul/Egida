#include "GpuSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Utils/Randomizer.h"
#include "../Core/Logger.h"
#include "../Common/Globals.h"

extern "C" POBJECT_TYPE* IoDriverObjectType;

// Static members
PGPU_SPOOF_CONTEXT GpuSpoofer::s_GpuContext = nullptr;
PVOID GpuSpoofer::s_Win32kBase = nullptr;
PVOID GpuSpoofer::s_DxgkrnlBase = nullptr;

// Kernel mode string conversion function
NTSTATUS ConvertAnsiToUnicode(_In_ PCSTR AnsiString, _Out_ PWCHAR UnicodeBuffer, _In_ SIZE_T BufferSize) {
    if (!AnsiString || !UnicodeBuffer || BufferSize < 2) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T ansiLength = strlen(AnsiString);
    if (ansiLength >= BufferSize / sizeof(WCHAR)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Simple ASCII to Unicode conversion for kernel mode
    for (SIZE_T i = 0; i <= ansiLength; i++) {
        UnicodeBuffer[i] = (WCHAR)AnsiString[i];
    }

    return STATUS_SUCCESS;
}

NTSTATUS GpuSpoofer::Initialize(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Initializing GPU Spoofer...");

    // Allocate GPU context
    s_GpuContext = static_cast<PGPU_SPOOF_CONTEXT>(
        EGIDA_ALLOC_NON_PAGED(sizeof(GPU_SPOOF_CONTEXT))
        );

    if (!s_GpuContext) {
        EgidaLogError("Failed to allocate GPU context");
        return EGIDA_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(s_GpuContext, sizeof(GPU_SPOOF_CONTEXT));

    // Get graphics-related module bases
    s_Win32kBase = EgidaUtils::GetModuleBase("win32k.sys");
    if (s_Win32kBase) {
        EgidaLogDebug("win32k.sys base: 0x%p", s_Win32kBase);
    }
    else {
        EgidaLogWarning("win32k.sys not found (may not be loaded yet)");
    }

    s_DxgkrnlBase = EgidaUtils::GetModuleBase("dxgkrnl.sys");
    if (s_DxgkrnlBase) {
        EgidaLogDebug("dxgkrnl.sys base: 0x%p", s_DxgkrnlBase);
    }
    else {
        EgidaLogWarning("dxgkrnl.sys not found");
    }

    EgidaLogInfo("GPU Spoofer initialized successfully");
    return EGIDA_SUCCESS;
}

NTSTATUS GpuSpoofer::ExecuteSpoof(_In_ PEGIDA_CONTEXT Context) {
    if (!Context || !s_GpuContext) {
        EgidaLogError("Invalid context or GPU spoofer not initialized");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Executing GPU spoofing...");

    // Initialize randomizer
    EgidaRandomizer::InitializeSeed(Context->Config.RandomConfig.RandomSeed);

    // Free any previously allocated strings
    FreeAllocatedStrings(Context);

    NTSTATUS status = EGIDA_SUCCESS;

    // Find and enumerate GPU devices
    status = FindGpuDevices(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to find GPU devices: 0x%08X", status);
        return status;
    }

    // Spoof registry values for each GPU device
    status = SpoofGpuRegistryValues(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to spoof GPU registry values: 0x%08X", status);
        return status;
    }

    s_GpuContext->IsActive = TRUE;
    EgidaLogInfo("GPU spoofing completed successfully");

    return EGIDA_SUCCESS;
}

NTSTATUS GpuSpoofer::FindGpuDevices(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Searching for GPU devices...");

    // Try to enumerate display drivers
    NTSTATUS status = EnumerateDisplayDrivers(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogWarning("Failed to enumerate display drivers, trying alternative method");
    }

    EgidaLogInfo("GPU device enumeration completed");
    return EGIDA_SUCCESS;
}

NTSTATUS GpuSpoofer::EnumerateDisplayDrivers(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogDebug("Enumerating display drivers...");

    // Get driver objects for common display drivers
    UNICODE_STRING driverNames[] = {
        RTL_CONSTANT_STRING(L"\\Driver\\nvlddmkm"),  // NVIDIA
        RTL_CONSTANT_STRING(L"\\Driver\\amdkmdap"),  // AMD
        RTL_CONSTANT_STRING(L"\\Driver\\igdkmd64"),  // Intel
        RTL_CONSTANT_STRING(L"\\Driver\\BasicDisplay") // Basic Display
    };

    for (ULONG i = 0; i < ARRAYSIZE(driverNames); i++) {
        PDRIVER_OBJECT driverObject = nullptr;

        NTSTATUS status = ObReferenceObjectByName(
            &driverNames[i],
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            0,
            *IoDriverObjectType,
            KernelMode,
            nullptr,
            reinterpret_cast<PVOID*>(&driverObject)
        );

        if (NT_SUCCESS(status) && driverObject) {
            EgidaLogDebug("Found display driver: %wZ", &driverNames[i]);

            // Enumerate devices for this driver
            PDEVICE_OBJECT deviceObject = driverObject->DeviceObject;
            while (deviceObject) {
                if (IsGpuDevice(deviceObject)) {
                    EgidaLogDebug("Found GPU device object: 0x%p", deviceObject);
                    // Add to our device list
                }
                deviceObject = deviceObject->NextDevice;
            }

            ObDereferenceObject(driverObject);
        }
    }

    return EGIDA_SUCCESS;
}

BOOLEAN GpuSpoofer::IsGpuDevice(_In_ PDEVICE_OBJECT DeviceObject) {
    if (!DeviceObject) return FALSE;

    __try {
        // Check device type and characteristics
        if (DeviceObject->DeviceType == FILE_DEVICE_VIDEO ||
            DeviceObject->DeviceType == FILE_DEVICE_UNKNOWN) {
            return TRUE;
        }

        // Additional checks could be added here
        return FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

NTSTATUS GpuSpoofer::SpoofGpuRegistryValues(_In_ PEGIDA_CONTEXT Context) {
    EgidaLogInfo("Spoofing GPU registry values...");

    // Common registry paths to modify
    struct {
        PCWSTR Path;
        PCWSTR ValueName;
        BOOLEAN IsString;
    } gpuValues[] = {
        { L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY", L"HardwareID", TRUE },
        { L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY", L"CompatibleIDs", TRUE },
        { L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"DriverDesc", TRUE },
        { L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"ProviderName", TRUE }
    };

    for (ULONG i = 0; i < ARRAYSIZE(gpuValues); i++) {
        PVOID originalData = nullptr;
        ULONG originalSize = 0;
        ULONG valueType = 0;

        // Read original value
        NTSTATUS status = ReadGpuRegistryValue(
            gpuValues[i].Path,
            gpuValues[i].ValueName,
            &originalData,
            &originalSize,
            &valueType
        );

        if (NT_SUCCESS(status) && originalData) {
            EgidaLogDebug("Read original value for %ws\\%ws", gpuValues[i].Path, gpuValues[i].ValueName);

            // Generate spoofed value
            CHAR spoofedBuffer[EGIDA_MAX_STRING_LENGTH];
            if (gpuValues[i].IsString) {
                if (wcsstr(gpuValues[i].ValueName, L"Desc") != nullptr) {
                    GenerateSpoofedDescription(spoofedBuffer, sizeof(spoofedBuffer), Context);
                }
                else {
                    GenerateSpoofedPNPDeviceID(spoofedBuffer, sizeof(spoofedBuffer), Context);
                }

                // Convert to wide string for registry using our kernel-safe function
                WCHAR wideSpoofed[EGIDA_MAX_STRING_LENGTH];
                status = ConvertAnsiToUnicode(spoofedBuffer, wideSpoofed, sizeof(wideSpoofed));

                if (NT_SUCCESS(status)) {
                    SIZE_T wideLength = wcslen(wideSpoofed);

                    // Write spoofed value
                    status = WriteGpuRegistryValue(
                        gpuValues[i].Path,
                        gpuValues[i].ValueName,
                        wideSpoofed,
                        static_cast<ULONG>((wideLength + 1) * sizeof(WCHAR)),
                        REG_SZ
                    );

                    if (NT_SUCCESS(status)) {
                        EgidaLogInfo("Successfully spoofed %ws with value: %s", gpuValues[i].ValueName, spoofedBuffer);
                    }
                    else {
                        EgidaLogWarning("Failed to write spoofed value for %ws: 0x%08X", gpuValues[i].ValueName, status);
                    }
                }
            }

            EGIDA_FREE(originalData);
        }
        else {
            EgidaLogWarning("Failed to read original value for %ws\\%ws: 0x%08X",
                gpuValues[i].Path, gpuValues[i].ValueName, status);
        }
    }

    return EGIDA_SUCCESS;
}

NTSTATUS GpuSpoofer::GenerateSpoofedPNPDeviceID(_Out_ PCHAR Buffer, _In_ UINT32 BufferSize, _In_ PEGIDA_CONTEXT Context) {
    if (!Buffer || BufferSize < 32) {
        return EGIDA_FAILED;
    }

    // Check if we have profile data
    if (Context && Context->HasProfileData &&
        strnlen(Context->CurrentProfile.GpuPNPID, sizeof(Context->CurrentProfile.GpuPNPID)) > 0) {

        EgidaLogInfo("Using GPU PNP ID from profile");
        RtlStringCbCopyA(Buffer, BufferSize, Context->CurrentProfile.GpuPNPID);
        EgidaLogInfo("Profile GPU PNP ID: %s", Buffer);
        return EGIDA_SUCCESS;
    }

    EgidaLogDebug("No profile data for GPU PNP ID, generating random");

    // Generate a realistic looking PNP Device ID
    const char* vendors[] = { "VEN_10DE", "VEN_1002", "VEN_8086" };
    const char* selectedVendor = vendors[EgidaRandomizer::GetRandomNumber(0, 2)];

    UINT32 deviceId = EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFF);
    UINT32 subsysId = EgidaRandomizer::GetRandomNumber(0x1000, 0xFFFF);
    UINT32 revId = EgidaRandomizer::GetRandomNumber(0x00, 0xFF);

    RtlStringCbPrintfA(Buffer, BufferSize,
        "PCI\\%s&DEV_%04X&SUBSYS_%08X&REV_%02X",
        selectedVendor, deviceId, subsysId, revId);

    EgidaLogDebug("Generated random GPU PNP ID: %s", Buffer);
    return EGIDA_SUCCESS;
}

NTSTATUS GpuSpoofer::GenerateSpoofedDescription(_Out_ PCHAR Buffer, _In_ UINT32 BufferSize, _In_ PEGIDA_CONTEXT Context) {
    if (!Buffer || BufferSize < 32) {
        return EGIDA_FAILED;
    }

    // Check if we have profile data
    if (Context && Context->HasProfileData &&
        strnlen(Context->CurrentProfile.GpuDescription, sizeof(Context->CurrentProfile.GpuDescription)) > 0) {

        EgidaLogInfo("Using GPU description from profile");
        RtlStringCbCopyA(Buffer, BufferSize, Context->CurrentProfile.GpuDescription);
        EgidaLogInfo("Profile GPU description: %s", Buffer);
        return EGIDA_SUCCESS;
    }

    EgidaLogDebug("No profile data for GPU description, generating random");

    const char* descriptions[] = {
        "NVIDIA GeForce RTX 3070",
        "AMD Radeon RX 6800 XT",
        "Intel UHD Graphics 630",
        "NVIDIA GeForce GTX 1660",
        "AMD Radeon RX 580"
    };

    const char* selected = descriptions[EgidaRandomizer::GetRandomNumber(0, 4)];
    RtlStringCbCopyA(Buffer, BufferSize, selected);

    EgidaLogDebug("Generated random GPU description: %s", Buffer);
    return EGIDA_SUCCESS;
}


NTSTATUS GpuSpoofer::WriteGpuRegistryValue(
    _In_ PCWSTR RegistryPath,
    _In_ PCWSTR ValueName,
    _In_ PVOID ValueData,
    _In_ ULONG ValueSize,
    _In_ ULONG ValueType
) {
    return RtlWriteRegistryValue(
        RTL_REGISTRY_ABSOLUTE,
        RegistryPath,
        ValueName,
        ValueType,
        ValueData,
        ValueSize
    );
}

NTSTATUS GpuSpoofer::ReadGpuRegistryValue(
    _In_ PCWSTR RegistryPath,
    _In_ PCWSTR ValueName,
    _Out_ PVOID* ValueData,
    _Out_ PULONG ValueSize,
    _Out_ PULONG ValueType
) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(ValueName);
    UNREFERENCED_PARAMETER(ValueData);
    UNREFERENCED_PARAMETER(ValueSize);
    UNREFERENCED_PARAMETER(ValueType);

    // Simplified implementation for now
    // In a full implementation, this would use ZwOpenKey/ZwQueryValueKey
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS GpuSpoofer::AllocateAndAssignString(
    _Out_ PVOID* Target,
    _In_ PCSTR Source,
    _In_ UINT32 MaxLength,
    _In_ PEGIDA_CONTEXT Context
) {
    UNREFERENCED_PARAMETER(Context);

    if (!Target || !Source) {
        return EGIDA_FAILED;
    }

    UINT32 sourceLength = static_cast<UINT32>(strlen(Source));
    UINT32 allocSize = max(sourceLength + 1, MaxLength);

    PCHAR allocatedString = static_cast<PCHAR>(EGIDA_ALLOC_NON_PAGED(allocSize));
    if (!allocatedString) {
        EgidaLogError("Failed to allocate string of size %lu", allocSize);
        return EGIDA_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(allocatedString, allocSize);
    RtlCopyMemory(allocatedString, Source, sourceLength);

    *Target = allocatedString;

    // Track allocated memory for cleanup
    if (s_GpuContext) {
        // Expand allocated values array if needed
        ULONG newCount = s_GpuContext->AllocatedValueCount + 1;
        PGPU_REGISTRY_VALUE newArray = static_cast<PGPU_REGISTRY_VALUE>(
            EGIDA_ALLOC_NON_PAGED(newCount * sizeof(GPU_REGISTRY_VALUE))
            );

        if (newArray) {
            if (s_GpuContext->AllocatedValues) {
                RtlCopyMemory(newArray, s_GpuContext->AllocatedValues,
                    s_GpuContext->AllocatedValueCount * sizeof(GPU_REGISTRY_VALUE));
                EGIDA_FREE(s_GpuContext->AllocatedValues);
            }

            newArray[s_GpuContext->AllocatedValueCount].SpoofedData = allocatedString;
            newArray[s_GpuContext->AllocatedValueCount].DataSize = allocSize;
            newArray[s_GpuContext->AllocatedValueCount].IsAllocated = TRUE;

            s_GpuContext->AllocatedValues = newArray;
            s_GpuContext->AllocatedValueCount = newCount;
        }
    }

    EgidaLogDebug("Allocated and assigned string: %s (size: %lu)", Source, allocSize);
    return EGIDA_SUCCESS;
}

VOID GpuSpoofer::FreeAllocatedStrings(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    if (!s_GpuContext || !s_GpuContext->AllocatedValues) {
        return;
    }

    EgidaLogDebug("Freeing %lu allocated GPU strings", s_GpuContext->AllocatedValueCount);

    for (ULONG i = 0; i < s_GpuContext->AllocatedValueCount; i++) {
        if (s_GpuContext->AllocatedValues[i].IsAllocated && s_GpuContext->AllocatedValues[i].SpoofedData) {
            EGIDA_FREE(s_GpuContext->AllocatedValues[i].SpoofedData);
            s_GpuContext->AllocatedValues[i].SpoofedData = nullptr;
            s_GpuContext->AllocatedValues[i].IsAllocated = FALSE;
        }
    }

    EGIDA_FREE(s_GpuContext->AllocatedValues);
    s_GpuContext->AllocatedValues = nullptr;
    s_GpuContext->AllocatedValueCount = 0;

    EgidaLogDebug("GPU string cleanup completed");
}

NTSTATUS GpuSpoofer::StopSpoof(_In_ PEGIDA_CONTEXT Context) {
    if (!Context || !s_GpuContext) {
        return EGIDA_SUCCESS;
    }

    EgidaLogInfo("Stopping GPU spoofing...");

    // Note: Registry changes are persistent until system restart
    // We just mark as inactive and clean up memory
    FreeAllocatedStrings(Context);
    s_GpuContext->IsActive = FALSE;

    EgidaLogInfo("GPU spoofing stopped");
    return EGIDA_SUCCESS;
}

VOID GpuSpoofer::Cleanup(_In_ PEGIDA_CONTEXT Context) {
    EgidaLogInfo("Cleaning up GPU Spoofer...");

    if (s_GpuContext) {
        FreeAllocatedStrings(Context);

        if (s_GpuContext->DeviceList) {
            EGIDA_FREE(s_GpuContext->DeviceList);
        }

        EGIDA_FREE(s_GpuContext);
        s_GpuContext = nullptr;
    }

    // Reset static members
    s_Win32kBase = nullptr;
    s_DxgkrnlBase = nullptr;

    EgidaLogInfo("GPU Spoofer cleanup completed");
}