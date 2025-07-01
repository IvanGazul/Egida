#pragma once
#include "../Common/Structures.h"

class GpuSpoofer {
public:
    static NTSTATUS Initialize(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ExecuteSpoof(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS StopSpoof(_In_ PEGIDA_CONTEXT Context);
    static VOID Cleanup(_In_ PEGIDA_CONTEXT Context);

private:
    static NTSTATUS FindGpuDevices(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS SpoofGpuRegistryValues(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS SpoofSingleGpuDevice(_In_ PGPU_DEVICE_INFO DeviceInfo, _In_ PEGIDA_CONTEXT Context);

    // Registry manipulation functions
    static NTSTATUS WriteGpuRegistryValue(
        _In_ PCWSTR RegistryPath,
        _In_ PCWSTR ValueName,
        _In_ PVOID ValueData,
        _In_ ULONG ValueSize,
        _In_ ULONG ValueType
    );

    static NTSTATUS ReadGpuRegistryValue(
        _In_ PCWSTR RegistryPath,
        _In_ PCWSTR ValueName,
        _Out_ PVOID* ValueData,
        _Out_ PULONG ValueSize,
        _Out_ PULONG ValueType
    );

    // Memory management for allocated strings
    static NTSTATUS AllocateAndAssignString(
        _Out_ PVOID* Target,
        _In_ PCSTR Source,
        _In_ UINT32 MaxLength,
        _In_ PEGIDA_CONTEXT Context
    );

    static VOID FreeAllocatedStrings(_In_ PEGIDA_CONTEXT Context);

    // GPU identification utilities
    static NTSTATUS GenerateSpoofedPNPDeviceID(_Out_ PCHAR Buffer, _In_ UINT32 BufferSize, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS GenerateSpoofedDescription(_Out_ PCHAR Buffer, _In_ UINT32 BufferSize, _In_ PEGIDA_CONTEXT Context);

    // Driver and device enumeration
    static NTSTATUS EnumerateDisplayDrivers(_In_ PEGIDA_CONTEXT Context);
    static BOOLEAN IsGpuDevice(_In_ PDEVICE_OBJECT DeviceObject);

    // Module state
    static PGPU_SPOOF_CONTEXT s_GpuContext;
    static PVOID s_Win32kBase;
    static PVOID s_DxgkrnlBase;
};

// Common GPU vendor IDs and device patterns
#define GPU_VENDOR_NVIDIA   "VEN_10DE"
#define GPU_VENDOR_AMD      "VEN_1002"
#define GPU_VENDOR_INTEL    "VEN_8086"

// Registry paths for GPU information
#define GPU_REGISTRY_PATH   L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI"
#define GPU_CLASS_PATH      L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}"