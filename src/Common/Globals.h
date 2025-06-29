#pragma once
#include "Definitions.h"
#include "Structures.h"

// Forward declarations
extern "C" {
    // Global driver context
    extern PEGIDA_CONTEXT g_EgidaGlobalContext;

    // Driver entry points
    NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
    VOID EgidaUnloadDriver(_In_ PDRIVER_OBJECT DriverObject);
    NTSTATUS EgidaCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
    NTSTATUS EgidaDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
}