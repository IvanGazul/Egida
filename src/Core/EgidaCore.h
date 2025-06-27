#pragma once
#include "../Common/Structures.h"
#include "Logger.h"

// Core module interface
class EgidaCore {
public:
    static NTSTATUS Initialize(_Out_ PEGIDA_CONTEXT* Context);
    static NTSTATUS Cleanup(_In_ PEGIDA_CONTEXT Context);

    static NTSTATUS StartSpoofing(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS StopSpoofing(_In_ PEGIDA_CONTEXT Context);

    static NTSTATUS SetConfiguration(_In_ PEGIDA_CONTEXT Context, _In_ PSPOOF_CONFIGURATION Config);
    static NTSTATUS GetStatus(_In_ PEGIDA_CONTEXT Context, _Out_ PEGIDA_STATUS Status);

    // Device control
    static NTSTATUS HandleDeviceControl(
        _In_ PDEVICE_OBJECT DeviceObject,
        _In_ PIRP Irp
    );

private:
    static NTSTATUS CreateDeviceObject(_In_ PDRIVER_OBJECT DriverObject, _Out_ PEGIDA_CONTEXT* Context);
    static NTSTATUS InitializeModules(_In_ PEGIDA_CONTEXT Context);
    static VOID CleanupModules(_In_ PEGIDA_CONTEXT Context);

    static PEGIDA_CONTEXT g_EgidaContext;
};

// Global context access
extern PEGIDA_CONTEXT g_EgidaGlobalContext;

// Driver entry points
extern "C" {
    NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
    VOID EgidaUnloadDriver(_In_ PDRIVER_OBJECT DriverObject);

    NTSTATUS EgidaCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
    NTSTATUS EgidaDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
}