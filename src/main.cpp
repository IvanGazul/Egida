// main.cpp - Updated to work with user mode application
#include "Core/EgidaCore.h"
#include "Utils/EgidaUtils.h"
#include "Core/Logger.h"
#include "Common/Globals.h"

// Global context for IOCTL access - DEFINITION (not declaration)
PEGIDA_CONTEXT g_EgidaGlobalContext = nullptr;

extern "C" {

    NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
        UNREFERENCED_PARAMETER(RegistryPath);

        // Initialize logging
        EgidaLogInitialize();
        EgidaLogInfo("Egida Driver v%s loading...", EGIDA_VERSION);

        // Set driver routines
        DriverObject->DriverUnload = EgidaUnloadDriver;
        DriverObject->MajorFunction[IRP_MJ_CREATE] = EgidaCreateClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = EgidaCreateClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EgidaDeviceControl;

        // Create device
        PDEVICE_OBJECT deviceObject;
        UNICODE_STRING deviceName;
        RtlInitUnicodeString(&deviceName, DEVICE_NAME);

        NTSTATUS status = IoCreateDevice(
            DriverObject,
            0, // No device extension needed, we use global context
            &deviceName,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,
            &deviceObject
        );

        if (!NT_SUCCESS(status)) {
            EgidaLogError("Failed to create device: 0x%08X", status);
            EgidaLogCleanup();
            return status;
        }

        // Create symbolic link
        UNICODE_STRING symbolicLink;
        RtlInitUnicodeString(&symbolicLink, SYMBOLIC_LINK);

        status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
        if (!NT_SUCCESS(status)) {
            EgidaLogError("Failed to create symbolic link: 0x%08X", status);
            IoDeleteDevice(deviceObject);
            EgidaLogCleanup();
            return status;
        }

        // Set device flags for proper access
        deviceObject->Flags |= DO_BUFFERED_IO;
        deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

        // Initialize core
        status = EgidaCore::Initialize(&g_EgidaGlobalContext);
        if (!NT_SUCCESS(status)) {
            EgidaLogError("Failed to initialize core: 0x%08X", status);
            IoDeleteSymbolicLink(&symbolicLink);
            IoDeleteDevice(deviceObject);
            EgidaLogCleanup();
            return status;
        }

        // Store device info in context
        g_EgidaGlobalContext->DeviceObject = deviceObject;
        RtlInitUnicodeString(&g_EgidaGlobalContext->DeviceName, DEVICE_NAME);
        RtlInitUnicodeString(&g_EgidaGlobalContext->SymbolicLink, SYMBOLIC_LINK);

        EgidaLogInfo("Egida Driver loaded successfully");
        EgidaLogInfo("Device: %ws", DEVICE_NAME);
        EgidaLogInfo("Symbolic Link: %ws", SYMBOLIC_LINK);

        return STATUS_SUCCESS;
    }

    VOID EgidaUnloadDriver(_In_ PDRIVER_OBJECT DriverObject) {
        UNREFERENCED_PARAMETER(DriverObject);

        EgidaLogInfo("Unloading Egida Driver...");

        if (g_EgidaGlobalContext) {
            // Delete symbolic link first
            UNICODE_STRING symbolicLink;
            RtlInitUnicodeString(&symbolicLink, SYMBOLIC_LINK);
            IoDeleteSymbolicLink(&symbolicLink);

            // Delete device
            if (g_EgidaGlobalContext->DeviceObject) {
                IoDeleteDevice(g_EgidaGlobalContext->DeviceObject);
            }

            // Cleanup core
            EgidaCore::Cleanup(g_EgidaGlobalContext);
            g_EgidaGlobalContext = nullptr;
        }

        EgidaLogInfo("Egida Driver unloaded successfully");
        EgidaLogCleanup();
    }

    NTSTATUS EgidaCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
        UNREFERENCED_PARAMETER(DeviceObject);

        PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

        if (irpSp->MajorFunction == IRP_MJ_CREATE) {
            EgidaLogDebug("Device opened by process");
        }
        else if (irpSp->MajorFunction == IRP_MJ_CLOSE) {
            EgidaLogDebug("Device closed by process");
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }

    NTSTATUS EgidaDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
        return EgidaCore::HandleDeviceControl(DeviceObject, Irp);
    }

} // extern "C"