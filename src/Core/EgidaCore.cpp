#include "EgidaCore.h"
#include "../Modules/SmbiosSpoofer.h"
#include "../Modules/DiskSpoofer.h"
#include "../Modules/NetworkSpoofer.h"
#include "../Utils/EgidaUtils.h"

// Global context
PEGIDA_CONTEXT g_EgidaGlobalContext = nullptr;
PEGIDA_CONTEXT EgidaCore::g_EgidaContext = nullptr;

NTSTATUS EgidaCore::Initialize(_Out_ PEGIDA_CONTEXT* Context) {
    EGIDA_PAGED_CODE();

    EgidaLogInfo("Initializing Egida Core...");

    if (!Context) {
        EgidaLogError("Invalid context pointer");
        return EGIDA_FAILED;
    }

    // Allocate context
    PEGIDA_CONTEXT context = static_cast<PEGIDA_CONTEXT>(
        EGIDA_ALLOC_NON_PAGED(sizeof(EGIDA_CONTEXT))
        );

    if (!context) {
        EgidaLogError("Failed to allocate context");
        return EGIDA_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(EGIDA_CONTEXT));

    // Initialize spin lock
    KeInitializeSpinLock(&context->SpinLock);

    // Set default configuration
    context->Config.Flags = EGIDA_SPOOF_ALL;
    context->Config.EnableSmbiosSpoof = TRUE;
    context->Config.EnableDiskSpoof = TRUE;
    context->Config.EnableNetworkSpoof = TRUE;
    context->Config.EnableBootInfoSpoof = TRUE;

    // Initialize randomization config
    context->Config.RandomConfig.RandomizeStrings = TRUE;
    context->Config.RandomConfig.RandomizeSerials = TRUE;
    context->Config.RandomConfig.RandomizeMAC = TRUE;
    context->Config.RandomConfig.RandomizeUUID = TRUE;
    context->Config.RandomConfig.MinStringLength = 8;
    context->Config.RandomConfig.MaxStringLength = 16;
    context->Config.RandomConfig.RandomSeed = static_cast<UINT32>(KeQueryTimeIncrement());

    // Initialize modules
    NTSTATUS status = InitializeModules(context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to initialize modules: 0x%08X", status);
        EGIDA_FREE(context);
        return status;
    }

    context->IsInitialized = TRUE;
    g_EgidaContext = context;
    *Context = context;

    EgidaLogInfo("Egida Core initialized successfully");
    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::Cleanup(_In_ PEGIDA_CONTEXT Context) {
    EGIDA_PAGED_CODE();

    if (!Context) {
        return EGIDA_SUCCESS;
    }

    EgidaLogInfo("Cleaning up Egida Core...");

    // Stop spoofing if active
    if (Context->IsSpoofingActive) {
        StopSpoofing(Context);
    }

    // Cleanup modules
    CleanupModules(Context);

    // Cleanup device objects
    if (Context->DeviceObject) {
        if (Context->SymbolicLink.Buffer) {
            IoDeleteSymbolicLink(&Context->SymbolicLink);
            RtlFreeUnicodeString(&Context->SymbolicLink);
        }

        IoDeleteDevice(Context->DeviceObject);
    }

    // Free context
    EGIDA_FREE(Context);
    g_EgidaContext = nullptr;

    EgidaLogInfo("Egida Core cleanup completed");
    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::StartSpoofing(_In_ PEGIDA_CONTEXT Context) {
    if (!Context || !Context->IsInitialized) {
        EgidaLogError("Context not initialized");
        return EGIDA_FAILED;
    }

    if (Context->IsSpoofingActive) {
        EgidaLogWarning("Spoofing already active");
        return EGIDA_SUCCESS;
    }

    EgidaLogInfo("Starting HWID spoofing...");

    NTSTATUS status = EGIDA_SUCCESS;

    // SMBIOS Spoofing
    if (Context->Config.EnableSmbiosSpoof) {
        EgidaLogInfo("Starting SMBIOS spoofing...");
        status = SmbiosSpoofer::ExecuteSpoof(Context);
        if (!NT_SUCCESS(status)) {
            EgidaLogError("SMBIOS spoofing failed: 0x%08X", status);
            return status;
        }
    }

    // Disk Spoofing
    if (Context->Config.EnableDiskSpoof) {
        EgidaLogInfo("Starting Disk spoofing...");
        status = DiskSpoofer::ExecuteSpoof(Context);
        if (!NT_SUCCESS(status)) {
            EgidaLogError("Disk spoofing failed: 0x%08X", status);
            return status;
        }
    }

    // Network Spoofing
    if (Context->Config.EnableNetworkSpoof) {
        EgidaLogInfo("Starting Network spoofing...");
        status = NetworkSpoofer::ExecuteSpoof(Context);
        if (!NT_SUCCESS(status)) {
            EgidaLogError("Network spoofing failed: 0x%08X", status);
            return status;
        }
    }

    Context->IsSpoofingActive = TRUE;
    EgidaLogInfo("HWID spoofing started successfully");

    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::StopSpoofing(_In_ PEGIDA_CONTEXT Context) {
    if (!Context) {
        return EGIDA_FAILED;
    }

    if (!Context->IsSpoofingActive) {
        return EGIDA_SUCCESS;
    }

    EgidaLogInfo("Stopping HWID spoofing...");

    // Stop individual modules
    if (Context->Config.EnableNetworkSpoof) {
        NetworkSpoofer::StopSpoof(Context);
    }

    if (Context->Config.EnableDiskSpoof) {
        DiskSpoofer::StopSpoof(Context);
    }

    if (Context->Config.EnableSmbiosSpoof) {
        SmbiosSpoofer::StopSpoof(Context);
    }

    Context->IsSpoofingActive = FALSE;
    EgidaLogInfo("HWID spoofing stopped");

    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::InitializeModules(_In_ PEGIDA_CONTEXT Context) {
    NTSTATUS status;

    // Initialize SMBIOS Spoofer
    status = SmbiosSpoofer::Initialize(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to initialize SMBIOS spoofer: 0x%08X", status);
        return status;
    }

    // Initialize Disk Spoofer  
    status = DiskSpoofer::Initialize(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to initialize Disk spoofer: 0x%08X", status);
        return status;
    }

    // Initialize Network Spoofer
    status = NetworkSpoofer::Initialize(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to initialize Network spoofer: 0x%08X", status);
        return status;
    }

    return EGIDA_SUCCESS;
}

VOID EgidaCore::CleanupModules(_In_ PEGIDA_CONTEXT Context) {
    if (Context->Config.EnableSmbiosSpoof) {
        SmbiosSpoofer::Cleanup(Context);
    }

    if (Context->Config.EnableDiskSpoof) {
        DiskSpoofer::Cleanup(Context);
    }

    if (Context->Config.EnableNetworkSpoof) {
        NetworkSpoofer::Cleanup(Context);
    }
}

NTSTATUS EgidaCore::HandleDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = EGIDA_SUCCESS;
    ULONG bytesReturned = 0;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_EGIDA_START_SPOOF:
        status = StartSpoofing(g_EgidaGlobalContext);
        break;

    case IOCTL_EGIDA_STOP_SPOOF:
        status = StopSpoofing(g_EgidaGlobalContext);
        break;

    case IOCTL_EGIDA_GET_STATUS:
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(EGIDA_STATUS)) {
            PEGIDA_STATUS statusInfo = static_cast<PEGIDA_STATUS>(Irp->AssociatedIrp.SystemBuffer);
            status = GetStatus(g_EgidaGlobalContext, statusInfo);
            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(EGIDA_STATUS);
            }
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_EGIDA_SET_CONFIG:
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(SPOOF_CONFIGURATION)) {
            PSPOOF_CONFIGURATION config = static_cast<PSPOOF_CONFIGURATION>(Irp->AssociatedIrp.SystemBuffer);
            status = SetConfiguration(g_EgidaGlobalContext, config);
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// Driver entry points implementation
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

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
        sizeof(EGIDA_CONTEXT),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to create device: 0x%08X", status);
        return status;
    }

    // Create symbolic link
    UNICODE_STRING symbolicLink;
    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_LINK);

    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to create symbolic link: 0x%08X", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Initialize core
    status = EgidaCore::Initialize(&g_EgidaGlobalContext);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to initialize core: 0x%08X", status);
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(deviceObject);
        return status;
    }

    g_EgidaGlobalContext->DeviceObject = deviceObject;
    deviceObject->DeviceExtension = g_EgidaGlobalContext;

    EgidaLogInfo("Egida Driver loaded successfully");
    return EGIDA_SUCCESS;
}

extern "C" VOID EgidaUnloadDriver(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    EgidaLogInfo("Unloading Egida Driver...");

    if (g_EgidaGlobalContext) {
        EgidaCore::Cleanup(g_EgidaGlobalContext);
        g_EgidaGlobalContext = nullptr;
    }

    EgidaLogCleanup();
}

extern "C" NTSTATUS EgidaCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS EgidaDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    return EgidaCore::HandleDeviceControl(DeviceObject, Irp);
}

NTSTATUS EgidaCore::SetConfiguration(_In_ PEGIDA_CONTEXT Context, _In_ PSPOOF_CONFIGURATION Config) {
    if (!Context || !Config) {
        return EGIDA_FAILED;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&Context->SpinLock, &oldIrql);

    RtlCopyMemory(&Context->Config, Config, sizeof(SPOOF_CONFIGURATION));

    KeReleaseSpinLock(&Context->SpinLock, oldIrql);

    EgidaLogInfo("Configuration updated");
    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::GetStatus(_In_ PEGIDA_CONTEXT Context, _Out_ PEGIDA_STATUS Status) {
    if (!Context || !Status) {
        return EGIDA_FAILED;
    }

    RtlZeroMemory(Status, sizeof(EGIDA_STATUS));

    Status->IsActive = Context->IsSpoofingActive;
    Status->SpoofedComponents = 0;

    if (Context->Config.EnableSmbiosSpoof) Status->SpoofedComponents |= EGIDA_SPOOF_SMBIOS;
    if (Context->Config.EnableDiskSpoof) Status->SpoofedComponents |= EGIDA_SPOOF_DISK;
    if (Context->Config.EnableNetworkSpoof) Status->SpoofedComponents |= EGIDA_SPOOF_NETWORK;

    RtlStringCbCopyA(Status->Version, sizeof(Status->Version), EGIDA_VERSION);

    return EGIDA_SUCCESS;
}