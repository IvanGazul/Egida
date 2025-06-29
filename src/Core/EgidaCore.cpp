#include "EgidaCore.h"
#include "../Modules/SmbiosSpoofer.h"
#include "../Modules/DiskSpoofer.h"
#include "../Modules/NetworkSpoofer.h"
#include "../Modules/GpuSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Core/Logger.h"
#include "../Common/Globals.h"

// Static context for EgidaCore class
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

    // GPU Spoofing
    if (Context->Config.Flags & EGIDA_SPOOF_GPU) {
        EgidaLogInfo("Starting GPU spoofing...");
        status = GpuSpoofer::ExecuteSpoof(Context);
        if (!NT_SUCCESS(status)) {
            EgidaLogError("GPU spoofing failed: 0x%08X", status);
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
    if (Context->Config.Flags & EGIDA_SPOOF_GPU) {
        GpuSpoofer::StopSpoof(Context);
    }

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

// NEW: GPU-specific control methods
NTSTATUS EgidaCore::StartGPUSpoofing(_In_ PEGIDA_CONTEXT Context) {
    if (!Context || !Context->IsInitialized) {
        EgidaLogError("Context not initialized");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Starting GPU spoofing only...");

    // Enable GPU spoofing flag
    Context->Config.Flags |= EGIDA_SPOOF_GPU;

    NTSTATUS status = GpuSpoofer::ExecuteSpoof(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("GPU spoofing failed: 0x%08X", status);
        return status;
    }

    EgidaLogInfo("GPU spoofing started successfully");
    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::StopGPUSpoofing(_In_ PEGIDA_CONTEXT Context) {
    if (!Context) {
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Stopping GPU spoofing...");

    NTSTATUS status = GpuSpoofer::StopSpoof(Context);
    if (NT_SUCCESS(status)) {
        Context->Config.Flags &= ~EGIDA_SPOOF_GPU;
        EgidaLogInfo("GPU spoofing stopped");
    }

    return status;
}

NTSTATUS EgidaCore::GetGPUStatus(_In_ PEGIDA_CONTEXT Context, _Out_ PEGIDA_STATUS Status) {
    if (!Context || !Status) {
        return EGIDA_FAILED;
    }

    // Use the regular GetStatus but focus on GPU info
    NTSTATUS status = GetStatus(Context, Status);
    if (NT_SUCCESS(status)) {
        // Additional GPU-specific status info could be added here
        EgidaLogDebug("GPU status: %s", (Status->SpoofedComponents & EGIDA_SPOOF_GPU) ? "Active" : "Inactive");
    }

    return status;
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

    // Initialize GPU Spoofer
    status = GpuSpoofer::Initialize(Context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to initialize GPU spoofer: 0x%08X", status);
        return status;
    }

    return EGIDA_SUCCESS;
}

VOID EgidaCore::CleanupModules(_In_ PEGIDA_CONTEXT Context) {
    if (Context->Config.Flags & EGIDA_SPOOF_GPU) {
        GpuSpoofer::Cleanup(Context);
    }

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

    EgidaLogDebug("Received IOCTL: 0x%08X", irpSp->Parameters.DeviceIoControl.IoControlCode);

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_EGIDA_START_SPOOF:
        EgidaLogInfo("Processing START_SPOOF command");
        status = StartSpoofing(g_EgidaGlobalContext);
        break;

    case IOCTL_EGIDA_STOP_SPOOF:
        EgidaLogInfo("Processing STOP_SPOOF command");
        status = StopSpoofing(g_EgidaGlobalContext);
        break;

    case IOCTL_EGIDA_GET_STATUS:
        EgidaLogDebug("Processing GET_STATUS command");
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(EGIDA_STATUS)) {
            PEGIDA_STATUS statusInfo = static_cast<PEGIDA_STATUS>(Irp->AssociatedIrp.SystemBuffer);
            status = GetStatus(g_EgidaGlobalContext, statusInfo);
            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(EGIDA_STATUS);
            }
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
            EgidaLogError("Buffer too small for status structure");
        }
        break;

    case IOCTL_EGIDA_SET_CONFIG:
        EgidaLogInfo("Processing SET_CONFIG command");
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(SPOOF_CONFIGURATION)) {
            PSPOOF_CONFIGURATION config = static_cast<PSPOOF_CONFIGURATION>(Irp->AssociatedIrp.SystemBuffer);
            status = SetConfiguration(g_EgidaGlobalContext, config);
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
            EgidaLogError("Buffer too small for configuration structure");
        }
        break;

    case IOCTL_EGIDA_START_GPU_SPOOF:
        EgidaLogInfo("Processing START_GPU_SPOOF command");
        status = StartGPUSpoofing(g_EgidaGlobalContext);
        break;

    case IOCTL_EGIDA_STOP_GPU_SPOOF:
        EgidaLogInfo("Processing STOP_GPU_SPOOF command");
        status = StopGPUSpoofing(g_EgidaGlobalContext);
        break;

    case IOCTL_EGIDA_GET_GPU_STATUS:
        EgidaLogDebug("Processing GET_GPU_STATUS command");
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(EGIDA_STATUS)) {
            PEGIDA_STATUS statusInfo = static_cast<PEGIDA_STATUS>(Irp->AssociatedIrp.SystemBuffer);
            status = GetGPUStatus(g_EgidaGlobalContext, statusInfo);
            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(EGIDA_STATUS);
            }
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
            EgidaLogError("Buffer too small for GPU status structure");
        }
        break;

    default:
        EgidaLogWarning("Unknown IOCTL code: 0x%08X", irpSp->Parameters.DeviceIoControl.IoControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    EgidaLogDebug("IOCTL completed with status: 0x%08X, bytes returned: %lu", status, bytesReturned);

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS EgidaCore::SetConfiguration(_In_ PEGIDA_CONTEXT Context, _In_ PSPOOF_CONFIGURATION Config) {
    if (!Context || !Config) {
        EgidaLogError("Invalid parameters for SetConfiguration");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Updating configuration...");
    EgidaLogDebug("Flags: 0x%08X", Config->Flags);
    EgidaLogDebug("SMBIOS: %s", Config->EnableSmbiosSpoof ? "Enabled" : "Disabled");
    EgidaLogDebug("Disk: %s", Config->EnableDiskSpoof ? "Enabled" : "Disabled");
    EgidaLogDebug("Network: %s", Config->EnableNetworkSpoof ? "Enabled" : "Disabled");
    EgidaLogDebug("Boot Info: %s", Config->EnableBootInfoSpoof ? "Enabled" : "Disabled");
    EgidaLogDebug("Random Seed: %lu", Config->RandomConfig.RandomSeed);

    KIRQL oldIrql;
    KeAcquireSpinLock(&Context->SpinLock, &oldIrql);

    // Copy configuration
    RtlCopyMemory(&Context->Config, Config, sizeof(SPOOF_CONFIGURATION));

    KeReleaseSpinLock(&Context->SpinLock, oldIrql);

    EgidaLogInfo("Configuration updated successfully");
    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::GetStatus(_In_ PEGIDA_CONTEXT Context, _Out_ PEGIDA_STATUS Status) {
    if (!Context || !Status) {
        EgidaLogError("Invalid parameters for GetStatus");
        return EGIDA_FAILED;
    }

    RtlZeroMemory(Status, sizeof(EGIDA_STATUS));

    Status->IsActive = Context->IsSpoofingActive;
    Status->SpoofedComponents = 0;

    // Determine which components are spoofed
    if (Context->Config.EnableSmbiosSpoof) Status->SpoofedComponents |= EGIDA_SPOOF_SMBIOS;
    if (Context->Config.EnableDiskSpoof) Status->SpoofedComponents |= EGIDA_SPOOF_DISK;
    if (Context->Config.EnableNetworkSpoof) Status->SpoofedComponents |= EGIDA_SPOOF_NETWORK;
    if (Context->Config.Flags & EGIDA_SPOOF_GPU) Status->SpoofedComponents |= EGIDA_SPOOF_GPU;

    // Memory statistics
    Status->SmbiosAllocatedCount = Context->SmbiosAllocatedStringCount;
    Status->DiskAllocatedCount = Context->DiskAllocatedStringCount;
    Status->AllocatedStringsCount = Status->SmbiosAllocatedCount + Status->DiskAllocatedCount;

    // GPU statistics
    if (Context->GpuContext) {
        Status->GpuDevicesCount = Context->GpuContext->DeviceCount;
    }
    else {
        Status->GpuDevicesCount = 0;
    }

    // Copy version string
    RtlStringCbCopyA(Status->Version, sizeof(Status->Version), EGIDA_VERSION);

    // Last error (for now, always success)
    Status->LastError = 0;

    EgidaLogDebug("Status retrieved - Active: %s, Components: 0x%08X",
        Status->IsActive ? "Yes" : "No", Status->SpoofedComponents);

    return EGIDA_SUCCESS;
}