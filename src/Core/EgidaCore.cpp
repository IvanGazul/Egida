#include "EgidaCore.h"
#include "../Modules/SmbiosSpoofer.h"
#include "../Modules/DiskSpoofer.h"
#include "../Modules/NetworkSpoofer.h"
#include "../Utils/EgidaUtils.h"

// Global context
PEGIDA_CONTEXT g_EgidaGlobalContext = nullptr;

// Device dispatch routines
NTSTATUS EgidaCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS EgidaDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

// Helper functions
VOID UpdateContextStatus(_In_ PEGIDA_CONTEXT Context, _In_ PCSTR ProfileName);
VOID ClearContextStatus(_In_ PEGIDA_CONTEXT Context);
NTSTATUS GetDriverStatus(_In_ PEGIDA_CONTEXT Context, _Out_ PDRIVER_STATUS Status);

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
    KeInitializeSpinLock(&context->SpinLock);

    // Initialize modules
    NTSTATUS status = InitializeModules(context);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to initialize modules: 0x%08X", status);
        EGIDA_FREE(context);
        return status;
    }

    context->IsInitialized = TRUE;
    context->IsSpoofingActive = FALSE;
    context->HasProfile = FALSE;
    context->ActiveSpoofModules = 0;
    RtlZeroMemory(context->ActiveProfileName, sizeof(context->ActiveProfileName));
    context->ProfileAppliedTime.QuadPart = 0;

    *Context = context;

    EgidaLogInfo("Egida Core initialized - waiting for profile from UserMode");
    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::Cleanup(_In_ PEGIDA_CONTEXT Context) {
    EGIDA_PAGED_CODE();

    if (!Context) {
        return EGIDA_SUCCESS;
    }

    EgidaLogInfo("Cleaning up Egida Core...");

    // Clear status
    ClearContextStatus(Context);

    // Free profile data if allocated
    if (Context->ProfileData) {
        EGIDA_FREE(Context->ProfileData);
        Context->ProfileData = nullptr;
    }

    // Cleanup modules
    CleanupModules(Context);

    // Free context
    EGIDA_FREE(Context);
    g_EgidaGlobalContext = nullptr;

    EgidaLogInfo("Egida Core cleanup completed");
    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::ExecuteAllSpoofs(_In_ PEGIDA_CONTEXT Context) {
    if (!Context || !Context->IsInitialized) {
        EgidaLogError("Context not initialized for spoofing");
        return EGIDA_FAILED;
    }

    if (!Context->HasProfile || !Context->ProfileData) {
        EgidaLogError("No profile data available for spoofing");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Starting HWID spoofing with profile: %s", Context->ProfileData->ProfileName);
    NTSTATUS status = EGIDA_SUCCESS;
    ULONG successfulModules = 0;

    // SMBIOS Spoofing
    EgidaLogInfo("Starting SMBIOS spoofing...");
    status = SmbiosSpoofer::ExecuteSpoof(Context);
    if (NT_SUCCESS(status)) {
        successfulModules |= SPOOF_MODULE_SMBIOS;
        EgidaLogInfo("SMBIOS spoofing completed successfully");
    }
    else {
        EgidaLogError("SMBIOS spoofing failed: 0x%08X", status);
        return status;
    }

    // Disk Spoofing
    EgidaLogInfo("Starting Disk spoofing...");
    status = DiskSpoofer::ExecuteSpoof(Context);
    if (NT_SUCCESS(status)) {
        successfulModules |= SPOOF_MODULE_DISK;
        EgidaLogInfo("Disk spoofing completed successfully");
    }
    else {
        EgidaLogWarning("Disk spoofing failed: 0x%08X (continuing)", status);
        // Don't return error, disk spoofing might fail but it's not critical
    }

    // Network Spoofing
    EgidaLogInfo("Starting Network spoofing...");
    status = NetworkSpoofer::ExecuteSpoof(Context);
    if (NT_SUCCESS(status)) {
        successfulModules |= SPOOF_MODULE_NETWORK;
        EgidaLogInfo("Network spoofing completed successfully");
    }
    else {
        EgidaLogError("Network spoofing failed: 0x%08X", status);
        return status;
    }

    // Update context status
    Context->IsSpoofingActive = TRUE;
    Context->ActiveSpoofModules = successfulModules;
    UpdateContextStatus(Context, Context->ProfileData->ProfileName);

    EgidaLogInfo("HWID spoofing completed successfully. Active modules: 0x%02X", successfulModules);
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

    Context->IsInitialized = TRUE;
    return EGIDA_SUCCESS;
}

VOID EgidaCore::CleanupModules(_In_ PEGIDA_CONTEXT Context) {
    SmbiosSpoofer::Cleanup(Context);
    DiskSpoofer::Cleanup(Context);
    NetworkSpoofer::Cleanup(Context);
}

// Helper functions implementation
VOID UpdateContextStatus(_In_ PEGIDA_CONTEXT Context, _In_ PCSTR ProfileName) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&Context->SpinLock, &oldIrql);

    // Update profile name
    RtlZeroMemory(Context->ActiveProfileName, sizeof(Context->ActiveProfileName));
    if (ProfileName && strlen(ProfileName) > 0) {
        strncpy_s(Context->ActiveProfileName, sizeof(Context->ActiveProfileName),
            ProfileName, _TRUNCATE);
    }

    // Update timestamp
    KeQuerySystemTime(&Context->ProfileAppliedTime);

    KeReleaseSpinLock(&Context->SpinLock, oldIrql);
}

VOID ClearContextStatus(_In_ PEGIDA_CONTEXT Context) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&Context->SpinLock, &oldIrql);

    RtlZeroMemory(Context->ActiveProfileName, sizeof(Context->ActiveProfileName));
    Context->ProfileAppliedTime.QuadPart = 0;
    Context->ActiveSpoofModules = 0;

    KeReleaseSpinLock(&Context->SpinLock, oldIrql);
}

NTSTATUS GetDriverStatus(_In_ PEGIDA_CONTEXT Context, _Out_ PDRIVER_STATUS Status) {
    if (!Context || !Status) {
        return STATUS_INVALID_PARAMETER;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&Context->SpinLock, &oldIrql);

    RtlZeroMemory(Status, sizeof(DRIVER_STATUS));
    Status->ProfileActive = Context->HasProfile && Context->IsSpoofingActive;
    Status->IsSpoofingActive = Context->IsSpoofingActive;
    Status->ActiveSpoofModules = Context->ActiveSpoofModules;
    Status->ProfileAppliedTime = Context->ProfileAppliedTime;

    if (Status->ProfileActive) {
        strncpy_s(Status->ActiveProfileName, sizeof(Status->ActiveProfileName),
            Context->ActiveProfileName, _TRUNCATE);
    }

    KeReleaseSpinLock(&Context->SpinLock, oldIrql);
    return STATUS_SUCCESS;
}

// Driver entry points implementation
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    EgidaLogInitialize();
    EgidaLogInfo("Egida Driver is loading...", EGIDA_VERSION);

    // Set dispatch routines
    DriverObject->DriverUnload = EgidaUnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = EgidaCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = EgidaCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EgidaDeviceControl;

    // Create device
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(SYMBOLIC_LINK);

    PDEVICE_OBJECT deviceObject = nullptr;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
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
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to create symbolic link: 0x%08X", status);
        IoDeleteDevice(deviceObject);
        EgidaLogCleanup();
        return status;
    }

    // Initialize core
    status = EgidaCore::Initialize(&g_EgidaGlobalContext);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to initialize core: 0x%08X", status);
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(deviceObject);
        EgidaLogCleanup();
        return status;
    }

    g_EgidaGlobalContext->DeviceObject = deviceObject;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    EgidaLogInfo("Egida Driver loaded successfully. Waiting for profile...");
    return EGIDA_SUCCESS;
}

extern "C" VOID EgidaUnloadDriver(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    EgidaLogInfo("Unloading Egida Driver...");

    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(SYMBOLIC_LINK);
    IoDeleteSymbolicLink(&symbolicLink);

    if (g_EgidaGlobalContext) {
        if (g_EgidaGlobalContext->DeviceObject) {
            IoDeleteDevice(g_EgidaGlobalContext->DeviceObject);
        }
        EgidaCore::Cleanup(g_EgidaGlobalContext);
        g_EgidaGlobalContext = nullptr;
    }

    EgidaLogCleanup();
}

// Device dispatch routines
NTSTATUS EgidaCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS EgidaDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    if (!g_EgidaGlobalContext) {
        EgidaLogError("Global context is null");
        status = STATUS_DEVICE_NOT_READY;
        goto Complete;
    }

    switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_EGIDA_SET_PROFILE: {
        EgidaLogInfo("Received SET_PROFILE IOCTL");

        ULONG inputSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG expectedSize = sizeof(SMBIOS_PROFILE_DATA);

        EgidaLogDebug("Profile data size - received: %lu, expected: %lu", inputSize, expectedSize);

        if (inputSize < expectedSize) {
            EgidaLogError("Invalid profile data size: %lu (expected: %lu)", inputSize, expectedSize);
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // Free existing profile if any
        if (g_EgidaGlobalContext->ProfileData) {
            EGIDA_FREE(g_EgidaGlobalContext->ProfileData);
            g_EgidaGlobalContext->ProfileData = nullptr;
        }

        // If spoofing was active, stop it first
        if (g_EgidaGlobalContext->IsSpoofingActive) {
            EgidaLogInfo("Stopping active spoofing before applying new profile");
            SmbiosSpoofer::StopSpoof(g_EgidaGlobalContext);
            DiskSpoofer::StopSpoof(g_EgidaGlobalContext);
            NetworkSpoofer::StopSpoof(g_EgidaGlobalContext);
            g_EgidaGlobalContext->IsSpoofingActive = FALSE;
            ClearContextStatus(g_EgidaGlobalContext);
        }

        // Allocate and copy new profile
        g_EgidaGlobalContext->ProfileData = static_cast<PSMBIOS_PROFILE_DATA>(
            EGIDA_ALLOC_NON_PAGED(sizeof(SMBIOS_PROFILE_DATA))
            );

        if (!g_EgidaGlobalContext->ProfileData) {
            EgidaLogError("Failed to allocate profile data");
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(
            g_EgidaGlobalContext->ProfileData,
            Irp->AssociatedIrp.SystemBuffer,
            sizeof(SMBIOS_PROFILE_DATA)
        );

        g_EgidaGlobalContext->HasProfile = TRUE;
        EgidaLogInfo("Profile data set successfully: %s", g_EgidaGlobalContext->ProfileData->ProfileName);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_EGIDA_EXECUTE_SPOOF: {
        EgidaLogInfo("Received EXECUTE_SPOOF IOCTL");

        if (!g_EgidaGlobalContext->HasProfile) {
            EgidaLogError("No profile data available");
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        status = EgidaCore::ExecuteAllSpoofs(g_EgidaGlobalContext);
        break;
    }

    case IOCTL_EGIDA_STOP_SPOOF: {
        EgidaLogInfo("Received STOP_SPOOF IOCTL");

        if (!g_EgidaGlobalContext->IsSpoofingActive) {
            EgidaLogWarning("Spoofing is not active");
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        // Stop spoofing in each module
        SmbiosSpoofer::StopSpoof(g_EgidaGlobalContext);
        DiskSpoofer::StopSpoof(g_EgidaGlobalContext);
        NetworkSpoofer::StopSpoof(g_EgidaGlobalContext);

        g_EgidaGlobalContext->IsSpoofingActive = FALSE;
        ClearContextStatus(g_EgidaGlobalContext);
        EgidaLogInfo("Spoofing stopped");
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_EGIDA_GET_STATUS: {
        EgidaLogInfo("Received GET_STATUS IOCTL");

        ULONG outputSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG expectedSize = sizeof(DRIVER_STATUS);

        if (outputSize < expectedSize) {
            EgidaLogError("Invalid output buffer size: %lu (expected: %lu)", outputSize, expectedSize);
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PDRIVER_STATUS driverStatus = static_cast<PDRIVER_STATUS>(Irp->AssociatedIrp.SystemBuffer);
        status = GetDriverStatus(g_EgidaGlobalContext, driverStatus);

        if (NT_SUCCESS(status)) {
            information = sizeof(DRIVER_STATUS);
            EgidaLogInfo("Driver status retrieved successfully. Profile active: %s, Name: %s",
                driverStatus->ProfileActive ? "Yes" : "No",
                driverStatus->ProfileActive ? driverStatus->ActiveProfileName : "None");
        }
        break;
    }

    default:
        EgidaLogWarning("Unknown IOCTL: 0x%08X", irpStack->Parameters.DeviceIoControl.IoControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}