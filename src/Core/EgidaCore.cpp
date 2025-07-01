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

    // Initialize profile data fields
    context->HasProfileData = FALSE;
    RtlZeroMemory(&context->CurrentProfile, sizeof(PROFILE_DATA));

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

NTSTATUS EgidaCore::SetProfileData(_In_ PEGIDA_CONTEXT Context, _In_ PPROFILE_DATA ProfileData) {
    if (!Context || !ProfileData) {
        EgidaLogError("Invalid parameters for SetProfileData");
        return EGIDA_FAILED;
    }

    // Validate profile data
    NTSTATUS status = ValidateProfileData(ProfileData);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Profile data validation failed: 0x%08X", status);
        return status;
    }

    EgidaLogInfo("=== SETTING PROFILE DATA ===");
    EgidaLogInfo("Profile Name: %s", ProfileData->ProfileName);
    EgidaLogInfo("Random Seed: %lu", ProfileData->RandomSeed);

    // Log SMBIOS values
    EgidaLogInfo("--- SMBIOS Profile Values ---");
    EgidaLogInfo("Motherboard Serial: %s", ProfileData->MotherboardSerial);
    EgidaLogInfo("System Manufacturer: %s", ProfileData->SystemManufacturer);
    EgidaLogInfo("System Product: %s", ProfileData->SystemProductName);
    EgidaLogInfo("System Serial: %s", ProfileData->SystemSerialNumber);
    EgidaLogInfo("System UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        ProfileData->SystemUUID[0], ProfileData->SystemUUID[1], ProfileData->SystemUUID[2], ProfileData->SystemUUID[3],
        ProfileData->SystemUUID[4], ProfileData->SystemUUID[5], ProfileData->SystemUUID[6], ProfileData->SystemUUID[7],
        ProfileData->SystemUUID[8], ProfileData->SystemUUID[9], ProfileData->SystemUUID[10], ProfileData->SystemUUID[11],
        ProfileData->SystemUUID[12], ProfileData->SystemUUID[13], ProfileData->SystemUUID[14], ProfileData->SystemUUID[15]);

    // Log Disk values
    EgidaLogInfo("--- Disk Profile Values ---");
    EgidaLogInfo("Disk Serial: %s", ProfileData->DiskSerial);
    EgidaLogInfo("Disk Model: %s", ProfileData->DiskModel);
    EgidaLogInfo("Disk Vendor: %s", ProfileData->DiskVendor);

    // Log Network values
    EgidaLogInfo("--- Network Profile Values ---");
    EgidaLogInfo("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X",
        ProfileData->MacAddress[0], ProfileData->MacAddress[1], ProfileData->MacAddress[2],
        ProfileData->MacAddress[3], ProfileData->MacAddress[4], ProfileData->MacAddress[5]);

    // Log GPU values
    EgidaLogInfo("--- GPU Profile Values ---");
    EgidaLogInfo("GPU Description: %s", ProfileData->GpuDescription);
    EgidaLogInfo("GPU PNP ID: %s", ProfileData->GpuPNPID);

    // Log BIOS values
    EgidaLogInfo("--- BIOS Profile Values ---");
    EgidaLogInfo("BIOS Vendor: %s", ProfileData->BiosVendor);
    EgidaLogInfo("BIOS Version: %s", ProfileData->BiosVersion);
    EgidaLogInfo("BIOS Date: %s", ProfileData->BiosReleaseDate);

    KIRQL oldIrql;
    KeAcquireSpinLock(&Context->SpinLock, &oldIrql);

    // Copy profile data to context
    RtlCopyMemory(&Context->CurrentProfile, ProfileData, sizeof(PROFILE_DATA));
    Context->HasProfileData = TRUE;

    KeReleaseSpinLock(&Context->SpinLock, oldIrql);

    EgidaLogInfo("Profile data stored in context successfully");
    EgidaLogInfo("=== PROFILE DATA SET COMPLETE ===");

    return EGIDA_SUCCESS;
}

NTSTATUS EgidaCore::ValidateProfileData(_In_ PPROFILE_DATA ProfileData) {
    if (!ProfileData) {
        EgidaLogError("ProfileData pointer is NULL");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("=== PROFILE VALIDATION DEBUG ===");
    EgidaLogDebug("Profile address: 0x%p", ProfileData);
    EgidaLogDebug("Profile IsValid field: %d (0x%02X)", ProfileData->IsValid, ProfileData->IsValid);
    EgidaLogDebug("Profile Checksum: 0x%08X", ProfileData->Checksum);
    EgidaLogDebug("Profile Name length: %zu", strnlen(ProfileData->ProfileName, sizeof(ProfileData->ProfileName)));
    EgidaLogDebug("Profile Name: '%.63s'", ProfileData->ProfileName);

    // Check if profile is marked as valid
    if (!ProfileData->IsValid) {
        EgidaLogError("Profile data marked as invalid (IsValid = %d)", ProfileData->IsValid);
        return EGIDA_FAILED;
    }

    // Verify checksum
    UINT32 calculatedChecksum = CalculateProfileChecksum(ProfileData);
    EgidaLogDebug("Calculated checksum: 0x%08X", calculatedChecksum);

    if (calculatedChecksum != ProfileData->Checksum) {
        EgidaLogError("Profile checksum mismatch: expected 0x%08X, got 0x%08X",
            ProfileData->Checksum, calculatedChecksum);
        return EGIDA_FAILED;
    }

    // Validate profile name
    SIZE_T nameLength = strnlen(ProfileData->ProfileName, sizeof(ProfileData->ProfileName));
    if (nameLength == 0) {
        EgidaLogError("Profile name is empty");
        return EGIDA_FAILED;
    }

    // Log some profile content for verification
    EgidaLogDebug("System Serial: '%.63s'", ProfileData->SystemSerialNumber);
    EgidaLogDebug("Disk Serial: '%.63s'", ProfileData->DiskSerial);
    EgidaLogDebug("=== PROFILE VALIDATION PASSED ===");

    EgidaLogInfo("Profile data validation passed");
    return EGIDA_SUCCESS;
}

UINT32 EgidaCore::CalculateProfileChecksum(_In_ PPROFILE_DATA ProfileData) {
    if (!ProfileData) {
        return 0;
    }

    UINT32 checksum = 0;
    UINT32 originalChecksum = ProfileData->Checksum;

    // Temporarily clear checksum for calculation
    ProfileData->Checksum = 0;

    // Simple checksum calculation
    PUCHAR data = reinterpret_cast<PUCHAR>(ProfileData);
    SIZE_T size = sizeof(PROFILE_DATA);

    for (SIZE_T i = 0; i < size; i++) {
        checksum += data[i];
        checksum = (checksum << 1) | (checksum >> 31); // Rotate left
    }

    // Restore original checksum
    ProfileData->Checksum = originalChecksum;

    return checksum;
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

    case IOCTL_EGIDA_SET_PROFILE_DATA:
        EgidaLogInfo("Processing SET_PROFILE_DATA command");
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PROFILE_DATA)) {
            PPROFILE_DATA profileData = static_cast<PPROFILE_DATA>(Irp->AssociatedIrp.SystemBuffer);

            EgidaLogInfo("=== RAW PROFILE DATA RECEIVED ===");
            EgidaLogInfo("Input buffer length: %lu", irpSp->Parameters.DeviceIoControl.InputBufferLength);
            EgidaLogInfo("Expected size: %lu", sizeof(PROFILE_DATA));
            EgidaLogInfo("Profile pointer: 0x%p", profileData);


            // Try to read the profile name first (it should be readable)
            CHAR tempName[65] = { 0 };
            RtlCopyMemory(tempName, profileData->ProfileName, 64);
            EgidaLogInfo("Profile name from raw data: '%s'", tempName);

            // Now try the normal processing
            status = SetProfileData(g_EgidaGlobalContext, profileData);
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
            EgidaLogError("Buffer too small for profile data structure, got %lu, need %lu",
                irpSp->Parameters.DeviceIoControl.InputBufferLength, sizeof(PROFILE_DATA));
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