#pragma once
#include "../Common/Definitions.h"
#include "../Common/Structures.h"

// Forward declarations
struct _EGIDA_CONTEXT;
typedef struct _EGIDA_CONTEXT EGIDA_CONTEXT, * PEGIDA_CONTEXT;

class EgidaCore {
public:
    // Main initialization and cleanup
    static NTSTATUS Initialize(_Out_ PEGIDA_CONTEXT* Context);
    static NTSTATUS Cleanup(_In_ PEGIDA_CONTEXT Context);

    // Spoofing control
    static NTSTATUS StartSpoofing(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS StopSpoofing(_In_ PEGIDA_CONTEXT Context);

    // Configuration and status
    static NTSTATUS SetConfiguration(_In_ PEGIDA_CONTEXT Context, _In_ PSPOOF_CONFIGURATION Config);
    static NTSTATUS GetStatus(_In_ PEGIDA_CONTEXT Context, _Out_ PEGIDA_STATUS Status);

    // IOCTL handler
    static NTSTATUS HandleDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

    // GPU specific controls
    static NTSTATUS StartGPUSpoofing(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS StopGPUSpoofing(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS GetGPUStatus(_In_ PEGIDA_CONTEXT Context, _Out_ PEGIDA_STATUS Status);

    // Context accessor
    static PEGIDA_CONTEXT GetGlobalContext() { return g_EgidaContext; }

    static NTSTATUS SetProfileData(_In_ PEGIDA_CONTEXT Context, _In_ PPROFILE_DATA ProfileData);
    static NTSTATUS ValidateProfileData(_In_ PPROFILE_DATA ProfileData);
    static UINT32 CalculateProfileChecksum(_In_ PPROFILE_DATA ProfileData);
private:
    // Module management
    static NTSTATUS InitializeModules(_In_ PEGIDA_CONTEXT Context);
    static VOID CleanupModules(_In_ PEGIDA_CONTEXT Context);

    // Static context
    static PEGIDA_CONTEXT g_EgidaContext;
};