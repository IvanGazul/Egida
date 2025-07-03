#pragma once
#include "../Common/Structures.h"

// Network specific structures
typedef struct _NDIS_FILTER_BLOCK {
    struct _NDIS_FILTER_BLOCK* NextFilter;
    PUNICODE_STRING FilterInstanceName;
    // Additional fields can be added as needed
    CHAR Reserved[0x100]; // Placeholder for unknown fields
} NDIS_FILTER_BLOCK, * PNDIS_FILTER_BLOCK;

class NetworkSpoofer {
public:
    static NTSTATUS Initialize(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ExecuteSpoof(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS StopSpoof(_In_ PEGIDA_CONTEXT Context);
    static VOID Cleanup(_In_ PEGIDA_CONTEXT Context);

private:
    static NTSTATUS HookNetworkDrivers(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS HookNetworkDriversAlternative(_In_ PEGIDA_CONTEXT Context);
    static PWCHAR ExtractAdapterName(_In_ PUNICODE_STRING InstanceName);
    static PVOID SafeCopyMemory(_In_ PVOID Source, _In_ SIZE_T Size);

    // Module state
    static PVOID s_NdisBase;
    static PVOID* s_NdisGlobalFilterList;
    static PVOID s_NdisDummyIrpHandler;
};