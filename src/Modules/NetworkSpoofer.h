#pragma once
#include "../Common/Structures.h"
#include <minwindef.h>

// Correct NDIS structures based on reference code
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
    static NTSTATUS ChangeMacAddress(_In_ PEGIDA_CONTEXT Context);
    static PWCHAR TrimGUID(_In_ PWCHAR guid, _In_ DWORD max);
    static PVOID SafeCopy(_In_ PVOID src, _In_ DWORD size);
    static DWORD Random(_Inout_ PDWORD seed);
    static DWORD Hash(_In_ PBYTE buffer, _In_ DWORD length);
    static VOID ShowMacAddress(_In_ PUCHAR macAddress, _In_ ULONG length);

    // Module state
    static PVOID s_NdisBase;
    static PVOID* s_NdisGlobalFilterList;
    static PVOID s_NdisDummyIrpHandler;
    static PVOID s_NdisMiniDriverList;
    static DWORD s_Seed;
};