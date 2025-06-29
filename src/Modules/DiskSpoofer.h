#pragma once
#include "../Common/Structures.h"

class DiskSpoofer {
public:
    static NTSTATUS Initialize(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ExecuteSpoof(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS StopSpoof(_In_ PEGIDA_CONTEXT Context);
    static VOID Cleanup(_In_ PEGIDA_CONTEXT Context);

private:
    static NTSTATUS ChangeDiskSerials(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS DisableSmartOnAllDisks(_In_ PEGIDA_CONTEXT Context);
    static PDEVICE_OBJECT GetRaidDevice(_In_ PCWSTR DeviceName);
    static NTSTATUS ProcessRaidDevices(_In_ PDEVICE_OBJECT DeviceArray, _In_ PEGIDA_CONTEXT Context);
    static VOID DisableSmartBit(_In_ PRAID_UNIT_EXTENSION Extension);
    static NTSTATUS ProcessSingleDiskDevice(_In_ PRAID_UNIT_EXTENSION Extension, _In_ PEGIDA_CONTEXT Context);

    static NTSTATUS AllocateAndSetDiskString(
        _In_ PRAID_UNIT_EXTENSION Extension,
        _In_ PSTRING TargetString,
        _In_ PCSTR NewValue,
        _In_ PEGIDA_CONTEXT Context,
        _In_ ULONG StringType
    );

    static VOID FreeDiskAllocatedStrings(_In_ PEGIDA_CONTEXT Context);

    static NTSTATUS TrackAllocatedDiskString(
        _In_ PEGIDA_CONTEXT Context,
        _In_ PCHAR StringPointer,
        _In_ SIZE_T StringSize,
        _In_ PRAID_UNIT_EXTENSION Extension,
        _In_ ULONG StringType
    );

    // Module state
    static PVOID s_StorportBase;
    static PVOID s_DiskBase;
    static RaidUnitRegisterInterfaces s_RaidUnitRegisterInterfaces;
    static DiskEnableDisableFailurePrediction s_DiskEnableDisableFailurePrediction;
};