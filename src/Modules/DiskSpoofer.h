#pragma once
#include "../Common/Structures.h"

// Disk spoofer specific structures
typedef struct _TELEMETRY_UNIT_EXTENSION {
    INT32 Flags;
} TELEMETRY_UNIT_EXTENSION, * PTELEMETRY_UNIT_EXTENSION;

typedef struct _STOR_SCSI_IDENTITY {
    CHAR Space[0x8];
    STRING SerialNumber;
} STOR_SCSI_IDENTITY, * PSTOR_SCSI_IDENTITY;

typedef struct _RAID_UNIT_EXTENSION {
    union {
        struct {
            CHAR Padding[0x68];
            STOR_SCSI_IDENTITY Identity;
        } _Identity;

        struct {
            CHAR Padding[0x7c8];
            TELEMETRY_UNIT_EXTENSION TelemetryExtension;
        } _Smart;
    };
} RAID_UNIT_EXTENSION, * PRAID_UNIT_EXTENSION;

// Function types
typedef __int64(__fastcall* RaidUnitRegisterInterfaces)(PRAID_UNIT_EXTENSION Extension);
typedef NTSTATUS(__fastcall* DiskEnableDisableFailurePrediction)(PVOID Extension, BOOLEAN Enable);

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

    // Module state
    static PVOID s_StorportBase;
    static PVOID s_DiskBase;
    static RaidUnitRegisterInterfaces s_RaidUnitRegisterInterfaces;
    static DiskEnableDisableFailurePrediction s_DiskEnableDisableFailurePrediction;
};