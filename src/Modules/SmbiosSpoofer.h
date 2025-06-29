#pragma once
#include "../Common/Structures.h"

// SMBIOS Types
#define SMBIOS_TYPE_BIOS           0
#define SMBIOS_TYPE_SYSTEM         1
#define SMBIOS_TYPE_BASEBOARD      2
#define SMBIOS_TYPE_CHASSIS        3
#define SMBIOS_TYPE_PROCESSOR      4
#define SMBIOS_TYPE_MEMORY_ARRAY   16
#define SMBIOS_TYPE_MEMORY_DEVICE  17
#define SMBIOS_TYPE_END            127

class SmbiosSpoofer {
public:
    static NTSTATUS Initialize(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ExecuteSpoof(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS StopSpoof(_In_ PEGIDA_CONTEXT Context);
    static VOID Cleanup(_In_ PEGIDA_CONTEXT Context);

private:
    static NTSTATUS FindSmbiosTables(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessSmbiosTable(_In_ PSMBIOS_HEADER Header, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS LoopSmbiosTables(_In_ PVOID MappedBase, _In_ ULONG TableSize, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS AllocateAndSetSmbiosString(
        _In_ PSMBIOS_HEADER Header,
        _In_ SMBIOS_STRING StringNumber,
        _In_ PCSTR NewValue,
        _In_ PEGIDA_CONTEXT Context
    );
    static VOID FreeSmbiosAllocatedStrings(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS TrackAllocatedSmbiosString(
        _In_ PEGIDA_CONTEXT Context,
        _In_ PCHAR StringPointer,
        _In_ SIZE_T StringSize,
        _In_ PSMBIOS_HEADER Header,
        _In_ SMBIOS_STRING StringNumber
    );

    // Individual table processors
    static NTSTATUS ProcessBiosInfo(_In_ PSMBIOS_BIOS_INFO BiosInfo, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessSystemInfo(_In_ PSMBIOS_SYSTEM_INFO SystemInfo, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessBaseboardInfo(_In_ PSMBIOS_BASEBOARD_INFO BaseboardInfo, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessChassisInfo(_In_ PSMBIOS_CHASSIS_INFO ChassisInfo, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessProcessorInfo(_In_ PSMBIOS_PROCESSOR_INFO ProcessorInfo, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessMemoryArrayInfo(_In_ PSMBIOS_MEMORY_ARRAY_INFO MemoryArrayInfo, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessMemoryDeviceInfo(_In_ PSMBIOS_MEMORY_DEVICE_INFO MemoryDeviceInfo, _In_ PEGIDA_CONTEXT Context);

    // Utility functions
    static VOID RandomizeString(_In_ PCHAR String, _In_ UINT32 MaxLength = 0);
    static NTSTATUS ChangeBootEnvironmentInfo(_In_ PEGIDA_CONTEXT Context);

    // Module state
    static PVOID s_NtoskrnlBase;
    static PPHYSICAL_ADDRESS s_SmbiosPhysicalAddress;
    static PULONG s_SmbiosTableLength;
    static PBOOT_ENVIRONMENT_INFORMATION s_BootEnvironmentInfo;
};