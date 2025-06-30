#pragma once
#include "Definitions.h"
#include <ntimage.h>

// IOCTL Codes - Compatible with user mode app
#define IOCTL_EGIDA_START_SPOOF        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_STOP_SPOOF         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_GET_STATUS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_SET_CONFIG         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_START_GPU_SPOOF    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_STOP_GPU_SPOOF     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_GET_GPU_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Spoof flags - Compatible with user mode app
#define EGIDA_SPOOF_SMBIOS         0x00000001
#define EGIDA_SPOOF_DISK           0x00000002
#define EGIDA_SPOOF_NETWORK        0x00000004
#define EGIDA_SPOOF_GPU            0x00000008
#define EGIDA_SPOOF_ALL            0xFFFFFFFF

// SMBIOS Type definitions
#define SMBIOS_TYPE_BIOS           0
#define SMBIOS_TYPE_SYSTEM         1
#define SMBIOS_TYPE_BASEBOARD      2
#define SMBIOS_TYPE_CHASSIS        3
#define SMBIOS_TYPE_PROCESSOR      4
#define SMBIOS_TYPE_MEMORY_ARRAY   16
#define SMBIOS_TYPE_MEMORY_DEVICE  17
#define SMBIOS_TYPE_END            127

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

// Forward declarations
typedef struct _EGIDA_CONTEXT EGIDA_CONTEXT, * PEGIDA_CONTEXT;
typedef struct _SPOOF_CONFIGURATION SPOOF_CONFIGURATION, * PSPOOF_CONFIGURATION;
typedef struct _GPU_SPOOF_CONTEXT GPU_SPOOF_CONTEXT, * PGPU_SPOOF_CONTEXT;

// SMBIOS Structures
typedef UINT8 SMBIOS_STRING;

typedef struct _SMBIOS_HEADER {
    UINT8 Type;
    UINT8 Length;
    UINT16 Handle;
} SMBIOS_HEADER, * PSMBIOS_HEADER;

// BIOS Information (Type 0)
typedef struct _SMBIOS_BIOS_INFO {
    SMBIOS_HEADER Header;
    SMBIOS_STRING Vendor;
    SMBIOS_STRING BiosVersion;
    UINT16 BiosStartingAddressSegment;
    SMBIOS_STRING BiosReleaseDate;
    UINT8 BiosRomSize;
    UINT64 BiosCharacteristics;
    UINT8 BiosCharacteristicsExtensionBytes[2];
    UINT8 SystemBiosMajorRelease;
    UINT8 SystemBiosMinorRelease;
    UINT8 EmbeddedControllerFirmwareMajorRelease;
    UINT8 EmbeddedControllerFirmwareMinorRelease;
} SMBIOS_BIOS_INFO, * PSMBIOS_BIOS_INFO;

// System Information (Type 1)
typedef struct _SMBIOS_SYSTEM_INFO {
    SMBIOS_HEADER Header;
    SMBIOS_STRING Manufacturer;
    SMBIOS_STRING ProductName;
    SMBIOS_STRING Version;
    SMBIOS_STRING SerialNumber;
    UINT8 UUID[16];
    UINT8 WakeUpType;
    SMBIOS_STRING SKUNumber;
    SMBIOS_STRING Family;
} SMBIOS_SYSTEM_INFO, * PSMBIOS_SYSTEM_INFO;

// Baseboard Information (Type 2)
typedef struct _SMBIOS_BASEBOARD_INFO {
    SMBIOS_HEADER Header;
    SMBIOS_STRING Manufacturer;
    SMBIOS_STRING Product;
    SMBIOS_STRING Version;
    SMBIOS_STRING SerialNumber;
    SMBIOS_STRING AssetTag;
    UINT8 FeatureFlags;
    SMBIOS_STRING LocationInChassis;
    UINT16 ChassisHandle;
    UINT8 BoardType;
    UINT8 NumberOfContainedObjectHandles;
} SMBIOS_BASEBOARD_INFO, * PSMBIOS_BASEBOARD_INFO;

// System Enclosure (Type 3)
typedef struct _SMBIOS_CHASSIS_INFO {
    SMBIOS_HEADER Header;
    SMBIOS_STRING Manufacturer;
    UINT8 Type;
    SMBIOS_STRING Version;
    SMBIOS_STRING SerialNumber;
    SMBIOS_STRING AssetTagNumber;
    UINT8 BootupState;
    UINT8 PowerSupplyState;
    UINT8 ThermalState;
    UINT8 SecurityStatus;
} SMBIOS_CHASSIS_INFO, * PSMBIOS_CHASSIS_INFO;

// Processor Information (Type 4)
typedef struct _SMBIOS_PROCESSOR_INFO {
    SMBIOS_HEADER Header;
    SMBIOS_STRING SocketDesignation;
    UINT8 ProcessorType;
    UINT8 ProcessorFamily;
    SMBIOS_STRING ProcessorManufacturer;
    UINT64 ProcessorID;
    SMBIOS_STRING ProcessorVersion;
    UINT8 Voltage;
    UINT16 ExternalClock;
    UINT16 MaxSpeed;
    UINT16 CurrentSpeed;
    UINT8 Status;
    UINT8 ProcessorUpgrade;
    UINT16 L1CacheHandle;
    UINT16 L2CacheHandle;
    UINT16 L3CacheHandle;
    SMBIOS_STRING SerialNumber;
    SMBIOS_STRING AssetTag;
    SMBIOS_STRING PartNumber;
} SMBIOS_PROCESSOR_INFO, * PSMBIOS_PROCESSOR_INFO;

// Memory Device Type Detail (Type 17)
typedef union _MEMORY_DEVICE_TYPE_DETAIL {
    struct {
        UINT16 Reserved1 : 1;
        UINT16 Other : 1;
        UINT16 Unknown : 1;
        UINT16 FastPaged : 1;
        UINT16 StaticColumn : 1;
        UINT16 PseudoStatic : 1;
        UINT16 Rambus : 1;
        UINT16 Synchronous : 1;
        UINT16 Cmos : 1;
        UINT16 Edo : 1;
        UINT16 WindowDram : 1;
        UINT16 CacheDram : 1;
        UINT16 NonVolatile : 1;
        UINT16 Registered : 1;
        UINT16 Unbuffered : 1;
        UINT16 Reserved2 : 1;
    } Bits;
    UINT16 Uint16;
} MEMORY_DEVICE_TYPE_DETAIL;

// Memory Device Operating Mode Capability (Type 17)
typedef union _MEMORY_DEVICE_OPERATING_MODE_CAPABILITY {
    struct {
        UINT16 Reserved : 1;
        UINT16 Other : 1;
        UINT16 Unknown : 1;
        UINT16 VolatileMemory : 1;
        UINT16 ByteAccessiblePersistentMemory : 1;
        UINT16 BlockAccessiblePersistentMemory : 1;
        UINT16 Reserved2 : 10;
    } Bits;
    UINT16 Uint16;
} MEMORY_DEVICE_OPERATING_MODE_CAPABILITY;

// Memory Array Information (Type 16)
typedef struct _SMBIOS_MEMORY_ARRAY_INFO {
    SMBIOS_HEADER Header;
    UINT8 Location;
    UINT8 Use;
    UINT8 MemoryErrorCorrection;
    UINT32 MaximumCapacity;
    UINT16 MemoryErrorInformationHandle;
    UINT16 NumberOfMemoryDevices;
    UINT64 ExtendedMaximumCapacity;
} SMBIOS_MEMORY_ARRAY_INFO, * PSMBIOS_MEMORY_ARRAY_INFO;

// Memory Device Information (Type 17)
typedef struct _SMBIOS_MEMORY_DEVICE_INFO {
    SMBIOS_HEADER Header;
    UINT16 MemoryArrayHandle;
    UINT16 MemoryErrorInformationHandle;
    UINT16 TotalWidth;
    UINT16 DataWidth;
    UINT16 Size;
    UINT8 FormFactor;
    UINT8 DeviceSet;
    SMBIOS_STRING DeviceLocator;
    SMBIOS_STRING BankLocator;
    UINT8 MemoryType;
    MEMORY_DEVICE_TYPE_DETAIL TypeDetail;
    UINT16 Speed;
    SMBIOS_STRING Manufacturer;
    SMBIOS_STRING SerialNumber;
    SMBIOS_STRING AssetTag;
    SMBIOS_STRING PartNumber;
    UINT8 Attributes;
    UINT32 ExtendedSize;
    UINT16 ConfiguredMemoryClockSpeed;
    UINT16 MinimumVoltage;
    UINT16 MaximumVoltage;
    UINT16 ConfiguredVoltage;
    UINT8 MemoryTechnology;
    MEMORY_DEVICE_OPERATING_MODE_CAPABILITY MemoryOperatingModeCapability;
    SMBIOS_STRING FirmwareVersion;
    UINT16 ModuleManufacturerID;
    UINT16 ModuleProductID;
    UINT16 MemorySubsystemControllerManufacturerID;
    UINT16 MemorySubsystemControllerProductID;
    UINT64 NonVolatileSize;
    UINT64 VolatileSize;
    UINT64 CacheSize;
    UINT64 LogicalSize;
    UINT32 ExtendedSpeed;
    UINT32 ExtendedConfiguredMemorySpeed;
    UINT16 Pmic0ManufacturerID;
    UINT16 Pmic0RevisionNumber;
    UINT16 RcdManufacturerID;
    UINT16 RcdRevisionNumber;
} SMBIOS_MEMORY_DEVICE_INFO, * PSMBIOS_MEMORY_DEVICE_INFO;

// Memory tracking structures
typedef struct _SMBIOS_ALLOCATED_STRING {
    PCHAR StringPointer;
    SIZE_T StringSize;
    PSMBIOS_HEADER OwnerHeader;
    SMBIOS_STRING StringNumber;
} SMBIOS_ALLOCATED_STRING, * PSMBIOS_ALLOCATED_STRING;

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

typedef __int64(__fastcall* RaidUnitRegisterInterfaces)(PRAID_UNIT_EXTENSION Extension);
typedef NTSTATUS(__fastcall* DiskEnableDisableFailurePrediction)(PVOID Extension, BOOLEAN Enable);

typedef struct _DISK_ALLOCATED_STRING {
    PCHAR StringPointer;
    SIZE_T StringSize;
    PRAID_UNIT_EXTENSION OwnerExtension;
    ULONG StringType; // 0=Serial, 1=Model, 2=Vendor
} DISK_ALLOCATED_STRING, * PDISK_ALLOCATED_STRING;

// Disk string type constants
#define DISK_STRING_SERIAL  0
#define DISK_STRING_MODEL   1
#define DISK_STRING_VENDOR  2

// Network structures
typedef struct _NETWORK_ADAPTER_INFO {
    CHAR AdapterName[EGIDA_MAX_STRING_LENGTH];
    UINT8 OriginalMAC[EGIDA_MAX_MAC_LENGTH];
    UINT8 SpoofedMAC[EGIDA_MAX_MAC_LENGTH];
    PDEVICE_OBJECT DeviceObject;
    PDRIVER_OBJECT DriverObject;
    BOOLEAN IsActive;
} NETWORK_ADAPTER_INFO, * PNETWORK_ADAPTER_INFO;

typedef struct _DISK_INFO {
    CHAR SerialNumber[EGIDA_MAX_SERIAL_LENGTH];
    CHAR Model[EGIDA_MAX_STRING_LENGTH];
    CHAR Vendor[EGIDA_MAX_STRING_LENGTH];
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN IsModified;
} DISK_INFO, * PDISK_INFO;

// Boot Environment Information
typedef struct _BOOT_ENVIRONMENT_INFORMATION {
    GUID BootIdentifier;
    UINT32 FirmwareType;
    UINT64 BootFlags;
} BOOT_ENVIRONMENT_INFORMATION, * PBOOT_ENVIRONMENT_INFORMATION;

// GPU structures
typedef struct _GPU_DEVICE_INFO {
    CHAR OriginalDescription[EGIDA_MAX_STRING_LENGTH];
    CHAR SpoofedDescription[EGIDA_MAX_STRING_LENGTH];
    CHAR OriginalPNPDeviceID[EGIDA_MAX_STRING_LENGTH];
    CHAR SpoofedPNPDeviceID[EGIDA_MAX_STRING_LENGTH];
    PDEVICE_OBJECT DeviceObject;
    PDRIVER_OBJECT DriverObject;
    PVOID RegistryPath;
    BOOLEAN IsModified;
} GPU_DEVICE_INFO, * PGPU_DEVICE_INFO;

typedef struct _GPU_REGISTRY_VALUE {
    PWSTR ValueName;
    PVOID OriginalData;
    PVOID SpoofedData;
    ULONG DataSize;
    ULONG ValueType;
    BOOLEAN IsAllocated;
} GPU_REGISTRY_VALUE, * PGPU_REGISTRY_VALUE;

typedef struct _GPU_SPOOF_CONTEXT {
    PGPU_DEVICE_INFO DeviceList;
    ULONG DeviceCount;
    PGPU_REGISTRY_VALUE AllocatedValues;
    ULONG AllocatedValueCount;
    BOOLEAN IsActive;
} GPU_SPOOF_CONTEXT, * PGPU_SPOOF_CONTEXT;

// Configuration structures
typedef struct _RANDOMIZE_CONFIG {
    BOOLEAN RandomizeStrings;
    BOOLEAN RandomizeSerials;
    BOOLEAN RandomizeMAC;
    BOOLEAN RandomizeUUID;
    UINT32 MinStringLength;
    UINT32 MaxStringLength;
    UINT32 RandomSeed;
} RANDOMIZE_CONFIG, * PRANDOMIZE_CONFIG;

typedef struct _SPOOF_CONFIGURATION {
    UINT32 Flags;
    RANDOMIZE_CONFIG RandomConfig;
    BOOLEAN EnableSmbiosSpoof;
    BOOLEAN EnableDiskSpoof;
    BOOLEAN EnableNetworkSpoof;
    BOOLEAN EnableBootInfoSpoof;
} SPOOF_CONFIGURATION, * PSPOOF_CONFIGURATION;

// Main Egida Context
typedef struct _EGIDA_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicLink;
    SPOOF_CONFIGURATION Config;

    // Module specific data
    PVOID SmbiosTableBase;
    ULONG SmbiosTableSize;
    PPHYSICAL_ADDRESS SmbiosPhysicalAddress;

    // Network adapters list
    PNETWORK_ADAPTER_INFO NetworkAdapters;
    ULONG NetworkAdapterCount;

    // Disk information
    PDISK_INFO DiskInfo;
    ULONG DiskCount;

    // Boot information
    PBOOT_ENVIRONMENT_INFORMATION BootInfo;

    // GPU information
    PGPU_SPOOF_CONTEXT GpuContext;

    // Memory tracking for allocated strings
    PSMBIOS_ALLOCATED_STRING SmbiosAllocatedStrings;
    ULONG SmbiosAllocatedStringCount;

    PDISK_ALLOCATED_STRING DiskAllocatedStrings;
    ULONG DiskAllocatedStringCount;

    // Status flags
    BOOLEAN IsInitialized;
    BOOLEAN IsSpoofingActive;

    // Synchronization
    KSPIN_LOCK SpinLock;
    KIRQL OldIrql;

} EGIDA_CONTEXT, * PEGIDA_CONTEXT;

// Status Structure for IOCTL
typedef struct _EGIDA_STATUS {
    BOOLEAN IsActive;
    UINT32 SpoofedComponents;
    UINT32 LastError;
    CHAR Version[32];
    UINT32 AllocatedStringsCount;
    UINT32 SmbiosAllocatedCount;
    UINT32 DiskAllocatedCount;
    UINT32 GpuDevicesCount;
} EGIDA_STATUS, * PEGIDA_STATUS;

// System information structures
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemInformationClassMin = 0,
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemNotImplemented1 = 4,
    SystemProcessInformation = 5,
    SystemProcessesAndThreadsInformation = 5,
    SystemCallCountInfoInformation = 6,
    SystemCallCounts = 6,
    SystemDeviceInformation = 7,
    SystemConfigurationInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemProcessorTimes = 8,
    SystemFlagsInformation = 9,
    SystemGlobalFlag = 9,
    SystemCallTimeInformation = 10,
    SystemNotImplemented2 = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemLockInformation = 12,
    SystemStackTraceInformation = 13,
    SystemNotImplemented3 = 13,
    SystemPagedPoolInformation = 14,
    SystemNotImplemented4 = 14,
    SystemNonPagedPoolInformation = 15,
    SystemNotImplemented5 = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemPagefileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemInstructionEmulationCounts = 19,
    SystemVdmBopInformation = 20,
    SystemInvalidInfoClass1 = 20,
    SystemFileCacheInformation = 21,
    SystemCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemProcessorStatistics = 23,
    SystemDpcBehaviourInformation = 24,
    SystemDpcInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemNotImplemented6 = 25,
    SystemLoadImage = 26,
    SystemUnloadImage = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemTimeAdjustment = 28,
    SystemSummaryMemoryInformation = 29,
    SystemNotImplemented7 = 29,
    SystemNextEventIdInformation = 30,
    SystemNotImplemented8 = 30,
    SystemEventIdsInformation = 31,
    SystemNotImplemented9 = 31,
    SystemCrashDumpInformation = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemLoadAndCallImage = 38,
    SystemPrioritySeparation = 39,
    SystemPlugPlayBusInformation = 40,
    SystemNotImplemented10 = 40,
    SystemDockInformation = 41,
    SystemNotImplemented11 = 41,
    SystemInvalidInfoClass2 = 42,
    SystemProcessorSpeedInformation = 43,
    SystemInvalidInfoClass3 = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemSetTimeSlipEvent = 46,
    SystemCreateSession = 47,
    SystemDeleteSession = 48,
    SystemInvalidInfoClass4 = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemAddVerifier = 52,
    SystemSessionProcessesInformation = 53,
    SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE
{
    ULONG_PTR Reserved[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG_PTR ulModuleCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

extern "C"
{
    NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
    NTSTATUS ObReferenceObjectByName(PUNICODE_STRING objectName, ULONG attributes, PACCESS_STATE accessState, ACCESS_MASK desiredAccess, POBJECT_TYPE objectType, KPROCESSOR_MODE accessMode, PVOID parseContext, PVOID* object);

    NTSYSAPI NTSTATUS RtlWriteRegistryValue(
        _In_           ULONG  RelativeTo,
        _In_           PCWSTR Path,
        _In_           PCWSTR ValueName,
        _In_           ULONG  ValueType,
        _In_           PVOID  ValueData,
        _In_           ULONG  ValueLength
    );
}