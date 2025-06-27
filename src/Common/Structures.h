#pragma once
#include "Definitions.h"
#include <ntimage.h>

// Forward declarations
typedef struct _EGIDA_CONTEXT EGIDA_CONTEXT, * PEGIDA_CONTEXT;
typedef struct _SPOOF_CONFIGURATION SPOOF_CONFIGURATION, * PSPOOF_CONFIGURATION;

// SMBIOS Structures
typedef struct _SMBIOS_HEADER {
    UINT8 Type;
    UINT8 Length;
    UINT16 Handle;
} SMBIOS_HEADER, * PSMBIOS_HEADER;

typedef UINT8 SMBIOS_STRING;

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
    UINT8 Location;                             // Memory array location
    UINT8 Use;                                  // Memory array use
    UINT8 MemoryErrorCorrection;                // Memory error correction
    UINT32 MaximumCapacity;                     // Maximum capacity in KB
    UINT16 MemoryErrorInformationHandle;        // Memory error information handle
    UINT16 NumberOfMemoryDevices;               // Number of memory devices
    UINT64 ExtendedMaximumCapacity;             // Extended maximum capacity in bytes (SMBIOS 2.7+)
} SMBIOS_MEMORY_ARRAY_INFO, * PSMBIOS_MEMORY_ARRAY_INFO;

// Memory Device Information (Type 17)
typedef struct _SMBIOS_MEMORY_DEVICE_INFO {
    SMBIOS_HEADER Header;
    UINT16 MemoryArrayHandle;                   // Handle of the memory array
    UINT16 MemoryErrorInformationHandle;        // Handle of memory error information
    UINT16 TotalWidth;                          // Total width in bits
    UINT16 DataWidth;                           // Data width in bits
    UINT16 Size;                                // Size in MB
    UINT8 FormFactor;                           // Form factor
    UINT8 DeviceSet;                            // Device set
    SMBIOS_STRING DeviceLocator;                // Device locator string
    SMBIOS_STRING BankLocator;                  // Bank locator string
    UINT8 MemoryType;                           // Memory type
    MEMORY_DEVICE_TYPE_DETAIL TypeDetail;      // Type detail
    UINT16 Speed;                               // Speed in MHz
    SMBIOS_STRING Manufacturer;                 // Manufacturer string
    SMBIOS_STRING SerialNumber;                 // Serial number string
    SMBIOS_STRING AssetTag;                     // Asset tag string
    SMBIOS_STRING PartNumber;                   // Part number string

    // SMBIOS 2.6+
    UINT8 Attributes;                           // Attributes

    // SMBIOS 2.7+
    UINT32 ExtendedSize;                        // Extended size
    UINT16 ConfiguredMemoryClockSpeed;          // Configured memory clock speed

    // SMBIOS 2.8+
    UINT16 MinimumVoltage;                      // Minimum voltage in mV
    UINT16 MaximumVoltage;                      // Maximum voltage in mV
    UINT16 ConfiguredVoltage;                   // Configured voltage in mV

    // SMBIOS 3.2+
    UINT8 MemoryTechnology;                     // Memory technology
    MEMORY_DEVICE_OPERATING_MODE_CAPABILITY MemoryOperatingModeCapability; // Operating mode capability
    SMBIOS_STRING FirmwareVersion;              // Firmware version string
    UINT16 ModuleManufacturerID;                // Module manufacturer ID
    UINT16 ModuleProductID;                     // Module product ID
    UINT16 MemorySubsystemControllerManufacturerID; // Memory subsystem controller manufacturer ID
    UINT16 MemorySubsystemControllerProductID;  // Memory subsystem controller product ID
    UINT64 NonVolatileSize;                     // Non-volatile size in bytes
    UINT64 VolatileSize;                        // Volatile size in bytes
    UINT64 CacheSize;                           // Cache size in bytes
    UINT64 LogicalSize;                         // Logical size in bytes

    // SMBIOS 3.3+
    UINT32 ExtendedSpeed;                       // Extended speed
    UINT32 ExtendedConfiguredMemorySpeed;       // Extended configured memory speed

    // SMBIOS 3.7+
    UINT16 Pmic0ManufacturerID;                 // PMIC0 manufacturer ID
    UINT16 Pmic0RevisionNumber;                 // PMIC0 revision number
    UINT16 RcdManufacturerID;                   // RCD manufacturer ID
    UINT16 RcdRevisionNumber;                   // RCD revision number
} SMBIOS_MEMORY_DEVICE_INFO, * PSMBIOS_MEMORY_DEVICE_INFO;


// Network Card Structure
typedef struct _NETWORK_ADAPTER_INFO {
    CHAR AdapterName[EGIDA_MAX_STRING_LENGTH];
    UINT8 OriginalMAC[EGIDA_MAX_MAC_LENGTH];
    UINT8 SpoofedMAC[EGIDA_MAX_MAC_LENGTH];
    PDEVICE_OBJECT DeviceObject;
    PDRIVER_OBJECT DriverObject;
    BOOLEAN IsActive;
} NETWORK_ADAPTER_INFO, * PNETWORK_ADAPTER_INFO;

// Disk Information Structure
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

// Randomization Configuration
typedef struct _RANDOMIZE_CONFIG {
    BOOLEAN RandomizeStrings;
    BOOLEAN RandomizeSerials;
    BOOLEAN RandomizeMAC;
    BOOLEAN RandomizeUUID;
    UINT32 MinStringLength;
    UINT32 MaxStringLength;
    UINT32 RandomSeed;
} RANDOMIZE_CONFIG, * PRANDOMIZE_CONFIG;

// Main Spoof Configuration
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

    // Status flags
    BOOLEAN IsInitialized;
    BOOLEAN IsSpoofingActive;

    // Synchronization
    KSPIN_LOCK SpinLock;
    KIRQL OldIrql;

} EGIDA_CONTEXT, * PEGIDA_CONTEXT;

// IOCTL Codes
#define IOCTL_EGIDA_START_SPOOF    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_STOP_SPOOF     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_GET_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_SET_CONFIG     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Status Structure for IOCTL
typedef struct _EGIDA_STATUS {
    BOOLEAN IsActive;
    UINT32 SpoofedComponents;
    UINT32 LastError;
    CHAR Version[32];
} EGIDA_STATUS, * PEGIDA_STATUS;

// ------------------------------------------------
// ntoskrnl.exe
// ------------------------------------------------

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
        _In_		   PVOID  ValueData,
        _In_           ULONG  ValueLength
    );

}

