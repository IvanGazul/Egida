#pragma once
#include "Definitions.h"
#include <ntimage.h>

// Forward declarations
typedef struct _EGIDA_CONTEXT EGIDA_CONTEXT, * PEGIDA_CONTEXT;

// Profile data structures for receiving from UserMode
#pragma pack(push, 1)
typedef struct _SMBIOS_PROFILE_DATA {
    // BIOS Information (Type 0)
    CHAR BiosVendor[EGIDA_MAX_STRING_LENGTH];
    CHAR BiosVersion[EGIDA_MAX_STRING_LENGTH];
    CHAR BiosReleaseDate[EGIDA_MAX_STRING_LENGTH];

    // System Information (Type 1)
    CHAR SystemManufacturer[EGIDA_MAX_STRING_LENGTH];
    CHAR SystemProductName[EGIDA_MAX_STRING_LENGTH];
    CHAR SystemVersion[EGIDA_MAX_STRING_LENGTH];
    CHAR SystemSerialNumber[EGIDA_MAX_SERIAL_LENGTH];
    CHAR SystemSKUNumber[EGIDA_MAX_STRING_LENGTH];
    CHAR SystemFamily[EGIDA_MAX_STRING_LENGTH];
    UINT8 SystemUUID[16];

    // Baseboard Information (Type 2)
    CHAR BaseboardManufacturer[EGIDA_MAX_STRING_LENGTH];
    CHAR BaseboardProduct[EGIDA_MAX_STRING_LENGTH];
    CHAR BaseboardVersion[EGIDA_MAX_STRING_LENGTH];
    CHAR BaseboardSerialNumber[EGIDA_MAX_SERIAL_LENGTH];
    CHAR BaseboardAssetTag[EGIDA_MAX_STRING_LENGTH];
    CHAR BaseboardLocationInChassis[EGIDA_MAX_STRING_LENGTH];

    // Chassis Information (Type 3)
    CHAR ChassisManufacturer[EGIDA_MAX_STRING_LENGTH];
    CHAR ChassisVersion[EGIDA_MAX_STRING_LENGTH];
    CHAR ChassisSerialNumber[EGIDA_MAX_SERIAL_LENGTH];
    CHAR ChassisAssetTag[EGIDA_MAX_STRING_LENGTH];

    // Processor Information (Type 4)
    CHAR ProcessorSocketDesignation[EGIDA_MAX_STRING_LENGTH];
    CHAR ProcessorManufacturer[EGIDA_MAX_STRING_LENGTH];
    CHAR ProcessorVersion[EGIDA_MAX_STRING_LENGTH];
    CHAR ProcessorSerialNumber[EGIDA_MAX_SERIAL_LENGTH];
    CHAR ProcessorAssetTag[EGIDA_MAX_STRING_LENGTH];
    CHAR ProcessorPartNumber[EGIDA_MAX_STRING_LENGTH];
    UINT64 ProcessorID;

    // Memory Device Information (Type 17)
    CHAR MemoryDeviceLocator[EGIDA_MAX_STRING_LENGTH];
    CHAR MemoryBankLocator[EGIDA_MAX_STRING_LENGTH];
    CHAR MemoryManufacturer[EGIDA_MAX_STRING_LENGTH];
    CHAR MemorySerialNumber[EGIDA_MAX_SERIAL_LENGTH];
    CHAR MemoryAssetTag[EGIDA_MAX_STRING_LENGTH];
    CHAR MemoryPartNumber[EGIDA_MAX_STRING_LENGTH];
    CHAR MemoryFirmwareVersion[EGIDA_MAX_STRING_LENGTH];
    UINT16 MemoryModuleManufacturerID;
    UINT16 MemoryModuleProductID;
    UINT16 MemorySubsystemControllerManufacturerID;
    UINT16 MemorySubsystemControllerProductID;
    UINT16 MemoryPmic0ManufacturerID;
    UINT16 MemoryPmic0RevisionNumber;
    UINT16 MemoryRcdManufacturerID;
    UINT16 MemoryRcdRevisionNumber;

    // Boot Environment
    UINT8 BootIdentifier[16];  // GUID as bytes

    // Disk Serial
    CHAR DiskSerials[10][EGIDA_MAX_SERIAL_LENGTH]; // Support up to 10 disks
    UINT32 DiskCount;

    // Network MAC addresses
    UINT8 NetworkMACs[10][6]; // Support up to 10 network adapters
    UINT32 NetworkAdapterCount;

    // Padding for alignment
    UINT8 Reserved[4];
} SMBIOS_PROFILE_DATA, * PSMBIOS_PROFILE_DATA;
#pragma pack(pop)

// IOCTL codes for communication
#define EGIDA_IOCTL_BASE 0x800
#define IOCTL_EGIDA_SET_PROFILE CTL_CODE(FILE_DEVICE_UNKNOWN, EGIDA_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_EXECUTE_SPOOF CTL_CODE(FILE_DEVICE_UNKNOWN, EGIDA_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EGIDA_STOP_SPOOF CTL_CODE(FILE_DEVICE_UNKNOWN, EGIDA_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
typedef struct _SMBIOS_MEMORY_DEVICE_INFO 
{
	SMBIOS_HEADER Header;
    USHORT	MemArrayHandle;
    USHORT	MemErrorInfoHandle;
    USHORT	TotalWidth;
    USHORT	DataWidth;
    USHORT	Size;
    SMBIOS_STRING	FormFactor;
    SMBIOS_STRING	DeviceSet;
    SMBIOS_STRING	DeviceLocator;
    SMBIOS_STRING	BankLocator;
    SMBIOS_STRING	MemoryType;
    USHORT	TypeDetail;
    USHORT	Speed;
    SMBIOS_STRING   Manufacturer;
    SMBIOS_STRING   SerialNumber;
    SMBIOS_STRING   AssetTagNumber;
    SMBIOS_STRING   PartNumber;
} SMBIOS_MEMORY_DEVICE_INFO, * PSMBIOS_MEMORY_DEVICE_INFO;

// Boot Environment Information
typedef struct _BOOT_ENVIRONMENT_INFORMATION {
    GUID BootIdentifier;
    UINT32 FirmwareType;
    UINT64 BootFlags;
} BOOT_ENVIRONMENT_INFORMATION, * PBOOT_ENVIRONMENT_INFORMATION;

// Main Egida Context
typedef struct _EGIDA_CONTEXT {
    // Module specific data
    PVOID SmbiosTableBase;
    ULONG SmbiosTableSize;
    PPHYSICAL_ADDRESS SmbiosPhysicalAddress;

    // Boot information
    PBOOT_ENVIRONMENT_INFORMATION BootInfo;

    // Profile data from UserMode
    PSMBIOS_PROFILE_DATA ProfileData;

    // Status flags
    BOOLEAN IsInitialized;
    BOOLEAN IsSpoofingActive;
    BOOLEAN HasProfile;

    // Device object for communication
    PDEVICE_OBJECT DeviceObject;

    // Synchronization
    KSPIN_LOCK SpinLock;
    KIRQL OldIrql;

} EGIDA_CONTEXT, * PEGIDA_CONTEXT;


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