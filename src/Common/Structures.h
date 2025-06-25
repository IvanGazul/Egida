#pragma once
#include "Definitions.h"

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