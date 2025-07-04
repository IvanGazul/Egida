#pragma once

// Exclude problematic headers and define kernel mode
#define KERNEL_MODE 1
#define POOL_NX_OPTIN 1

// Essential kernel headers only
extern "C" {
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntddk.h>
#include <wdf.h>
}

// Disable C++ features not available in kernel
#ifdef __cplusplus
extern "C" {
#endif

    // Driver Information
#define EGIDA_POOL_TAG 'agdE'
#define EGIDA_VERSION "1.0.0"

// Device names
#define DEVICE_NAME L"\\Device\\Egida"
#define SYMBOLIC_LINK L"\\DosDevices\\Egida"

// Status codes
#define EGIDA_SUCCESS                STATUS_SUCCESS
#define EGIDA_FAILED                 STATUS_UNSUCCESSFUL
#define EGIDA_NOT_FOUND              STATUS_NOT_FOUND
#define EGIDA_INSUFFICIENT_RESOURCES STATUS_INSUFFICIENT_RESOURCES

// Debug levels
#define EGIDA_LOG_ERROR     0x01
#define EGIDA_LOG_WARNING   0x02
#define EGIDA_LOG_INFO      0x04
#define EGIDA_LOG_DEBUG     0x08

// Compilation flags
#ifndef EGIDA_ENABLE_LOGGING
#define EGIDA_ENABLE_LOGGING 1
#endif

// Function attributes
#define EGIDA_PAGED_CODE() PAGED_CODE()
#define EGIDA_NON_PAGED

// Memory allocation macros
#define EGIDA_ALLOC_PAGED(size) \
    ExAllocatePoolWithTag(PagedPool, (size), EGIDA_POOL_TAG)

#define EGIDA_ALLOC_NON_PAGED(size) \
    ExAllocatePoolWithTag(NonPagedPool, (size), EGIDA_POOL_TAG)

#define EGIDA_FREE(ptr) \
    do { if (ptr) { ExFreePoolWithTag((ptr), EGIDA_POOL_TAG); (ptr) = NULL; } } while(0)

// String length limits
#define EGIDA_MAX_STRING_LENGTH     256
#define EGIDA_MAX_SERIAL_LENGTH     64
#define EGIDA_MAX_MAC_LENGTH        6

// Spoof configuration flags
#define EGIDA_SPOOF_SMBIOS         0x00000001
#define EGIDA_SPOOF_DISK           0x00000002
#define EGIDA_SPOOF_NETWORK        0x00000004
#define EGIDA_SPOOF_ALL            0xFFFFFFFF

// Basic types for kernel mode
    typedef unsigned char   UINT8;
    typedef unsigned short  UINT16;
    typedef unsigned __int64 UINT64;

    // Missing definitions
#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

#ifdef __cplusplus
}
#endif