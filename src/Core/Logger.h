#pragma once
#include "../Common/Definitions.h"

// Logging macros
#if EGIDA_ENABLE_LOGGING

#define EgidaLog(level, format, ...) \
    EgidaLogPrint(level, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)

#define EgidaLogError(format, ...) \
    EgidaLog(EGIDA_LOG_ERROR, "[ERROR] " format, ##__VA_ARGS__)

#define EgidaLogWarning(format, ...) \
    EgidaLog(EGIDA_LOG_WARNING, "[WARNING] " format, ##__VA_ARGS__)

#define EgidaLogInfo(format, ...) \
    EgidaLog(EGIDA_LOG_INFO, "[INFO] " format, ##__VA_ARGS__)

#define EgidaLogDebug(format, ...) \
    EgidaLog(EGIDA_LOG_DEBUG, "[DEBUG] " format, ##__VA_ARGS__)

#else

#define EgidaLogError(format, ...)
#define EgidaLogWarning(format, ...)
#define EgidaLogInfo(format, ...)
#define EgidaLogDebug(format, ...)

#endif

// Global variables for file logging
static HANDLE g_LogFileHandle = NULL;

// Function declarations
VOID EgidaLogPrint(
    _In_ ULONG Level,
    _In_ PCSTR Function,
    _In_ ULONG Line,
    _In_ PCSTR Format,
    ...
);

VOID EgidaLogInitialize();
VOID EgidaLogCleanup();

// Implementation

inline VOID EgidaLogPrint(
    _In_ ULONG Level,
    _In_ PCSTR Function,
    _In_ ULONG Line,
    _In_ PCSTR Format,
    ...
) {
#if EGIDA_ENABLE_LOGGING
    CHAR buffer[512];
    CHAR prefix[128];
    CHAR finalMessage[640];
    va_list args;
    LARGE_INTEGER systemTime;
    TIME_FIELDS timeFields;
    KIRQL currentIrql;

    // Get current time
    KeQuerySystemTime(&systemTime);
    RtlTimeToTimeFields(&systemTime, &timeFields);

    // Create prefix with timestamp, function and line info
    RtlStringCbPrintfA(prefix, sizeof(prefix),
        "[%02d:%02d:%02d.%03d][EGIDA][%s:%lu] ",
        timeFields.Hour, timeFields.Minute, timeFields.Second,
        timeFields.Milliseconds, Function, Line);

    // Format the message
    va_start(args, Format);
    RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);

    // Combine prefix and message
    RtlStringCbPrintfA(finalMessage, sizeof(finalMessage), "%s%s\n", prefix, buffer);

    // Always print to debug output (WinDbg) - safe at any IRQL
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", finalMessage);

    // Write to file only if IRQL is low enough (PASSIVE_LEVEL or APC_LEVEL)
    currentIrql = KeGetCurrentIrql();
    if (g_LogFileHandle != NULL && currentIrql <= APC_LEVEL) {
        UNICODE_STRING fileName;
        OBJECT_ATTRIBUTES objAttributes;
        IO_STATUS_BLOCK ioStatusBlock;
        HANDLE tempFileHandle;
        NTSTATUS status;
        LARGE_INTEGER byteOffset;
        ULONG messageLength = (ULONG)strlen(finalMessage);

        // Open file for each write to avoid locking issues
        RtlInitUnicodeString(&fileName, L"\\??\\C:\\egida.log");

        InitializeObjectAttributes(
            &objAttributes,
            &fileName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL
        );

        status = ZwCreateFile(
            &tempFileHandle,
            GENERIC_WRITE | SYNCHRONIZE,
            &objAttributes,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (NT_SUCCESS(status)) {
            // Seek to end of file
            byteOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;
            byteOffset.HighPart = -1;

            ZwWriteFile(
                tempFileHandle,
                NULL,
                NULL,
                NULL,
                &ioStatusBlock,
                (PVOID)finalMessage,
                messageLength,
                &byteOffset,
                NULL
            );

            // Close immediately after writing
            ZwClose(tempFileHandle);
        }
    }

#else
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(Function);
    UNREFERENCED_PARAMETER(Line);
    UNREFERENCED_PARAMETER(Format);
#endif
}

inline VOID EgidaLogInitialize() {
#if EGIDA_ENABLE_LOGGING
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;

    // Create log file
    RtlInitUnicodeString(&fileName, L"\\??\\C:\\egida.log");

    InitializeObjectAttributes(
        &objAttributes,
        &fileName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    status = ZwCreateFile(
        &g_LogFileHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,  // Allow other processes to read/write
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        g_LogFileHandle = NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[EGIDA] Failed to create log file: 0x%X - logging to debug output only\n", status);
    }

    EgidaLogInfo("Egida Driver v%s - Logger initialized", EGIDA_VERSION);
#endif
}

inline VOID EgidaLogCleanup() {
#if EGIDA_ENABLE_LOGGING
    EgidaLogInfo("Egida Driver - Logger cleanup");

    // No need to close g_LogFileHandle since we're not keeping it open
    g_LogFileHandle = NULL;
#endif
}