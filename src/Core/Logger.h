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
    va_list args;

    // Create prefix with function and line info
    RtlStringCbPrintfA(prefix, sizeof(prefix), "[EGIDA][%s:%lu] ", Function, Line);

    // Format the message
    va_start(args, Format);
    RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);

    // Print with prefix
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s%s\n", prefix, buffer);
#else
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(Function);
    UNREFERENCED_PARAMETER(Line);
    UNREFERENCED_PARAMETER(Format);
#endif
}

inline VOID EgidaLogInitialize() {
    EgidaLogInfo("Egida Driver v%s - Logger initialized", EGIDA_VERSION);
}

inline VOID EgidaLogCleanup() {
    EgidaLogInfo("Egida Driver - Logger cleanup");
}