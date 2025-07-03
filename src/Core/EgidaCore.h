#pragma once
#include "../Common/Structures.h"
#include "Logger.h"

// Core module interface
class EgidaCore {
public:
    static NTSTATUS Initialize(_Out_ PEGIDA_CONTEXT* Context);
    static NTSTATUS Cleanup(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ExecuteAllSpoofs(_In_ PEGIDA_CONTEXT Context);

private:
    static NTSTATUS InitializeModules(_In_ PEGIDA_CONTEXT Context);
    static VOID CleanupModules(_In_ PEGIDA_CONTEXT Context);
};

// Global context access
extern PEGIDA_CONTEXT g_EgidaGlobalContext;

// Driver entry points
extern "C" {
    NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
    VOID EgidaUnloadDriver(_In_ PDRIVER_OBJECT DriverObject);
}