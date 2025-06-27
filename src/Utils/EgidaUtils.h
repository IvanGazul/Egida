#pragma once
#include "../Common/Structures.h"

class EgidaUtils {
public:
    // Memory utilities
    static PVOID GetModuleBase(_In_ PCSTR ModuleName);
    static PVOID FindPatternInModule(_In_ PVOID ModuleBase, _In_ PCSTR Pattern, _In_ PCSTR Mask);
    static PVOID FindPattern(_In_ PVOID BaseAddress, _In_ SIZE_T Size, _In_ PCSTR Pattern, _In_ PCSTR Mask);

    // Address translation utilities
    template<typename T>
    static T TranslateAddress(_In_ PVOID Address, _In_ INT32 Offset) {
        if (!Address) return nullptr;
        PUCHAR addr = static_cast<PUCHAR>(Address);
        INT32 relativeOffset = *reinterpret_cast<PINT32>(addr + Offset - 4);
        return reinterpret_cast<T>(addr + Offset + relativeOffset);
    }

    // Template for reinterpreting addresses with offset
    template<typename T>
    static T reinterpret(_In_ PVOID Address, _In_ INT32 Offset) {
        if (!Address) return nullptr;
        return reinterpret_cast<T>(static_cast<PUCHAR>(Address) + Offset);
    }

    // String utilities
    static PCHAR GetSmbiosString(_In_ PSMBIOS_HEADER Header, _In_ SMBIOS_STRING StringNumber);
    static NTSTATUS SafeCopyString(_Out_ PCHAR Destination, _In_ PCSTR Source, _In_ SIZE_T DestinationSize);
    static BOOLEAN IsValidKernelPointer(_In_ PVOID Pointer);

    // System information utilities
    static NTSTATUS GetSystemModules(_Out_ PSYSTEM_MODULE_INFORMATION* ModuleList, _Out_ PULONG ModuleListSize);

    // Registry utilities
    static NTSTATUS WriteRegistryValue(
        _In_ PCWSTR KeyPath,
        _In_ PCWSTR ValueName,
        _In_ ULONG ValueType,
        _In_ PVOID ValueData,
        _In_ ULONG ValueSize
    );

    // Verification utilities
    static BOOLEAN CheckMask(_In_ PCSTR Base, _In_ PCSTR Pattern, _In_ PCSTR Mask);

private:
    static PCHAR ToLowerString(_In_ PCHAR String);
};