#include "EgidaUtils.h"
#include "../Core/Logger.h"
#include <ntimage.h>

PVOID EgidaUtils::GetModuleBase(_In_ PCSTR ModuleName) {
    EGIDA_PAGED_CODE();

    if (!ModuleName) {
        EgidaLogError("Invalid module name");
        return nullptr;
    }

    PSYSTEM_MODULE_INFORMATION moduleList = nullptr;
    ULONG moduleListSize = 0;

    NTSTATUS status = GetSystemModules(&moduleList, &moduleListSize);
    if (!NT_SUCCESS(status)) {
        EgidaLogError("Failed to get system modules: 0x%08X", status);
        return nullptr;
    }

    PVOID moduleBase = nullptr;

    for (ULONG i = 0; i < moduleList->ulModuleCount; i++) {
        PSYSTEM_MODULE module = &moduleList->Modules[i];
        PCHAR imageName = ToLowerString(module->ImageName);

        if (strstr(imageName, ModuleName)) {
            moduleBase = module->Base;
            EgidaLogDebug("Found module %s at 0x%p", ModuleName, moduleBase);
            break;
        }
    }

    if (moduleList) {
        EGIDA_FREE(moduleList);
    }

    return moduleBase;
}

PVOID EgidaUtils::FindPatternInModule(_In_ PVOID ModuleBase, _In_ PCSTR Pattern, _In_ PCSTR Mask) {
    if (!ModuleBase || !Pattern || !Mask) {
        return nullptr;
    }

    __try {
        PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(ModuleBase);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return nullptr;
        }

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            static_cast<PUCHAR>(ModuleBase) + dosHeader->e_lfanew
            );

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

        for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER section = &sections[i];

            // Search in .text and PAGE sections
            if ((memcmp(section->Name, ".text", 5) == 0) ||
                (memcmp(section->Name, "PAGE", 4) == 0)) {

                PVOID sectionBase = static_cast<PUCHAR>(ModuleBase) + section->VirtualAddress;
                PVOID result = FindPattern(sectionBase, section->Misc.VirtualSize, Pattern, Mask);

                if (result) {
                    return result;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogError("Exception while scanning module");
        return nullptr;
    }

    return nullptr;
}

PVOID EgidaUtils::FindPattern(_In_ PVOID BaseAddress, _In_ SIZE_T Size, _In_ PCSTR Pattern, _In_ PCSTR Mask) {
    if (!BaseAddress || !Pattern || !Mask) {
        return nullptr;
    }

    SIZE_T maskLength = strlen(Mask);
    if (Size < maskLength) {
        return nullptr;
    }

    __try {
        PUCHAR searchBase = static_cast<PUCHAR>(BaseAddress);
        SIZE_T searchSize = Size - maskLength;

        for (SIZE_T i = 0; i <= searchSize; i++) {
            if (CheckMask(reinterpret_cast<PCSTR>(&searchBase[i]), Pattern, Mask)) {
                return &searchBase[i];
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogError("Exception during pattern search");
        return nullptr;
    }

    return nullptr;
}

BOOLEAN EgidaUtils::CheckMask(_In_ PCSTR Base, _In_ PCSTR Pattern, _In_ PCSTR Mask) {
    for (; *Mask; ++Base, ++Pattern, ++Mask) {
        if (*Mask == 'x' && *Base != *Pattern) {
            return FALSE;
        }
    }
    return TRUE;
}

PCHAR EgidaUtils::GetSmbiosString(_In_ PSMBIOS_HEADER Header, _In_ SMBIOS_STRING StringNumber) {
    if (!Header || !StringNumber) {
        return nullptr;
    }

    PCSTR start = reinterpret_cast<PCSTR>(Header) + Header->Length;

    if (*start == 0) {
        return nullptr;
    }

    // Navigate to the requested string
    while (--StringNumber) {
        start += strlen(start) + 1;
    }

    return const_cast<PCHAR>(start);
}

NTSTATUS EgidaUtils::GetSystemModules(_Out_ PSYSTEM_MODULE_INFORMATION* ModuleList, _Out_ PULONG ModuleListSize) {
    if (!ModuleList || !ModuleListSize) {
        return STATUS_INVALID_PARAMETER;
    }

    *ModuleList = nullptr;
    *ModuleListSize = 0;

    // Get required size
    ULONG requiredSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(
        SystemModuleInformation,
        nullptr,
        0,
        &requiredSize
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    // Allocate buffer
    PSYSTEM_MODULE_INFORMATION moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(
        EGIDA_ALLOC_PAGED(requiredSize)
        );

    if (!moduleList) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Get actual data
    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        moduleList,
        requiredSize,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        EGIDA_FREE(moduleList);
        return status;
    }

    *ModuleList = moduleList;
    *ModuleListSize = requiredSize;

    return STATUS_SUCCESS;
}

BOOLEAN EgidaUtils::IsValidKernelPointer(_In_ PVOID Pointer) {
    if (!Pointer) {
        return FALSE;
    }

    if (!MmIsAddressValid(Pointer)) {
        return FALSE;
    }

    ULONG_PTR address = reinterpret_cast<ULONG_PTR>(Pointer);
    return address >= reinterpret_cast<ULONG_PTR>(MmSystemRangeStart);
}

PCHAR EgidaUtils::ToLowerString(_In_ PCHAR String) {
    if (!String) return nullptr;

    for (PCHAR p = String; *p; ++p) {
        if (*p >= 'A' && *p <= 'Z') {
            *p = *p + ('a' - 'A');
        }
    }
    return String;
}

NTSTATUS EgidaUtils::SafeCopyString(_Out_ PCHAR Destination, _In_ PCSTR Source, _In_ SIZE_T DestinationSize) {
    if (!Destination || !Source || DestinationSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    return RtlStringCbCopyA(Destination, DestinationSize, Source);
}

NTSTATUS EgidaUtils::WriteRegistryValue(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueSize
) {
    return RtlWriteRegistryValue(
        RTL_REGISTRY_ABSOLUTE,
        KeyPath,
        ValueName,
        ValueType,
        ValueData,
        ValueSize
    );
}