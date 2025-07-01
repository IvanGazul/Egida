#include "NetworkSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Utils/Randomizer.h"
#include "../Core/Logger.h"
#include "../Common/Globals.h"

// Static members
PVOID NetworkSpoofer::s_NdisBase = nullptr;
PVOID* NetworkSpoofer::s_NdisGlobalFilterList = nullptr;
PVOID NetworkSpoofer::s_NdisDummyIrpHandler = nullptr;
PVOID NetworkSpoofer::s_NdisMiniDriverList = nullptr;
DWORD NetworkSpoofer::s_Seed = 0x7899;

NTSTATUS NetworkSpoofer::Initialize(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Initializing Network Spoofer...");

    // Get ndis.sys base
    s_NdisBase = EgidaUtils::GetModuleBase("ndis.sys");
    if (!s_NdisBase) {
        EgidaLogError("Failed to find ndis.sys");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("ndis.sys base: 0x%p", s_NdisBase);

    // Find ndisReferenceFilterByHandle to locate ndisGlobalFilterList
    // Pattern from reference: ndisReferenceFilterByHandle
    PVOID ndisReferenceFilterByHandle = EgidaUtils::FindPatternInModule(
        s_NdisBase,
        "\x48\x89\x5c\x24\x00\x48\x89\x74\x24\x00\x88\x54\x24\x00\x57",
        "xxxx?xxxx?xxx?x"
    );

    if (!ndisReferenceFilterByHandle) {
        EgidaLogError("Failed to find ndisReferenceFilterByHandle");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("ndisReferenceFilterByHandle: 0x%p", ndisReferenceFilterByHandle);

    // Extract ndisGlobalFilterList from offset 46 (0x2E) + 7 for RIP relative
    PVOID ndisGlobalFilterListCall = static_cast<PUCHAR>(ndisReferenceFilterByHandle) + 46;
    s_NdisGlobalFilterList = EgidaUtils::TranslateAddress<PVOID*>(ndisGlobalFilterListCall, 7);

    if (!s_NdisGlobalFilterList) {
        EgidaLogError("Failed to find ndisGlobalFilterList");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("ndisGlobalFilterList: 0x%p", s_NdisGlobalFilterList);

    // Find ndisDummyIrpHandler
    s_NdisDummyIrpHandler = EgidaUtils::FindPatternInModule(
        s_NdisBase,
        "\x48\x8b\xc4\x48\x89\x58\x00\x48\x89\x68\x00\x48\x89\x70\x00\x48\x89\x78\x00\x41\x57\x48\x83\xec",
        "xxxxxx?xxx?xxx?xxx?xxxxx"
    );

    if (!s_NdisDummyIrpHandler) {
        EgidaLogError("Failed to find ndisDummyIrpHandler");
        return EGIDA_FAILED;
    }

    EgidaLogDebug("ndisDummyIrpHandler: 0x%p", s_NdisDummyIrpHandler);

    // Find ndisMiniDriverList (optional for additional functionality)
    PVOID ndisMiniDriverListCall = EgidaUtils::FindPatternInModule(
        s_NdisBase,
        "\x4c\x8b\x3d\x00\x00\x00\x00\x4d\x85\xff\x74\x00\x4d\x3b\xfd\x0f\x85",
        "xxx????xxxx?xxxxx"
    );

    if (ndisMiniDriverListCall) {
        s_NdisMiniDriverList = EgidaUtils::TranslateAddress<PVOID>(ndisMiniDriverListCall, 7);
        EgidaLogDebug("ndisMiniDriverList: 0x%p", s_NdisMiniDriverList);
    }
    else {
        EgidaLogWarning("ndisMiniDriverList not found (optional)");
    }

    EgidaLogInfo("Network Spoofer initialized successfully");
    EgidaLogDebug("ndisBase: 0x%p, GlobalFilterList: 0x%p, DummyIrpHandler: 0x%p, MiniDriverList: 0x%p",
        s_NdisBase, s_NdisGlobalFilterList, s_NdisDummyIrpHandler, s_NdisMiniDriverList);

    return EGIDA_SUCCESS;
}

NTSTATUS NetworkSpoofer::ExecuteSpoof(_In_ PEGIDA_CONTEXT Context) {
    if (!Context) {
        EgidaLogError("Invalid context");
        return EGIDA_FAILED;
    }

    if (!s_NdisBase || !s_NdisGlobalFilterList || !s_NdisDummyIrpHandler) {
        EgidaLogError("Network Spoofer not properly initialized");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Executing network spoofing...");

    // Initialize seed from context
    if (Context->Config.RandomConfig.RandomSeed != 0) {
        s_Seed = Context->Config.RandomConfig.RandomSeed;
    }

    // Use MAC from profile if available
    if (Context->HasProfileData) {
        BOOLEAN macEmpty = TRUE;
        for (int i = 0; i < 6; i++) {
            if (Context->CurrentProfile.MacAddress[i] != 0) {
                macEmpty = FALSE;
                break;
            }
        }

        if (!macEmpty) {
            EgidaLogInfo("Using MAC address from profile");
            ShowMacAddress(Context->CurrentProfile.MacAddress, 6);
        }
        else {
            EgidaLogInfo("Profile MAC is empty, will generate random");
        }
    }

    NTSTATUS status = ChangeMacAddress(Context);
    if (NT_SUCCESS(status)) {
        EgidaLogInfo("Network spoofing completed successfully");
    }
    else {
        EgidaLogWarning("Network spoofing completed with some failures: 0x%08X", status);
        // Don't fail completely - network spoofing is best effort
        status = EGIDA_SUCCESS;
    }

    return status;
}

NTSTATUS NetworkSpoofer::ChangeMacAddress(_In_ PEGIDA_CONTEXT Context) {
    EgidaLogInfo("Starting MAC address spoofing...");

    ULONG adapterCount = 0;
    ULONG hooksSet = 0;

    __try {
        // Validate global filter list pointer
        if (!EgidaUtils::IsValidKernelPointer(s_NdisGlobalFilterList)) {
            EgidaLogError("Invalid ndisGlobalFilterList pointer: 0x%p", s_NdisGlobalFilterList);
            return EGIDA_FAILED;
        }

        EgidaLogDebug("ndisGlobalFilterList pointer is valid: 0x%p", s_NdisGlobalFilterList);

        if (!*s_NdisGlobalFilterList) {
            EgidaLogWarning("ndisGlobalFilterList is empty (points to NULL)");
            return EGIDA_NOT_FOUND;
        }

        EgidaLogDebug("First filter in list: 0x%p", *s_NdisGlobalFilterList);

        // Iterate through NDIS filter list
        for (PNDIS_FILTER_BLOCK filter = static_cast<PNDIS_FILTER_BLOCK>(*s_NdisGlobalFilterList);
            filter != nullptr && adapterCount < 50; // Safety limit
            filter = filter->NextFilter) {

            adapterCount++;
            EgidaLogDebug("=== Processing Filter #%lu at 0x%p ===", adapterCount, filter);

            // Validate filter pointer
            if (!EgidaUtils::IsValidKernelPointer(filter)) {
                EgidaLogWarning("Invalid filter pointer at index %lu: 0x%p", adapterCount, filter);
                break;
            }

            EgidaLogDebug("Filter pointer is valid, checking FilterInstanceName...");

            // Enhanced validation of FilterInstanceName
            if (!filter->FilterInstanceName) {
                EgidaLogDebug("Filter %lu: FilterInstanceName is NULL", adapterCount);
                continue;
            }

            if (!EgidaUtils::IsValidKernelPointer(filter->FilterInstanceName)) {
                EgidaLogDebug("Filter %lu: FilterInstanceName pointer invalid: 0x%p",
                    adapterCount, filter->FilterInstanceName);
                continue;
            }

            EgidaLogDebug("Filter %lu: FilterInstanceName pointer valid: 0x%p",
                adapterCount, filter->FilterInstanceName);

            // Check UNICODE_STRING structure
            EgidaLogDebug("Filter %lu: Length=%u, MaximumLength=%u, Buffer=0x%p",
                adapterCount,
                filter->FilterInstanceName->Length,
                filter->FilterInstanceName->MaximumLength,
                filter->FilterInstanceName->Buffer);

            if (!filter->FilterInstanceName->Buffer) {
                EgidaLogDebug("Filter %lu: FilterInstanceName Buffer is NULL", adapterCount);
                continue;
            }

            if (!EgidaUtils::IsValidKernelPointer(filter->FilterInstanceName->Buffer)) {
                EgidaLogDebug("Filter %lu: FilterInstanceName Buffer invalid: 0x%p",
                    adapterCount, filter->FilterInstanceName->Buffer);
                continue;
            }

            if (filter->FilterInstanceName->Length == 0) {
                EgidaLogDebug("Filter %lu: FilterInstanceName Length is 0", adapterCount);
                continue;
            }

            if (filter->FilterInstanceName->Length > 1024) { // Reasonable limit
                EgidaLogDebug("Filter %lu: FilterInstanceName Length too large: %u",
                    adapterCount, filter->FilterInstanceName->Length);
                continue;
            }

            EgidaLogDebug("Filter %lu: All validations passed, attempting to copy instance name", adapterCount);

            // Try to read first few characters for debugging
            __try {
                WCHAR testChar = filter->FilterInstanceName->Buffer[0];
                EgidaLogDebug("Filter %lu: First character: 0x%04X ('%wc')",
                    adapterCount, testChar, testChar);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                EgidaLogDebug("Filter %lu: Cannot read first character - access violation", adapterCount);
                continue;
            }

            // Safe copy of instance name with enhanced error handling
            ULONG copySize = min(filter->FilterInstanceName->Length + sizeof(WCHAR), MAX_PATH * sizeof(WCHAR));
            EgidaLogDebug("Filter %lu: Attempting to copy %lu bytes", adapterCount, copySize);

            PWCHAR instanceName = static_cast<PWCHAR>(SafeCopy(
                filter->FilterInstanceName->Buffer,
                copySize
            ));

            if (!instanceName) {
                EgidaLogDebug("Filter %lu: SafeCopy failed", adapterCount);
                continue;
            }

            EgidaLogDebug("Filter %lu: SafeCopy succeeded, instance name: '%ws'", adapterCount, instanceName);

            // Create adapter device path
            WCHAR adapter[MAX_PATH] = { 0 };
            PWCHAR trimmedGuid = TrimGUID(instanceName, MAX_PATH / 2);

            EgidaLogDebug("Filter %lu: Trimmed GUID: '%ws'", adapterCount, trimmedGuid);

            NTSTATUS status = RtlStringCchPrintfW(adapter, MAX_PATH, L"\\Device\\%ws", trimmedGuid);

            ExFreePool(instanceName);

            if (!NT_SUCCESS(status)) {
                EgidaLogDebug("Filter %lu: Failed to format adapter path: 0x%08X", adapterCount, status);
                continue;
            }

            EgidaLogInfo("Filter %lu: Found NIC: %ws", adapterCount, adapter);

            // Get device and driver objects
            UNICODE_STRING deviceName;
            RtlInitUnicodeString(&deviceName, adapter);

            PFILE_OBJECT fileObject = nullptr;
            PDEVICE_OBJECT deviceObject = nullptr;

            status = IoGetDeviceObjectPointer(&deviceName, FILE_READ_DATA, &fileObject, &deviceObject);
            if (!NT_SUCCESS(status)) {
                EgidaLogDebug("Filter %lu: Failed to get device object for %ws: 0x%08X",
                    adapterCount, adapter, status);
                continue;
            }

            PDRIVER_OBJECT driverObject = deviceObject->DriverObject;
            if (!driverObject || !EgidaUtils::IsValidKernelPointer(driverObject)) {
                EgidaLogDebug("Filter %lu: Invalid driver object for %ws", adapterCount, adapter);
                if (fileObject) ObDereferenceObject(fileObject);
                continue;
            }

            // Validate MajorFunction table
            if (!EgidaUtils::IsValidKernelPointer(driverObject->MajorFunction)) {
                EgidaLogDebug("Filter %lu: Invalid MajorFunction table for %ws", adapterCount, adapter);
                if (fileObject) ObDereferenceObject(fileObject);
                continue;
            }

            // Hook the device control function
            driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
                static_cast<PDRIVER_DISPATCH>(s_NdisDummyIrpHandler);

            hooksSet++;
            EgidaLogInfo("✅ Filter %lu: Successfully hooked NIC: %ws", adapterCount, adapter);

            // Show MAC address info
            if (Context && Context->HasProfileData) {
                BOOLEAN macEmpty = TRUE;
                for (int i = 0; i < 6; i++) {
                    if (Context->CurrentProfile.MacAddress[i] != 0) {
                        macEmpty = FALSE;
                        break;
                    }
                }

                if (!macEmpty) {
                    EgidaLogInfo("Filter %lu: Profile MAC for %ws:", adapterCount, adapter);
                    ShowMacAddress(Context->CurrentProfile.MacAddress, 6);
                }
                else {
                    // Generate random MAC
                    UINT8 spoofedMac[6];
                    EgidaRandomizer::GenerateRandomMAC(spoofedMac);
                    EgidaLogInfo("Filter %lu: Generated MAC for %ws:", adapterCount, adapter);
                    ShowMacAddress(spoofedMac, 6);
                }
            }

            if (fileObject) {
                ObDereferenceObject(fileObject);
            }

            // Check next filter pointer
            EgidaLogDebug("Filter %lu: NextFilter = 0x%p", adapterCount, filter->NextFilter);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS exceptionCode = GetExceptionCode();
        EgidaLogError("Exception in ChangeMacAddress at filter %lu: 0x%08X", adapterCount, exceptionCode);
        return EGIDA_FAILED;
    }

    EgidaLogInfo("MAC address spoofing completed - Found %lu adapters, hooked %lu",
        adapterCount, hooksSet);

    return hooksSet > 0 ? EGIDA_SUCCESS : EGIDA_NOT_FOUND;
}

PWCHAR NetworkSpoofer::TrimGUID(_In_ PWCHAR guid, _In_ DWORD max) {
    if (!guid || max == 0) return guid;

    DWORD i = 0;
    PWCHAR start = guid;

    --max;
    // Find start of GUID
    for (; i < max && *start != L'{'; ++i, ++start);

    // Find end of GUID and null terminate
    for (; i < max && guid[i] != L'}' && guid[i] != L'\0'; ++i);

    if (i < max && guid[i] == L'}') {
        guid[i + 1] = L'\0';
    }
    else {
        guid[i] = L'\0';
    }

    return start;
}

PVOID NetworkSpoofer::SafeCopy(_In_ PVOID src, _In_ DWORD size) {
    if (!src) {
        EgidaLogError("SafeCopy: Source pointer is NULL");
        return nullptr;
    }

    if (size == 0) {
        EgidaLogError("SafeCopy: Size is 0");
        return nullptr;
    }

    if (size > 4096) {
        EgidaLogError("SafeCopy: Size too large: %lu", size);
        return nullptr;
    }

    EgidaLogDebug("SafeCopy: Attempting to copy %lu bytes from 0x%p", size, src);

    PVOID buffer = ExAllocatePool(NonPagedPool, size);
    if (!buffer) {
        EgidaLogError("SafeCopy: Failed to allocate pool of size %lu", size);
        return nullptr;
    }

    EgidaLogDebug("SafeCopy: Allocated buffer at 0x%p", buffer);

    __try {
        // First try direct memory copy
        RtlCopyMemory(buffer, src, size);
        EgidaLogDebug("SafeCopy: Direct copy succeeded");
        return buffer;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EgidaLogDebug("SafeCopy: Direct copy failed, trying MmCopyMemory");

        // Try safe memory copy
        __try {
            MM_COPY_ADDRESS addr = { 0 };
            addr.VirtualAddress = src;

            SIZE_T bytesRead = 0;
            NTSTATUS status = MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_VIRTUAL, &bytesRead);

            if (!NT_SUCCESS(status)) {
                EgidaLogError("SafeCopy: MmCopyMemory failed: 0x%08X", status);
                ExFreePool(buffer);
                return nullptr;
            }

            if (bytesRead != size) {
                EgidaLogError("SafeCopy: Only read %zu bytes of %lu", bytesRead, size);
                ExFreePool(buffer);
                return nullptr;
            }

            EgidaLogDebug("SafeCopy: MmCopyMemory succeeded, read %zu bytes", bytesRead);
            return buffer;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            EgidaLogError("SafeCopy: MmCopyMemory also failed with exception");
            ExFreePool(buffer);
            return nullptr;
        }
    }
}

DWORD NetworkSpoofer::Random(_Inout_ PDWORD seed) {
    DWORD s = (*seed) * 1103515245 + 12345;
    *seed = s;
    return (s / 65536) % 32768;
}

DWORD NetworkSpoofer::Hash(_In_ PBYTE buffer, _In_ DWORD length) {
    if (!buffer || !length) {
        return 0;
    }

    DWORD h = (buffer[0] ^ 0x4B9ACE3F) * 0x1040193;
    for (DWORD i = 1; i < length; ++i) {
        h = (buffer[i] ^ h) * 0x1040193;
    }
    return h;
}

VOID NetworkSpoofer::ShowMacAddress(_In_ PUCHAR macAddress, _In_ ULONG length) {
    if (!macAddress || length == 0) return;

    EgidaLogInfo("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X",
        macAddress[0], macAddress[1], macAddress[2],
        macAddress[3], macAddress[4], macAddress[5]);
}

NTSTATUS NetworkSpoofer::HookNetworkDrivers(_In_ PEGIDA_CONTEXT Context) {
    return ChangeMacAddress(Context);
}

NTSTATUS NetworkSpoofer::StopSpoof(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Stopping network spoofing...");

    // Note: Network hooks remain active until driver unload
    // This is intentional for security reasons - we don't want to restore
    // original handlers as it might leave traces

    EgidaLogInfo("Network spoofing stopped (hooks remain active)");
    return EGIDA_SUCCESS;
}

VOID NetworkSpoofer::Cleanup(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Cleaning up Network Spoofer...");

    // Reset static members
    s_NdisBase = nullptr;
    s_NdisGlobalFilterList = nullptr;
    s_NdisDummyIrpHandler = nullptr;
    s_NdisMiniDriverList = nullptr;
    s_Seed = 0x7899;

    EgidaLogInfo("Network Spoofer cleanup completed");
}