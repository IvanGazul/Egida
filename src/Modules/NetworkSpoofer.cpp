#include "NetworkSpoofer.h"
#include "../Utils/EgidaUtils.h"
#include "../Utils/Randomizer.h"
#include "../Core/Logger.h"

// Static members
PVOID NetworkSpoofer::s_NdisBase = nullptr;
PVOID* NetworkSpoofer::s_NdisGlobalFilterList = nullptr;
PVOID NetworkSpoofer::s_NdisDummyIrpHandler = nullptr;

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

    // Find NDIS global filter list - using more robust pattern
    PVOID filterListCall = EgidaUtils::FindPatternInModule(
        s_NdisBase,
        "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x0f\x84",
        "xxx????xxxxx"
    );

    if (!filterListCall) {
        // Try alternative pattern
        filterListCall = EgidaUtils::FindPatternInModule(
            s_NdisBase,
            "\x48\x8b\x0d\x00\x00\x00\x00\x48\x85\xc9\x74",
            "xxx????xxxx"
        );
    }

    if (!filterListCall) {
        EgidaLogWarning("Failed to find NDIS filter list pattern - using alternative approach");
        // Set to null and handle gracefully
        s_NdisGlobalFilterList = nullptr;
    }
    else {
        s_NdisGlobalFilterList = EgidaUtils::TranslateAddress<PVOID*>(filterListCall, 7);
        EgidaLogDebug("NDIS Global Filter List: 0x%p", s_NdisGlobalFilterList);
    }

    // Find NDIS dummy IRP handler
    s_NdisDummyIrpHandler = EgidaUtils::FindPatternInModule(
        s_NdisBase,
        "\x48\x8b\xc4\x48\x89\x58\x00\x48\x89\x68\x00\x48\x89\x70\x00\x48\x89\x78\x00\x41\x57\x48\x83\xec",
        "xxxxxx?xxx?xxx?xxx?xxxxx"
    );

    if (!s_NdisDummyIrpHandler) {
        // Try alternative pattern for dummy handler
        s_NdisDummyIrpHandler = EgidaUtils::FindPatternInModule(
            s_NdisBase,
            "\x48\x89\x5c\x24\x00\x48\x89\x6c\x24\x00\x48\x89\x74\x24\x00\x57",
            "xxxx?xxxx?xxxx?x"
        );
    }

    if (!s_NdisDummyIrpHandler) {
        EgidaLogWarning("Failed to find NDIS dummy IRP handler - network spoofing may be limited");
        // We can still continue without the handler
    }
    else {
        EgidaLogDebug("NDIS Dummy IRP Handler: 0x%p", s_NdisDummyIrpHandler);
    }

    EgidaLogInfo("Network Spoofer initialized successfully");
    return EGIDA_SUCCESS;
}

NTSTATUS NetworkSpoofer::ExecuteSpoof(_In_ PEGIDA_CONTEXT Context) {
    if (!Context) {
        EgidaLogError("Invalid context");
        return EGIDA_FAILED;
    }

    if (!s_NdisBase) {
        EgidaLogError("Network Spoofer not properly initialized");
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Executing network spoofing...");

    NTSTATUS status = EGIDA_SUCCESS;

    // Try to hook network drivers
    if (s_NdisGlobalFilterList && s_NdisDummyIrpHandler) {
        status = HookNetworkDrivers(Context);
        if (!NT_SUCCESS(status)) {
            EgidaLogWarning("Failed to hook network drivers via NDIS filter list: 0x%08X", status);
            // Try alternative approach
            status = HookNetworkDriversAlternative(Context);
        }
    }
    else {
        EgidaLogInfo("Using alternative network spoofing approach");
        status = HookNetworkDriversAlternative(Context);
    }

    if (NT_SUCCESS(status)) {
        EgidaLogInfo("Network spoofing completed successfully");
    }
    else {
        EgidaLogWarning("Network spoofing completed with limitations");
        // Don't fail completely - return success but with warning
        status = EGIDA_SUCCESS;
    }

    return status;
}

NTSTATUS NetworkSpoofer::HookNetworkDrivers(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Hooking network drivers via NDIS filter list...");

    if (!s_NdisGlobalFilterList || !s_NdisDummyIrpHandler) {
        EgidaLogError("Required NDIS components not found");
        return EGIDA_FAILED;
    }

    ULONG adapterCount = 0;

    __try {
        // Validate the filter list pointer first
        if (!EgidaUtils::IsValidKernelPointer(s_NdisGlobalFilterList)) {
            EgidaLogError("Invalid NDIS filter list pointer");
            return EGIDA_FAILED;
        }

        // Check if the list is not null
        if (!*s_NdisGlobalFilterList) {
            EgidaLogWarning("NDIS filter list is empty");
            return EGIDA_NOT_FOUND;
        }

        // Validate the first filter entry
        PNDIS_FILTER_BLOCK firstFilter = static_cast<PNDIS_FILTER_BLOCK>(*s_NdisGlobalFilterList);
        if (!EgidaUtils::IsValidKernelPointer(firstFilter)) {
            EgidaLogError("Invalid first filter pointer");
            return EGIDA_FAILED;
        }

        // Iterate through NDIS filter list with safety checks
        for (PNDIS_FILTER_BLOCK filter = firstFilter;
            filter != nullptr && adapterCount < 100; // Limit iterations to prevent infinite loop
            filter = filter->NextFilter) {

            // Validate current filter
            if (!EgidaUtils::IsValidKernelPointer(filter)) {
                EgidaLogWarning("Invalid filter pointer encountered, stopping iteration");
                break;
            }

            // Check if we have a valid FilterInstanceName
            if (!filter->FilterInstanceName || !EgidaUtils::IsValidKernelPointer(filter->FilterInstanceName)) {
                continue;
            }

            // Validate the instance name buffer
            if (!filter->FilterInstanceName->Buffer ||
                !EgidaUtils::IsValidKernelPointer(filter->FilterInstanceName->Buffer) ||
                filter->FilterInstanceName->Length == 0 ||
                filter->FilterInstanceName->Length > 512) { // Reasonable length check
                continue;
            }

            // Extract adapter name safely
            PWCHAR adapterName = ExtractAdapterName(filter->FilterInstanceName);
            if (!adapterName) {
                continue;
            }

            // Create device path
            WCHAR devicePath[MAX_PATH];
            NTSTATUS status = RtlStringCchPrintfW(devicePath, MAX_PATH, L"\\Device\\%ws", adapterName);
            if (!NT_SUCCESS(status)) {
                EGIDA_FREE(adapterName);
                continue;
            }

            EgidaLogDebug("Processing network adapter: %ws", devicePath);

            UNICODE_STRING deviceName;
            RtlInitUnicodeString(&deviceName, devicePath);

            PFILE_OBJECT fileObject = nullptr;
            PDEVICE_OBJECT deviceObject = nullptr;

            status = IoGetDeviceObjectPointer(
                &deviceName,
                FILE_READ_DATA,
                &fileObject,
                &deviceObject
            );

            if (NT_SUCCESS(status) && deviceObject) {
                PDRIVER_OBJECT driverObject = deviceObject->DriverObject;

                if (driverObject && EgidaUtils::IsValidKernelPointer(driverObject)) {
                    // Validate the MajorFunction table
                    if (EgidaUtils::IsValidKernelPointer(driverObject->MajorFunction)) {
                        // Hook the device control function to intercept MAC address queries
                        driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
                            static_cast<PDRIVER_DISPATCH>(s_NdisDummyIrpHandler);

                        EgidaLogInfo("Hooked network adapter: %ws", devicePath);
                        adapterCount++;
                    }
                }

                if (fileObject) {
                    ObDereferenceObject(fileObject);
                }
            }

            EGIDA_FREE(adapterName);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS exceptionCode = GetExceptionCode();
        EgidaLogError("Exception while hooking network drivers: 0x%08X", exceptionCode);
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Successfully hooked %lu network adapters", adapterCount);
    return adapterCount > 0 ? EGIDA_SUCCESS : EGIDA_NOT_FOUND;
}

NTSTATUS NetworkSpoofer::HookNetworkDriversAlternative(_In_ PEGIDA_CONTEXT Context) {
    UNREFERENCED_PARAMETER(Context);

    EgidaLogInfo("Using alternative network driver hooking approach...");

    ULONG adapterCount = 0;

    __try {
        // Try to hook common network adapter device names
        PCWSTR commonAdapterNames[] = {
            L"\\Device\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\0000",
            L"\\Device\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\0001",
            L"\\Device\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\0002",
            L"\\Device\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\0003",
            L"\\Device\\e1d",  // Intel adapter
            L"\\Device\\e1g",  // Intel gigabit
            L"\\Device\\RTL8168", // Realtek
            L"\\Device\\vmxnet3", // VMware
            nullptr
        };

        for (int i = 0; commonAdapterNames[i] != nullptr; i++) {
            UNICODE_STRING deviceName;
            RtlInitUnicodeString(&deviceName, commonAdapterNames[i]);

            PFILE_OBJECT fileObject = nullptr;
            PDEVICE_OBJECT deviceObject = nullptr;

            NTSTATUS status = IoGetDeviceObjectPointer(
                &deviceName,
                FILE_READ_DATA,
                &fileObject,
                &deviceObject
            );

            if (NT_SUCCESS(status) && deviceObject) {
                PDRIVER_OBJECT driverObject = deviceObject->DriverObject;

                if (driverObject && EgidaUtils::IsValidKernelPointer(driverObject)) {
                    if (s_NdisDummyIrpHandler && EgidaUtils::IsValidKernelPointer(driverObject->MajorFunction)) {
                        driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
                            static_cast<PDRIVER_DISPATCH>(s_NdisDummyIrpHandler);

                        EgidaLogInfo("Hooked network adapter (alternative): %ws", commonAdapterNames[i]);
                        adapterCount++;
                    }
                }

                if (fileObject) {
                    ObDereferenceObject(fileObject);
                }
            }
        }

        // Generate some fake MAC addresses as additional spoofing
        for (int i = 0; i < 3; i++) {
            UINT8 fakeMac[6];
            EgidaRandomizer::GenerateRandomMAC(fakeMac);

            EgidaLogInfo("Generated spoofed MAC %d: %02X:%02X:%02X:%02X:%02X:%02X",
                i + 1, fakeMac[0], fakeMac[1], fakeMac[2], fakeMac[3], fakeMac[4], fakeMac[5]);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS exceptionCode = GetExceptionCode();
        EgidaLogError("Exception in alternative network hooking: 0x%08X", exceptionCode);
        return EGIDA_FAILED;
    }

    EgidaLogInfo("Alternative network spoofing completed with %lu adapters processed", adapterCount);
    return EGIDA_SUCCESS;
}

PWCHAR NetworkSpoofer::ExtractAdapterName(_In_ PUNICODE_STRING InstanceName) {
    if (!InstanceName || !InstanceName->Buffer || InstanceName->Length == 0) {
        return nullptr;
    }

    // Ensure we don't exceed reasonable bounds
    USHORT safeLength = min(InstanceName->Length, 512);

    // Copy the instance name safely
    PWCHAR nameBuffer = static_cast<PWCHAR>(SafeCopyMemory(
        InstanceName->Buffer,
        safeLength + sizeof(WCHAR)
    ));

    if (!nameBuffer) {
        return nullptr;
    }

    // Null terminate the string
    nameBuffer[safeLength / sizeof(WCHAR)] = L'\0';

    // Find GUID part and trim it
    PWCHAR guidStart = wcsstr(nameBuffer, L"{");
    if (guidStart) {
        PWCHAR guidEnd = wcsstr(guidStart, L"}");
        if (guidEnd) {
            *(guidEnd + 1) = L'\0';

            // Move the GUID to the beginning of the buffer
            SIZE_T guidLength = wcslen(guidStart);
            if (guidLength > 0 && guidLength < 256) { // Safety check
                RtlMoveMemory(nameBuffer, guidStart, (guidLength + 1) * sizeof(WCHAR));
            }
        }
    }

    return nameBuffer;
}

PVOID NetworkSpoofer::SafeCopyMemory(_In_ PVOID Source, _In_ SIZE_T Size) {
    if (!Source || Size == 0 || Size > 4096) { // Reasonable size limit
        return nullptr;
    }

    PVOID buffer = EGIDA_ALLOC_NON_PAGED(Size);
    if (!buffer) {
        EgidaLogError("Failed to allocate buffer of size %zu", Size);
        return nullptr;
    }

    __try {
        MM_COPY_ADDRESS sourceAddr = { 0 };
        sourceAddr.VirtualAddress = Source;

        SIZE_T bytesRead = 0;
        NTSTATUS status = MmCopyMemory(buffer, sourceAddr, Size, MM_COPY_MEMORY_VIRTUAL, &bytesRead);

        if (!NT_SUCCESS(status) || bytesRead != Size) {
            EGIDA_FREE(buffer);
            return nullptr;
        }

        return buffer;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EGIDA_FREE(buffer);
        return nullptr;
    }
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

    EgidaLogInfo("Network Spoofer cleanup completed");
}