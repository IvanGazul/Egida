#pragma once
#include "../Common/Structures.h"

// SMBIOS Types
#define SMBIOS_TYPE_BIOS           0
#define SMBIOS_TYPE_SYSTEM         1
#define SMBIOS_TYPE_BASEBOARD      2
#define SMBIOS_TYPE_CHASSIS        3
#define SMBIOS_TYPE_PROCESSOR      4
#define SMBIOS_TYPE_MEMORY_ARRAY   16
#define SMBIOS_TYPE_MEMORY_DEVICE  17
#define SMBIOS_TYPE_END            127

class SmbiosSpoofer {
public:
    // --- Публичный интерфейс остался без изменений ---
    static NTSTATUS Initialize(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ExecuteSpoof(_In_ PEGIDA_CONTEXT Context);
    static NTSTATUS StopSpoof(_In_ PEGIDA_CONTEXT Context);
    static VOID Cleanup(_In_ PEGIDA_CONTEXT Context);

private:
    // --- Приватные методы обновлены для соответствия новой логике пересборки ---

    /**
     * @brief Итерируется по оригинальной таблице SMBIOS и пересобирает её в новом буфере.
     * @param ReadBase Указатель на начало оригинальной (читаемой) таблицы.
     * @param ReadSize Размер оригинальной таблицы.
     * @param WriteBase Указатель на начало нового (записываемого) буфера.
     * @param WriteSize Размер нового буфера.
     * @param FinalSize Выходной параметр для итогового размера пересобранной таблицы.
     * @param Context Контекст драйвера.
     * @return NTSTATUS.
     */
    static NTSTATUS LoopAndRebuildSmbiosTables(_In_ PVOID ReadBase, _In_ ULONG ReadSize, _In_ PVOID WriteBase, _In_ ULONG WriteSize, _Out_ PULONG FinalSize, _In_ PEGIDA_CONTEXT Context);

    /**
     * @brief Обрабатывает одну структуру SMBIOS, копируя и модифицируя её в новый буфер.
     * @param ReadHeader Указатель на заголовок структуры в оригинальной таблице.
     * @param WritePtr Указатель на текущую позицию для записи в новом буфере.
     * @param BufferEnd Указатель на конец нового буфера для проверки границ.
     * @param Context Контекст драйвера.
     * @return NTSTATUS.
     */
    static NTSTATUS ProcessAndRebuildTable(_In_ PSMBIOS_HEADER ReadHeader, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context);

    // --- Индивидуальные обработчики таблиц с обновлёнными сигнатурами ---

    static NTSTATUS ProcessBiosInfo(_In_ PSMBIOS_BIOS_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessSystemInfo(_In_ PSMBIOS_SYSTEM_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessBaseboardInfo(_In_ PSMBIOS_BASEBOARD_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessChassisInfo(_In_ PSMBIOS_CHASSIS_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessProcessorInfo(_In_ PSMBIOS_PROCESSOR_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context);
    static NTSTATUS ProcessMemoryDeviceInfo(_In_ PSMBIOS_MEMORY_DEVICE_INFO ReadInfo, _In_ PUCHAR* WritePtr, _In_ PUCHAR BufferEnd, _In_ PEGIDA_CONTEXT Context);

    // --- Вспомогательные функции ---

    static NTSTATUS ChangeBootEnvironmentInfo(_In_ PEGIDA_CONTEXT Context);

    // --- Состояние модуля (статические переменные) ---

    static PVOID s_NtoskrnlBase;
    static PPHYSICAL_ADDRESS s_SmbiosPhysicalAddress;
    static PULONG s_SmbiosTableLength;
    static PBOOT_ENVIRONMENT_INFORMATION s_BootEnvironmentInfo;
};