#pragma once
#include "../Common/Definitions.h"

class EgidaRandomizer {
public:
    static VOID InitializeSeed(_In_ UINT32 Seed = 0);
    static UINT32 GetRandomNumber(_In_ UINT32 Min = 0, _In_ UINT32 Max = MAXUINT32);
    static VOID GenerateRandomString(_Out_ PCHAR Buffer, _In_ UINT32 Length, _In_ BOOLEAN AlphaNumeric = TRUE);
    static VOID GenerateRandomBytes(_Out_ PUCHAR Buffer, _In_ UINT32 Length);
    static VOID GenerateRandomMAC(_Out_ PUCHAR MacAddress);
    static VOID GenerateRandomUUID(_Out_ GUID* Uuid);
    static VOID GenerateRandomSerial(_Out_ PCHAR Buffer, _In_ UINT32 Length);
    static PCHAR GenerateRandomAlphanumericString(ULONG length);
private:
    static UINT32 SimpleRandom();
    static UINT32 HashData(_In_ PUCHAR Data, _In_ UINT32 Length);

    // Определение статической переменной теперь тоже inline
    inline static UINT32 s_RandomSeed = 0;
};

// Implementation
// Каждая функция теперь inline

inline VOID EgidaRandomizer::InitializeSeed(_In_ UINT32 Seed) {
    if (Seed == 0) {
        LARGE_INTEGER time;
        KeQuerySystemTime(&time);
        s_RandomSeed = static_cast<UINT32>(time.LowPart ^ time.HighPart);
    }
    else {
        s_RandomSeed = Seed;
    }

    // Warm up the generator
    for (int i = 0; i < 10; i++) {
        SimpleRandom();
    }
}

inline UINT32 EgidaRandomizer::SimpleRandom() {
    s_RandomSeed = s_RandomSeed * 1103515245 + 12345;
    return (s_RandomSeed / 65536) % 32768;
}

inline UINT32 EgidaRandomizer::GetRandomNumber(_In_ UINT32 Min, _In_ UINT32 Max) {
    if (Min >= Max) return Min;
    return Min + (SimpleRandom() % (Max - Min + 1));
}

inline VOID EgidaRandomizer::GenerateRandomString(_Out_ PCHAR Buffer, _In_ UINT32 Length, _In_ BOOLEAN AlphaNumeric) {
    if (!Buffer || Length == 0) return;

    const char* charset;
    UINT32 charsetSize;

    if (AlphaNumeric) {
        charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        charsetSize = 62;
    }
    else {
        charset = "0123456789ABCDEF";
        charsetSize = 16;
    }

    for (UINT32 i = 0; i < Length - 1; i++) {
        Buffer[i] = charset[SimpleRandom() % charsetSize];
    }
    Buffer[Length - 1] = '\0';
}

inline VOID EgidaRandomizer::GenerateRandomBytes(_Out_ PUCHAR Buffer, _In_ UINT32 Length) {
    if (!Buffer) return;

    for (UINT32 i = 0; i < Length; i++) {
        Buffer[i] = static_cast<UCHAR>(GetRandomNumber(0, 255));
    }
}

inline PCHAR EgidaRandomizer::GenerateRandomAlphanumericString(ULONG length) {
    if (length == 0 || length > 64) return nullptr;

    PCHAR buffer = static_cast<PCHAR>(EGIDA_ALLOC_NON_PAGED(length + 1));
    if (!buffer) return nullptr;

    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const ULONG charsetSize = sizeof(charset) - 1; // Exclude null terminator

    for (ULONG i = 0; i < length; i++) {
        ULONG randomIndex = SimpleRandom() % charsetSize;
        buffer[i] = charset[randomIndex];
    }

    buffer[length] = '\0';
    return buffer;
}


inline VOID EgidaRandomizer::GenerateRandomMAC(_Out_ PUCHAR MacAddress) {
    if (!MacAddress) return;

    GenerateRandomBytes(MacAddress, 6);

    // Ensure it's a locally administered address
    MacAddress[0] = (MacAddress[0] & 0xFE) | 0x02;
}

inline VOID EgidaRandomizer::GenerateRandomUUID(_Out_ GUID* Uuid) {
    if (!Uuid) return;

    GenerateRandomBytes(reinterpret_cast<PUCHAR>(Uuid), sizeof(GUID));

    // Set version (4) and variant bits according to RFC 4122
    Uuid->Data3 = (Uuid->Data3 & 0x0FFF) | 0x4000;
    Uuid->Data4[0] = (Uuid->Data4[0] & 0x3F) | 0x80;
}

inline VOID EgidaRandomizer::GenerateRandomSerial(_Out_ PCHAR Buffer, _In_ UINT32 Length) {
    if (!Buffer || Length < 8) return;

    // Generate alphanumeric serial
    GenerateRandomString(Buffer, Length, TRUE);

    // Ensure it starts with a letter
    if (Buffer[0] >= '0' && Buffer[0] <= '9') {
        Buffer[0] = 'A' + (SimpleRandom() % 26);
    }
}

inline UINT32 EgidaRandomizer::HashData(_In_ PUCHAR Data, _In_ UINT32 Length) {
    if (!Data || Length == 0) return 0;

    UINT32 hash = (Data[0] ^ 0x4B9ACE3F) * 0x1040193;
    for (UINT32 i = 1; i < Length; i++) {
        hash = (Data[i] ^ hash) * 0x1040193;
    }
    return hash;
}