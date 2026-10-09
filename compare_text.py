#!/usr/bin/env python3
"""compare_text.py — shows how much of .text is byte-identical between two builds."""
import struct, sys

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

def longest_common_run(a, b):
    best = 0
    run = 0
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] == b[i]:
            run += 1
            if run > best:
                best = run
        else:
            run = 0
    return best

a = text_section(sys.argv[1])
b = text_section(sys.argv[2])
n = min(len(a), len(b))
ident = sum(1 for i in range(n) if a[i] == b[i])
print(f".text A = {len(a):,} B = {len(b):,} bytes")
print(f"Identical bytes: {ident:,} / {n:,}  ({100.0 * ident / n:.1f}%)")
print(f"Longest identical run: {longest_common_run(a, b):,} bytes")
