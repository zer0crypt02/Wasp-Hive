#!/usr/bin/env python3
"""Check whether sys_check.exe's .reloc covers the TLS directory fields + callbacks."""
import struct

data = open('sys_check.exe', 'rb').read()
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
nsec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
opt = e_lfanew + 24
magic = struct.unpack_from('<H', data, opt)[0]
is64 = (magic == 0x20b)
sizeof_opt = struct.unpack_from('<H', data, e_lfanew + 20)[0]
sec_tab = opt + sizeof_opt
BASE = 0x140000000

def dd(idx):
    return struct.unpack_from('<II', data, opt + (112 if is64 else 96) + idx * 8)

tls_dir = dd(9)
reloc_dir = dd(5)
print(f"TLS dir  RVA=0x{tls_dir[0]:x} size=0x{tls_dir[1]:x}")
print(f"Reloc dir RVA=0x{reloc_dir[0]:x} size=0x{reloc_dir[1]:x}")

sections = []
for i in range(nsec):
    off = sec_tab + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', 'replace')
    vsz, va, rsz, ptr = struct.unpack_from('<IIII', data, off + 8)
    sections.append((name, va, vsz, ptr, rsz))

def rva_to_off(rva):
    for name, va, vsz, ptr, rsz in sections:
        if va <= rva < va + max(vsz, rsz):
            return ptr + (rva - va)
    return None

# TLS directory struct
tls_off = rva_to_off(tls_dir[0])
tls_fields = struct.unpack_from('<QQQQII', data, tls_off) if tls_off else None
start = end = idx = callbacks = 0
if tls_fields:
    start, end, idx, callbacks, zf, ch = tls_fields
    print(f"TLS: start=0x{start:x} end=0x{end:x} idx=0x{idx:x} callbacks=0x{callbacks:x}")

# All reloc targets as preferred-base VAs
targets = set()
rb_off = rva_to_off(reloc_dir[0])
rb = data[rb_off:rb_off + reloc_dir[1]]
ro = 0
while ro < len(rb):
    page, blksz = struct.unpack_from('<II', rb, ro)
    if blksz < 8:
        break
    cnt = (blksz - 8) // 2
    for i in range(cnt):
        ent = struct.unpack_from('<H', rb, ro + 8 + i * 2)[0]
        typ, offs = ent >> 12, ent & 0xFFF
        if typ in (3, 10):
            targets.add(BASE + page + offs)
    ro += blksz
print(f"total reloc targets: {len(targets)}")

checks = [("TLS.StartAddressOfRawData", start), ("TLS.EndAddressOfRawData", end),
          ("TLS.AddressOfIndex", idx), ("TLS.AddressOfCallBacks", callbacks)]
if callbacks:
    cb_off = rva_to_off(callbacks - BASE)
    if cb_off:
        for j in range(8):
            cb = struct.unpack_from('<Q', data, cb_off + j * 8)[0]
            if cb == 0:
                break
            checks.append((f"callback[{j}]", cb))

for name, va in checks:
    print(f"{name:35s} 0x{va:016x} reloc-covered={va in targets}")
