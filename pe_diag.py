#!/usr/bin/env python3
"""
pe_diag.py — PE diagnostic for ML-detection profiling.

Reads a PE file and reports the feature-vector signals that ML engines
(EMBER-style: Elastic, Defender !ml, Symantec ML, SentinelOne, etc.) weigh:

  1. Section table: name / virtual size / raw size / entropy per section
  2. Optional header: subsystem, characteristics, TLS directory presence
  3. Imports: DLLs + function counts (import-count is a strong ML feature)
  4. Resource directory: version info / icon / manifest presence
  5. Payload-section padding probe: byte distribution at several offsets

Usage: python3 pe_diag.py <file.exe>
"""
import struct
import sys
import math
import collections


def entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    c = collections.Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


RES_NAMES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
             6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
             10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
             14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
             19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON",
             23: "HTML", 24: "MANIFEST"}


def main(path: str):
    data = open(path, "rb").read()
    print(f"== {path} ({len(data):,} bytes) ==")

    if data[:2] != b"MZ":
        print("Not a PE")
        return

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0"
    coff = e_lfanew + 4
    machine, nsec, ts, ptr_sym, nsym, opt_sz, chars = struct.unpack_from(
        "<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B

    print(f"\n[optional header] magic=0x{magic:04x} ({'PE32+' if is64 else 'PE32'})")
    print(f"  SizeOfOptionalHeader={opt_sz}  -> section table @0x{opt + opt_sz:x}")
    print(f"  characteristics=0x{chars:04x} "
          f"({'DLL' if chars & 0x2000 else 'EXE'}, "
          f"{'RELOCS_STRIPPED' if chars & 0x0001 else 'relocs-present'}, "
          f"{'EXECUTABLE' if chars & 0x0002 else ''}, "
          f"{'32BIT' if chars & 0x0100 else '64bit'})")

    num_rva = struct.unpack_from("<I", data, opt + (108 if is64 else 92))[0]
    sec_tab = opt + opt_sz
    dd = opt + (112 if is64 else 96)
    tls_rva, tls_sz = struct.unpack_from("<II", data, dd + 9 * 8)
    res_rva, res_sz = struct.unpack_from("<II", data, dd + 2 * 8)
    imp_rva, imp_sz = struct.unpack_from("<II", data, dd + 1 * 8)

    subsystem = struct.unpack_from("<H", data, opt + (68 if is64 else 68))[0]
    dll_chars = struct.unpack_from("<H", data, opt + (70 if is64 else 70))[0]
    subsystem_names = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI"}
    print(f"  subsystem={subsystem} ({subsystem_names.get(subsystem, '?')})")
    print(f"  DLL characteristics=0x{dll_chars:04x} "
          f"({'HIGH_ENTROPY_VA' if dll_chars & 0x0020 else ''} "
          f"{'DYNAMIC_BASE' if dll_chars & 0x0040 else ''} "
          f"{'NX_COMPAT' if dll_chars & 0x0100 else ''} "
          f"{'NO_SEH' if dll_chars & 0x0400 else ''} "
          f"{'GUARD_CF' if dll_chars & 0x4000 else ''})")
    print(f"  TLS directory: {'PRESENT @0x%x (size %d)' % (tls_rva, tls_sz) if tls_rva else 'ABSENT'}")
    print(f"  Resource directory: {'PRESENT @0x%x (size %d)' % (res_rva, res_sz) if res_rva else 'ABSENT'}")
    print(f"  Import directory: {'PRESENT @0x%x (size %d)' % (imp_rva, imp_sz) if imp_rva else 'ABSENT'}")

    # --- sections ---
    print(f"\n[section table] ({nsec} sections)")
    sections = []
    for i in range(nsec):
        off = sec_tab + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("latin1")
        vsz, va, rsz, pra, prel, pln, nrel, nln, chars2 = struct.unpack_from(
            "<IIIIIIHHI", data, off + 8)
        raw = data[pra:pra + rsz] if pra and rsz else b""
        ent = entropy(raw) if raw else 0.0
        sections.append((name, vsz, va, rsz, ent, chars2, pra))
        flags = []
        if chars2 & 0x20000000: flags.append("EXEC")
        if chars2 & 0x40000000: flags.append("READ")
        if chars2 & 0x80000000: flags.append("WRITE")
        print(f"  {name:<9} vsz=0x{vsz:06x} rsz=0x{rsz:06x} ent={ent:4.2f} "
              f"{'/'.join(flags) if flags else ''}")

    # --- padding probe from largest non-exec writable section ---
    non_exec = [s for s in sections if not (s[5] & 0x20000000) and s[3] > 0]
    if non_exec:
        biggest = max(non_exec, key=lambda s: s[3])
        name, vsz, va, rsz, ent, _, pra = biggest
        raw = data[pra:pra + rsz]
        print(f"\n[padding probe] section '{name}' ent={ent:.2f}")
        for frac in (0.10, 0.25, 0.50, 0.75, 0.90):
            off = int(len(raw) * frac)
            chunk = raw[off:off + 256]
            c = collections.Counter(chunk)
            top = c.most_common(3)
            print(f"  @{frac:>3.0%}: uniq={len(c)}/256 top={top} ent={entropy(chunk):.2f}")

    # --- imports (RVA -> file offset via section map) ---
    print("\n[imports]")
    sec_by_rva = sorted([(s[2], s[6], s[3]) for s in sections], key=lambda t: t[0])

    def rva2off(rva):
        for va, off, sz in sec_by_rva:
            if va <= rva < va + max(sz, 1):
                return off + (rva - va)
        return None

    if imp_rva:
        off = rva2off(imp_rva)
        if off is not None:
            while True:
                ilt, ts, fwd, name_rva, iat = struct.unpack_from(
                    "<IIIII", data, off)
                if name_rva == 0 and ilt == 0:
                    break
                noff = rva2off(name_rva)
                if noff is None:
                    break
                end = data.find(b"\0", noff)
                dll_name = data[noff:end].decode("latin1")
                cnt = 0
                if ilt:
                    loff = rva2off(ilt)
                    if loff is not None:
                        step = 8 if is64 else 4
                        while True:
                            v = struct.unpack_from("<Q" if is64 else "<I", data, loff)[0]
                            if v == 0:
                                break
                            cnt += 1
                            loff += step
                            if cnt > 2000:
                                break
                print(f"  {dll_name:<24} {cnt:3d} functions")
                off += 20
        else:
            print("  (import dir RVA unmappable)")

    # --- resources: top-level type IDs only ---
    print("\n[resources]")
    if res_rva:
        roff = rva2off(res_rva)
        if roff is not None:
            try:
                nname, nid = struct.unpack_from("<HH", data, roff + 12)
                types = []
                for i in range(nname + nid):
                    e = roff + 16 + i * 8
                    tid = struct.unpack_from("<I", data, e)[0]
                    types.append(RES_NAMES.get(tid, "type_%d" % tid))
                # dedupe keeping order
                seen = set()
                uniq = [t for t in types if not (t in seen or seen.add(t))]
                print(f"  root entries ({nname} named / {nid} id): {', '.join(uniq[:20])}")
                has_ver = 16 in [t for t in types]
                print(f"  VERSION_INFO: {'YES' if has_ver else 'NO (ML red flag for some engines)'}")
            except struct.error:
                print("  (resource dir parse failed)")
        else:
            print("  (resource dir RVA unmappable)")
    else:
        print("  NONE")

    # --- quick ML-profile summary ---
    print("\n[ML profile]")
    code = [s for s in sections if s[5] & 0x20000000]
    data_secs = [s for s in sections if not (s[5] & 0x20000000) and s[3] > 0]
    code_bytes = sum(s[3] for s in code)
    data_bytes = sum(s[3] for s in data_secs)
    hi_ent = [s for s in sections if s[3] > 0 and s[4] > 7.0]
    print(f"  section count: {nsec} (legit PE: usually 5-9)")
    print(f"  code bytes: {code_bytes:,} ({code_bytes/len(data)*100:.1f}%) | "
          f"data bytes: {data_bytes:,} ({data_bytes/len(data)*100:.1f}%)")
    print(f"  sections with entropy > 7.0: {len(hi_ent)} "
          f"{[s[0] for s in hi_ent] if hi_ent else ''}")
    if nsec > 10:
        print("  !! HIGH section count - packer-style layout")
    if len(hi_ent) >= 4:
        print("  !! 4+ high-entropy sections - strong packer/encrypted signal")
    if code_bytes / len(data) < 0.05:
        print("  !! tiny code footprint vs file size - classic packer ratio")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
