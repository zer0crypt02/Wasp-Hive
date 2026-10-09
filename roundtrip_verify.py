#!/usr/bin/env python3
"""
roundtrip_verify.py — independent round-trip verifier for the packer output.

Replicates the stub's extraction + decryption pipeline in pure Python:
  1. Parse the final exe's section table, locate the N payload sections by name
     (names come from the injected stub's sn[] array — passed as args).
  2. Replicate ep(): for each section, take bp bytes per bt-sized block.
  3. Concatenate the recovered stream = the aligned encrypted payload.
  4. Read key (32 bytes from <keysec>) and iv (16 bytes from <ivsec>).
  5. SHA256-CTR decrypt: h = sha256(key + pack("<Q", ctr) + iv), 32-byte blocks.
  6. Compare the first len(pe) bytes against the original PE.

Usage (N payload sections, bt optional, default 256):
  python3 roundtrip_verify.py <exe> <orig_pe> <keysec> <ivsec> \
      bp0 bp1 ... bpN-1 [bt] sec0 sec1 ... secN-1
"""
import hashlib, struct, sys


def sections(data: bytes):
    """Yield (name, ptr_raw, size_raw, virt_size) for each section."""
    if data[:2] != b"MZ":
        return
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    fh = pe_off + 4
    ns = struct.unpack_from("<H", data, fh + 2)[0]
    oh = fh + 20
    ohs = struct.unpack_from("<H", data, fh + 16)[0]
    so = oh + ohs
    for i in range(ns):
        s = so + i * 40
        name = data[s:s + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vs = struct.unpack_from("<I", data, s + 8)[0]
        rs = struct.unpack_from("<I", data, s + 16)[0]
        ro = struct.unpack_from("<I", data, s + 20)[0]
        yield name, ro, rs, vs


def ep(sd: bytes, bp: int, bt: int) -> bytes:
    """Replicate stub ep(): take bp bytes per bt-sized block."""
    out = bytearray()
    ss = len(sd)
    i = 0
    while i + bt <= ss:
        out += sd[i:i + bp]
        i += bt
    return bytes(out)


def ctr_decrypt(enc: bytes, key: bytes, iv: bytes) -> bytes:
    """SHA256-CTR decrypt, matching build_v5.py's loop."""
    out = bytearray(len(enc))
    off = 0
    ctr = 0
    while off < len(enc):
        h = hashlib.sha256(key + struct.pack("<Q", ctr) + iv).digest()
        ch = min(32, len(enc) - off)
        for i in range(ch):
            out[off + i] = enc[off + i] ^ h[i]
        off += ch
        ctr += 1
    return bytes(out)


def main():
    if len(sys.argv) < 6:
        sys.exit(__doc__)
    exe, orig, ksec, isec = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

    # --- flexible tail parser: numbers first (bps + optional bt), then names ---
    rest = sys.argv[5:]
    nums = [int(x) for x in rest if x.lstrip("-").isdigit()]
    names = [x for x in rest if not x.lstrip("-").isdigit()]
    n = len(names)
    if n < 1:
        sys.exit("[FAIL] no payload section names given")
    bps = nums[:n]
    bt = nums[n] if len(nums) > n else 256
    if len(bps) != n:
        sys.exit(f"[FAIL] expected {n} bp values, got {len(bps)}: {bps}")

    pe = open(orig, "rb").read()
    data = open(exe, "rb").read()

    sec = {nm: (ro, rs, vs) for nm, ro, rs, vs in sections(data)}
    print(f"Sections found in {exe}: {sorted(sec.keys())}")

    # recover payload from the N sections
    rec = bytearray()
    for i, name in enumerate(names):
        if name not in sec:
            print(f"[FAIL] payload section '{name}' not found")
            return 1
        ro, rs, vs = sec[name]
        # stub fs() uses min(VirtualSize, SizeOfRawData)
        read = min(rs, vs) if vs else rs
        sd = data[ro:ro + read]
        part = ep(sd, bps[i], bt)
        rec += part
        print(f"  {name}: raw={rs:,} -> recovered={len(part):,} (bp={bps[i]}, bt={bt})")

    # key / iv — same section (key at 0, iv at +32) or two separate sections
    if ksec not in sec:
        print(f"[FAIL] key/iv section not found ({ksec})")
        return 1
    kro, krs, _ = sec[ksec]
    if isec == ksec:
        # single .ksec-style section: key[0:32], iv[32:48]
        key = data[kro:kro + 32]
        iv = data[kro + 32:kro + 48]
    else:
        if isec not in sec:
            print(f"[FAIL] iv section not found ({isec})")
            return 1
        iro, irs, _ = sec[isec]
        key = data[kro:kro + 32]
        iv = data[iro:iro + 16]
    if len(key) != 32 or len(iv) != 16:
        print(f"[FAIL] key/iv size wrong: {len(key)}/{len(iv)}")
        return 1

    dec = ctr_decrypt(bytes(rec), key, iv)
    n_ = min(len(dec), len(pe))
    match = dec[:n_] == pe[:n_]
    print(f"\nRecovered stream: {len(rec):,} bytes | decrypted: {len(dec):,} | PE: {len(pe):,}")
    print(f"First {n_:,} bytes match original PE: {match}")

    if not match:
        # diagnostic: first divergence offset
        for i in range(n_):
            if dec[i] != pe[i]:
                print(f"  first divergence at offset {i} (0x{i:x})")
                print(f"  got : {dec[max(0, i - 8):i + 8].hex()}")
                print(f"  want: {pe[max(0, i - 8):i + 8].hex()}")
                return 1
    print("ROUND-TRIP PASS ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
