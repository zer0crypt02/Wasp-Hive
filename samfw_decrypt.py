#!/usr/bin/env python3
"""
samfw_decrypt.py — Samsung .enc4 firmware decryptor (Smart scheme, 2025/26)

Samsung, 2025'te FUS auth'unu komple degistirdi (eski NF_Download* uclari + AES
nonce sabitleri artuk calismiyor). Bu tool, zacharee/Bifrost 2.1.4 kaynak kodundan
port edilen GUNCEL akisi kullanir:

  1. GET  NF_SmartDownloadGenerateNonce.do  -> NONCE header (raw text)
  2. auth_param.dat icindeki white-box tablolarla ilk 16 karakter transform edilir
     -> auth imzasi (32 karakter hex)
  3. POST NF_SmartDownloadBinaryInform.do (Smart XML, IMEI YOK)
     -> BINARY_NAME / BINARY_BYTE_SIZE / BINARY_CRC / LATEST_FW_VERSION
        / LOGIC_VALUE_FACTORY
  4. key = md5( logiccheck(LATEST_FW_VERSION, LOGIC_VALUE_FACTORY) )   (16 byte)
  5. AES-128-ECB stream decrypt (unpad yok — Bifrost ile ayni parite)
  6. BINARY_CRC ile enc4 dosyasinin CRC32'si dogrulanir (butunluk kontrolu)

Kaynak referanslari:
  - zacharee/Bifrost: common/src/commonMain/kotlin/tk/zwander/common/tools/{CryptUtils,FusClient,Request}.kt
  - auth_param.dat:   common/src/commonMain/moko-resources/files/auth_param.dat

Kullanim:
  # Sadece anahtar uret + head-blok dogrulamasi:
  python3 samfw_decrypt.py -m SM-A715F -r DBT \
      -v "A715FXXSBDXB1/A715FOXMBDXB1/A715FXXSBDXB1/A715FXXSBDXB1" \
      --key-only --input firmware.zip.enc4

  # Tam decrypt:
  python3 samfw_decrypt.py -m SM-A715F -r DBT -v <FWVER> \
      --input firmware.zip.enc4 --output firmware.zip
"""

import argparse
import hashlib
import os
import struct
import sys
import xml.etree.ElementTree as ET
import zlib

import requests
from Cryptodome.Cipher import AES  # pycryptodomex namespace

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------
FUS_BASE = "https://neofussvr.sslcs.cdngc.net"
UA = "SMART 2.0"                      # Bifrost FusClient tarafindan kullanilan UA
DEFAULT_AUTH_PARAM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth_param.dat")
CHUNK = 1 << 20                       # 1 MiB decrypt blogu

# white-box transform'da kullanilan karisik indeksler (CryptUtils.kt:31)
SHIFT_INDICES = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]

# ---------------------------------------------------------------------------
# auth_param.dat: white-box tablo dosyasi
# ---------------------------------------------------------------------------

class AuthParam:
    """auth_param.dat parse + white-box transform (CryptUtils.authenticateBlock portu)."""

    def __init__(self, path: str):
        try:
            self.data = open(path, "rb").read()
        except OSError as e:
            raise RuntimeError(f"auth_param.dat acilamadi ({path}): {e}")
        if len(self.data) < 56:
            raise RuntimeError("auth_param.dat cok kucuk — bozuk dosya")
        # 56-byte header: magic, alignment, 6 blok (offset, size)
        vals = struct.unpack("<14I", self.data[:56])
        self.magic = vals[0]
        # Kotlin'deki blok eslemesi birebir (values[2..13]):
        self.b1 = (vals[2], vals[3])   # baseFinal olarak kullanilir (aslinda offset)
        self.b2 = (vals[4], vals[5])
        self.b5 = (vals[6], vals[7])
        self.b6 = (vals[8], vals[9])
        self.b3 = (vals[10], vals[11])
        self.b4 = (vals[12], vals[13])

    def _read(self, pos: int, n: int) -> bytes:
        """Stream okumasi: Kotlin'de tum pozisyonlar header(56B) sonrasina gore shift'li."""
        off = 56 + pos
        chunk = self.data[off:off + n]
        if len(chunk) != n:
            raise RuntimeError(f"auth_param.dat kisa okuma @ {pos}")
        return chunk

    def authenticate_block(self, in_block: bytes) -> bytes:
        """16 byte'lik girdiyi white-box tablo agiyla 16 byte'a donusturur."""
        base_final = self.b1[1]           # block1.size (offset olarak kullanilir)
        final_src_start = 288             # 9 * 32
        temp = [0] * 320
        for i in range(16):
            temp[i] = in_block[i]         # girdi byte'lari (unsigned)
        v15 = [0] * 64
        out = bytearray(16)

        for j in range(9):
            src_start = j * 32
            next_src_start = (j + 1) * 32
            blk_id_base = j * 16
            src_mid = src_start + 16

            # 1) round-scatter: girdiyi SHIFT_INDICES ile yay
            for idx in range(16):
                temp[src_start + 16 + idx] = temp[src_start + SHIFT_INDICES[idx]]

            for i in range(4):
                i4 = i * 4
                i16 = i * 16
                blk_id_row = blk_id_base + i4
                base262 = base_final + self.b2[1] + self.b3[1] + 6144 * (i + (j << 2))

                for k in range(4):
                    idx_val = temp[src_mid + i4 + k]
                    blk_id = blk_id_row + k
                    base257 = (blk_id << 12) + (idx_val << 4)
                    sel_offset = base_final + self.b2[1] + (blk_id << 5)
                    src16 = self._read(base257, 16)
                    sel = self._read(sel_offset, 32)
                    out_start = i16 + (k << 2)

                    # 2) bit-selektor: 32 byte'lik selector, 4 byte cikarir
                    for out_idx in range(4):
                        acc = 0
                        sel_base = out_idx * 8
                        for bit in range(8):
                            sel_byte = sel[sel_base + bit]
                            src_idx = (sel_byte >> 3) & 0x1F
                            bit_pos = 7 - (sel_byte & 7)
                            src_byte = src16[src_idx] if src_idx < 16 else 0
                            acc |= ((src_byte >> bit_pos) & 1) << (7 - bit)
                        v15[out_start + out_idx] = acc & 0xFF

                # 3) mixing tablolari (4x4x1536) — FEAL/DES benzeri tablo agi
                for k2 in range(4):
                    a1 = v15[i16 + k2]
                    a2 = v15[i16 + k2 + 4]
                    a3 = v15[i16 + k2 + 8]
                    a4 = v15[i16 + k2 + 12]
                    tbl = self._read(base262 + 1536 * k2, 1536)
                    hi1 = ((a1 & 0xF0) | (a2 >> 4)) & 0xFF
                    lo1 = (((a1 & 0x0F) << 4) | (a2 & 0x0F)) & 0xFF
                    v6 = ((tbl[hi1] << 4) ^ tbl[256 + lo1]) & 0xFF
                    hi2 = ((a3 & 0xF0) | (a4 >> 4)) & 0xFF
                    lo2 = (((a3 & 0x0F) << 4) | (a4 & 0x0F)) & 0xFF
                    v7 = ((tbl[512 + hi2] << 4) ^ tbl[768 + lo2]) & 0xFF
                    hi3 = ((v6 & 0xF0) | (v7 >> 4)) & 0xFF
                    lo3 = (((v6 & 0x0F) << 4) | (v7 & 0x0F)) & 0xFF
                    temp[next_src_start + i4 + k2] = ((tbl[1024 + hi3] << 4) ^ tbl[1280 + lo3]) & 0xFF

        # 4) final tablo: pozisyon bazli cikti secimi
        for idx in range(16):
            pos = base_final + (idx << 8) + temp[SHIFT_INDICES[idx] + final_src_start]
            out[idx] = self._read(pos, 1)[0]
        return bytes(out)


def nonce_auth_hex(auth_param: AuthParam, nonce_header: str) -> str:
    """NONCE header'inin ilk 16 karakterini transform edip hex string dondurur.

    Bifrost makeReq: decryptNonce(nonce.take(16).padEnd(16-len, '0'))
    """
    prefix = nonce_header[:16]
    if len(prefix) < 16:
        prefix = prefix.ljust(16, "0")
    return auth_param.authenticate_block(prefix.encode()).hex()


# ---------------------------------------------------------------------------
# FUS Smart client
# ---------------------------------------------------------------------------

def get_logic_check(inp: str, nonce: str) -> str:
    """Logic check: nonce karakterlerinin low-nibble'i input index'i olur (Request.kt:38)."""
    if len(inp) < 16:
        return ""
    return "".join(inp[ord(c) & 0xF] for c in nonce)


def build_binary_inform_xml(fw: str, model: str, region: str, logic_check: str) -> str:
    """Smart BinaryInform XML (Request.createBinaryInform, legacy=False birebir).

    DIKKAT: Smart yolda IMEI GONDERILMEZ (DEVICE_SN_NUMBER bos birakilir).
    """
    lc = logic_check.strip()
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<FUSMsg>",
        "<FUSHdr>",
        "<ProtoVer>1</ProtoVer>",      # Smart yolda ProtoVer "1" (legacy'de "1.0")
        "<SessionID>0</SessionID>",
        "<MsgID>1</MsgID>",
        "</FUSHdr>",
        "<FUSBody>",
        "<Put>",
        "<CmdID>1</CmdID>",
        "<REQUEST_TYPE><Data>2</Data></REQUEST_TYPE>",
        f"<BINARY_SW_VERSION><Data>{fw}</Data></BINARY_SW_VERSION>",
        "<DEVICE_SN_NUMBER><Data></Data></DEVICE_SN_NUMBER>",
        f"<BINARY_LOCAL_CODE><Data>{region}</Data></BINARY_LOCAL_CODE>",
        f"<BINARY_MODEL_NAME><Data>{model}</Data></BINARY_MODEL_NAME>",
        "<ACCESS_MODE><Data>1</Data></ACCESS_MODE>",   # Smart yolda 1 (legacy'de 2)
        "<BINARY_NATURE><Data>1</Data></BINARY_NATURE>",
        f"<LOGIC_CHECK><Data>{lc}</Data></LOGIC_CHECK>",
        "<CLIENT_LANGUAGE><Type>String</Type>"
        "<Type>ISO 3166-1-alpha-3</Type><Data>1033</Data></CLIENT_LANGUAGE>",
        "</Put>",
        "<Get>",
        "<CmdID>2</CmdID>",
        "<BINARY_SW_VERSION></BINARY_SW_VERSION>",
        "</Get>",
        "</FUSBody>",
        "</FUSMsg>",
    ]
    return "".join(parts)


class FusSmart:
    """NF_SmartDownload* endpoint client'i (FusClient.kt portu)."""

    def __init__(self, auth_param: AuthParam):
        self.auth_param = auth_param
        self.sess = requests.Session()
        self.nonce = ""   # NONCE header'inin RAW text'i
        self.auth = ""    # white-box transform'dan gelen 32 karakter hex
        self.session_id = ""

    def _auth_header(self, include_nonce: bool) -> str:
        """Authorization degeri (FusClient.getAuthV, signature=null yolu)."""
        n = self.nonce if include_nonce else ""
        sig = self.auth
        return f'FUS nonce="{n}", signature="{sig}", nc="", type="", realm=""'

    def _common_headers(self, authv: str) -> dict:
        return {
            "Authorization": authv,
            "User-Agent": UA,
            "Cookie": f"JSESSIONID={self.session_id};SESSION={self.session_id}",
            "Set-Cookie": f"JSESSIONID={self.session_id};SESSION={self.session_id}",
        }

    def _update_nonce_from(self, resp: requests.Response) -> None:
        """Yanittaki NONCE header'ini isle (raw text + white-box auth)."""
        enc = resp.headers.get("NONCE") or resp.headers.get("nonce")
        if enc is None:
            return
        self.nonce = enc
        try:
            self.auth = nonce_auth_hex(self.auth_param, self.nonce)
        except (RuntimeError, ValueError) as e:
            print(f"UYARI: nonce transform basarisiz: {e}", file=sys.stderr)

    def _update_session(self, resp: requests.Response) -> None:
        sc = resp.headers.get("Set-Cookie")
        if sc and ("JSESSIONID=" in sc or "SESSION=" in sc):
            val = sc.replace("JSESSIONID=", "").replace("SESSION=", "")
            self.session_id = val.split(";")[0]

    def generate_nonce(self) -> None:
        """NF_SmartDownloadGenerateNonce — oturum ac (Bifrost makeReq, GENERATE_NONCE)."""
        authv = self._auth_header(include_nonce=True)  # nonce henuz bos -> nonce=""
        r = self.sess.get(
            f"{FUS_BASE}/NF_SmartDownloadGenerateNonce.do",
            headers=self._common_headers(authv),
            timeout=60,
        )
        r.raise_for_status()
        self._update_nonce_from(r)
        self._update_session(r)
        if not self.nonce:
            raise RuntimeError("GenerateNonce yanitinda NONCE header yok")

    def binary_inform(self, fw: str, model: str, region: str, include_nonce: bool) -> dict:
        """NF_SmartDownloadBinaryInform — firmware bilgisi + anahtar malzemesi."""
        if not self.nonce:
            self.generate_nonce()
        lc = get_logic_check(fw.upper(), self.nonce)  # Bifrost: fw.uppercase()
        xml_req = build_binary_inform_xml(fw.upper(), model, region, lc)
        authv = self._auth_header(include_nonce=include_nonce)
        r = self.sess.post(
            f"{FUS_BASE}/NF_SmartDownloadBinaryInform.do",
            data=xml_req.encode(),
            headers=self._common_headers(authv),
            timeout=60,
        )
        r.raise_for_status()
        self._update_nonce_from(r)
        self._update_session(r)

        root = ET.fromstring(r.text)

        def data_of(tag: str):
            el = root.find(f"./FUSBody/Put/{tag}/Data")
            return el.text if (el is not None and el.text) else None

        def result_of(tag: str):
            el = root.find(f"./FUSBody/Results/{tag}/Data")
            return el.text if (el is not None and el.text) else None

        status = root.find("./FUSBody/Results/Status")
        status = status.text if (status is not None and status.text) else None
        if status not in ("200", "S00"):
            raise RuntimeError(f"BinaryInform status={status} "
                               f"(408=IMEI/serial reddi, F01=gecersiz firmware)")

        # Anahtar malzemesi: LATEST_FW_VERSION -> yoksa BINARY_SW_VERSION
        fwver = result_of("LATEST_FW_VERSION") or result_of("BINARY_SW_VERSION")
        logic_val = data_of("LOGIC_VALUE_FACTORY") or data_of("LOGIC_VALUE_HOME")
        info = {
            "binary_name": data_of("BINARY_NAME"),
            "binary_size": data_of("BINARY_BYTE_SIZE"),
            "binary_crc": data_of("BINARY_CRC"),
            "model_path": data_of("MODEL_PATH"),
            "fw_version": fwver,
            "logic_value": logic_val,
        }
        if not info["binary_name"] or not info["binary_size"]:
            raise RuntimeError("BinaryInform yanitinda binary adi/boyutu yok")
        return info


# ---------------------------------------------------------------------------
# Dosya islemleri
# ---------------------------------------------------------------------------

def crc32_file(path: str, verbose: bool = False) -> int:
    """Dosyanin CRC32'si (chunked; enc4 butunluk dogrulamasi icin)."""
    crc = 0
    read = 0
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            crc = zlib.crc32(block, crc)
            read += len(block)
            if verbose and read % (1 << 30) < CHUNK:
                print(f"  crc: {read/1e9:.2f} GB islendi", flush=True)
    return crc & 0xFFFFFFFF


def derive_key(fw_version: str, logic_value: str) -> bytes:
    """V4 anahtari: md5(logiccheck(fwver, logicval)) — extractV4Key portu."""
    dec_key = get_logic_check(fw_version, logic_value)
    if not dec_key:
        raise ValueError(f"logic check cok kisa: fwver='{fw_version}' logicval='{logic_value}'")
    return hashlib.md5(dec_key.encode()).digest()


def head_test(path: str, key: bytes) -> bytes:
    """Ilk 16 byte'i decrypt et — dogru anahtarda zip imzasi (PK\\x03\\x04) beklenir."""
    with open(path, "rb") as f:
        first = f.read(16)
    if len(first) < 16:
        raise ValueError("dosya 16 byte'tan kucuk")
    return AES.new(key, AES.MODE_ECB).decrypt(first)


def decrypt_stream(inp: str, outp: str, key: bytes, verbose: bool) -> int:
    """Tam decrypt: AES-128-ECB stream. Unpad YOK (Bifrost decryptProgress paritesi)."""
    size = os.path.getsize(inp)
    if size % 16 != 0:
        raise ValueError(f"dosya boyutu 16'nin kati degil ({size})")
    cipher = AES.new(key, AES.MODE_ECB)
    written = 0
    next_report = 0
    with open(inp, "rb") as fi, open(outp, "wb") as fo:
        remaining = size
        while remaining > 0:
            n = min(CHUNK, remaining)
            block = fi.read(n)
            if len(block) != n:
                raise IOError(f"kisa okuma {len(block)}/{n} — dosya bozuk?")
            fo.write(cipher.decrypt(block))
            written += n
            remaining -= n
            if verbose and written >= next_report:
                print(f"  {100.0*written/size:5.1f}%  ({written/1e9:.2f} GB)", flush=True)
                next_report += (1 << 29)  # 512 MiB'de bir
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run_with_key(args) -> int:
    """--key yolu: anahtar hazir (JVM/Bifrost'dan geldigi dogrulanmis).
    Ag akisi tamamen atlanir — sadece CRC + head test + decrypt yapilir."""
    try:
        key = bytes.fromhex(args.key)
    except ValueError as e:
        print(f"HATA: anahtar hex formati gecersiz: {e}", file=sys.stderr)
        return 11
    if len(key) != 16:
        print(f"HATA: anahtar 16 byte olmali ({len(key)} geldi)", file=sys.stderr)
        return 11
    print("AES key :", key.hex(), "(harici — ag akisi atlandi)")

    if not args.input:
        print("(--input verilmedi — sadece anahtar yazildi)")
        return 0

    # enc4 butunluk: BINARY_CRC ile karsilastir
    if args.crc and not args.skip_crc:
        local = crc32_file(args.input, verbose=args.verbose)
        ok = (args.crc & 0xFFFFFFFF) == local
        print(f"crc     : local={local:08x} remote={args.crc & 0xFFFFFFFF:08x} "
              f"{'✔ DOSYA SAGLAM' if ok else '✗ DOSYA BOZUK/YARIM'}")
        if not ok:
            return 5

    # Head-blok dogrulamasi: dogru anahtar -> zip imzasi
    pt = head_test(args.input, key)
    print("head    :", pt[:8].hex(), repr(pt[:4]))
    if pt[:4] != b"PK\x03\x04":
        print("SONUC: ANAHTAR YANLIS ✗  (ilk blok zip degil)")
        return 4
    print("SONUC: ANAHTAR DOGRU ✔")

    if args.key_only:
        return 0
    if not args.output:
        print("HATA: --output gerekli")
        return 1

    written = decrypt_stream(args.input, args.output, key, args.verbose)
    print(f"decrypt : {args.output}  ({written/1e9:.3f} GB)")
    with open(args.output, "rb") as f:
        head = f.read(8)
        f.seek(-8, 2)
        tail = f.read(8)
    print("output  : head =", head.hex(), " tail =", tail.hex())
    return 0


def get_args():
    p = argparse.ArgumentParser(
        description="Samsung .enc4 firmware decryptor (Smart scheme, 2025/26 — Bifrost portu)",
        epilog="Ornek: python3 samfw_decrypt.py -m SM-A715F -r DBT "
               '-v "A715FXXSBDXB1/A715FOXMBDXB1/A715FXXSBDXB1/A715FXXSBDXB1" '
               "--key-only --input fw.zip.enc4",
    )
    p.add_argument("-m", "--model", required=True, help="cihaz modeli (SM-A715F)")
    p.add_argument("-r", "--region", required=True, help="bolge kodu (DBT)")
    p.add_argument("-v", "--fwver", required=True, help="firmware surumu (PDA/CSC/PDA/CSC)")
    p.add_argument("--key-only", action="store_true", help="anahtar uret + head test, decrypt yapma")
    p.add_argument("--input", help="sifreli .enc4 dosyasi")
    p.add_argument("--output", help="decrypt ciktisi (.zip)")
    p.add_argument("--skip-crc", action="store_true", help="BINARY_CRC butunluk kontrolunu atla (hizli)")
    p.add_argument("--key", help="hazir AES-128 anahtari (hex) — ag akisini atlar (JVM'den gelen)")
    p.add_argument("--crc", type=lambda s: int(s, 0), help="beklenen CRC32 (BINARY_CRC, decimal) — --key ile kullanilir")
    p.add_argument("--authparam", default=DEFAULT_AUTH_PARAM, help="auth_param.dat yolu")
    p.add_argument("--verbose", action="store_true", help="ayrintili cikti")
    if len(sys.argv) == 1:
        p.print_help()
        sys.exit(0)
    return p.parse_args()


def main() -> int:
    args = get_args()
    try:
        # Harici anahtar yolu: ag akisi olmadan dogrudan islem
        if args.key:
            return run_with_key(args)

        # 1) auth_param.dat yukle (white-box tablolari)
        ap = AuthParam(args.authparam)
        if args.verbose:
            print(f"auth_param.dat: {len(ap.data)} byte, magic=0x{ap.magic:x}")

        # 2) Smart oturum: nonce + auth imzasi
        fus = FusSmart(ap)
        fus.generate_nonce()
        if args.verbose:
            print(f"nonce header : {fus.nonce!r}")
            print(f"auth imzasi  : {fus.auth}")

        # 3) BinaryInform -> anahtar malzemesi
        #    (Decrypter yolu: includeNonce=TRUE)
        info = fus.binary_inform(args.fwver, args.model, args.region, include_nonce=True)
        print("binary  :", info["binary_name"])
        print("size    :", info["binary_size"])
        print("crc32   :", info["binary_crc"])
        print("fw ver  :", info["fw_version"])
        print("logicval:", repr(info["logic_value"]))
        if not info["logic_value"]:
            print("UYARI: LOGIC_VALUE_FACTORY/HOME bos — anahtar turetilemez")

        # 4) Anahtar turet
        key = derive_key(info["fw_version"], info["logic_value"])
        print("AES key :", key.hex())

        if not args.input:
            if args.key_only:
                print("(head test atlandi — --input verilmedi)")
                return 0
            print("HATA: decrypt icin --input ve --output gerekli")
            return 1

        # 5) enc4 butunluk: CRC32 kontrolu
        if info["binary_crc"] and not args.skip_crc:
            remote = int(info["binary_crc"]) & 0xFFFFFFFF
            local = crc32_file(args.input, verbose=args.verbose)
            ok = remote == local
            print(f"crc     : local={local:08x} remote={remote:08x} "
                  f"{'✔ DOSYA SAGLAM' if ok else '✗ DOSYA BOZUK/YARIM'}")
            if not ok:
                return 5

        # 6) Head-blok dogrulamasi
        pt = head_test(args.input, key)
        print("head    :", pt[:8].hex(), repr(pt[:4]))
        if pt[:4] != b"PK\x03\x04":
            print("SONUC: ANAHTAR YANLIS ✗  (ilk blok zip degil)")
            print("  -> Dosya, indirme oturumuna bagli olabilir; yeniden indirme gerekebilir.")
            return 4
        print("SONUC: ANAHTAR DOGRU ✔")

        if args.key_only:
            return 0
        if not args.output:
            print("HATA: --output gerekli")
            return 1

        # 7) Tam decrypt
        written = decrypt_stream(args.input, args.output, key, args.verbose)
        print(f"decrypt : {args.output}  ({written/1e9:.3f} GB)")
        with open(args.output, "rb") as f:
            head = f.read(8)
            f.seek(-8, 2)
            tail = f.read(8)
        print("output  : head =", head.hex(), " tail =", tail.hex())
        return 0

    except requests.RequestException as e:
        print(f"AG HATASI: {e}", file=sys.stderr)
        return 10
    except (ValueError, RuntimeError, OSError, KeyError) as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 11


if __name__ == "__main__":
    sys.exit(main())
