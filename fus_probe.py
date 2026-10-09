#!/usr/bin/env python3
"""FUS probe — legacy + Smart endpoint varyantlarini dogru cookie/nonce/UA ile test eder."""

import xml.etree.ElementTree as ET

import requests

from samfw_decrypt import AuthParam, nonce_auth_hex, get_logic_check

FUS = "https://neofussvr.sslcs.cdngc.net"


def get_logic_check16(inp: str, nonce: str) -> str:
    """Legacy beklenen form: nonce 16 karakter genisliginde."""
    if len(inp) < 16:
        return ""
    return "".join(inp[ord(c) & 0xF] for c in nonce)


class Probe:
    def __init__(self, ap: AuthParam):
        self.ap = ap
        self.s = requests.Session()
        self.nonce = ""      # NONCE header'inin ilk 16 karakteri
        self.auth = ""
        self.jsessionid = ""
        self.session = ""

    def cookie_header(self):
        parts = []
        if self.jsessionid:
            parts.append(f"JSESSIONID={self.jsessionid}")
        if self.session:
            parts.append(f"SESSION={self.session}")
        return ";".join(parts)

    def consume(self, r: requests.Response):
        # NONCE: raw header'in ilk 16 karakteri hem nonce hem white-box girdisi
        enc = r.headers.get("NONCE") or r.headers.get("nonce")
        if enc:
            self.nonce = enc[:16]
            self.auth = nonce_auth_hex(self.ap, self.nonce)
        # Cerezler: JSESSIONID ve SESSION ayri ayrı (FusClientLegacy.cookieHeader paritesi)
        for name in ("JSESSIONID", "SESSION"):
            val = r.cookies.get(name)
            if val:
                if name == "JSESSIONID":
                    self.jsessionid = val
                else:
                    self.session = val

    def auth_header(self, include_nonce=True, newauth=False):
        n = self.nonce if include_nonce else ""
        extra = ', newauth="1"' if newauth else ""
        return f'FUS nonce="{n}", signature="{self.auth}", nc="", type="", realm=""{extra}'


def legacy_inform_xml(fw, model, region, imei, nonce16):
    pda, csc, phone, data = (fw.split("/") + [None, None, None, None])[:4]
    lc = get_logic_check16(fw.upper(), nonce16)
    parts = [
        "<FUSMsg><FUSHdr><ProtoVer>1.0</ProtoVer></FUSHdr><FUSBody><Put>",
        "<CLIENT_PRODUCT><Data>Smart Switch</Data></CLIENT_PRODUCT>",
        "<CLIENT_VERSION><Data>4.3.23123_1</Data></CLIENT_VERSION>",
        f"<DEVICE_IMEI_PUSH><Data>{imei}</Data></DEVICE_IMEI_PUSH>",
        f"<DEVICE_FW_VERSION><Data>{fw}</Data></DEVICE_FW_VERSION>",
        f"<DEVICE_LOCAL_CODE><Data>{region}</Data></DEVICE_LOCAL_CODE>",
        f"<DEVICE_AID_CODE><Data>{region}</Data></DEVICE_AID_CODE>",
        f"<DEVICE_MODEL_NAME><Data>{model}</Data></DEVICE_MODEL_NAME>",
        f"<DEVICE_CONTENTS_DATA_VERSION><Data>{data or ''}</Data></DEVICE_CONTENTS_DATA_VERSION>",
        f"<DEVICE_CSC_CODE2_VERSION><Data>{csc or ''}</Data></DEVICE_CSC_CODE2_VERSION>",
        f"<DEVICE_PDA_CODE1_VERSION><Data>{pda or ''}</Data></DEVICE_PDA_CODE1_VERSION>",
        f"<DEVICE_PHONE_FONT_VERSION><Data>{phone or ''}</Data></DEVICE_PHONE_FONT_VERSION>",
        "<ACCESS_MODE><Data>2</Data></ACCESS_MODE>",
        "<BINARY_NATURE><Data>1</Data></BINARY_NATURE>",
        f"<LOGIC_CHECK><Data>{lc}</Data></LOGIC_CHECK>",
        "<CLIENT_LANGUAGE><Type>String</Type><Type>ISO 3166-1-alpha-3</Type>"
        "<Data>1033</Data></CLIENT_LANGUAGE>",
        "</Put><Get><LATEST_FW_VERSION/></Get></FUSBody></FUSMsg>",
    ]
    return "".join(parts)


def status_of(body):
    try:
        el = ET.fromstring(body).find("./FUSBody/Results/Status")
        return el.text if el is not None else None
    except ET.ParseError:
        return "(XML degil)"


def main():
    FW = "A715FXXSBDXB1/A715FOXMBDXB1/A715FXXSBDXB1/A715FXXSBDXB1"
    MODEL, REGION, IMEI = "SM-A715F", "DBT", "350000029442064"

    ap = AuthParam("auth_param.dat")

    # ---- 1) LEGACY endpoint (UA = Kiss2.0_FUS) ----
    p = Probe(ap)
    print("== 1) LEGACY GenerateNonce (Kiss2.0_FUS) ==")
    r = p.s.get(f"{FUS}/NF_DownloadGenerateNonce.do",
                headers={"Authorization": 'FUS nonce="", signature="", nc="", type="", realm=""',
                         "User-Agent": "Kiss2.0_FUS"},
                timeout=60)
    print("HTTP", r.status_code)
    for k, v in r.headers.items():
        if k.lower() in ("set-cookie", "nonce", "server", "content-type"):
            print(f"  <- {k}: {v}")
    print("  body:", r.text[:200])
    p.consume(r)
    print(f"  nonce={p.nonce!r} auth={p.auth} cookies: js={p.jsessionid!r} sess={p.session!r}")

    print("== 2) LEGACY BinaryInform (imei'li XML, nonce16 imzali) ==")
    xml = legacy_inform_xml(FW, MODEL, REGION, IMEI, p.nonce)
    hdrs = {"Authorization": p.auth_header(include_nonce=True),
            "User-Agent": "Kiss2.0_FUS"}
    ck = p.cookie_header()
    if ck:
        hdrs["Cookie"] = ck
    r = p.s.post(f"{FUS}/NF_DownloadBinaryInform.do", data=xml.encode(), headers=hdrs, timeout=60)
    print("HTTP", r.status_code, " body Status:", status_of(r.text))
    print("  NONCE hdr:", r.headers.get("NONCE"))
    print("  body:", r.text[:800])
    p.consume(r)
    print(f"  yeni nonce={p.nonce!r} auth={p.auth} js={p.jsessionid!r} sess={p.session!r}")

    # 401 ise: yeni nonce ile BODY'YI yeniden kurup retry (Bifrost davranisi)
    st = status_of(r.text)
    if st == "401":
        print("== 3) 401 sonrasi yeni nonce ile retry ==")
        xml = legacy_inform_xml(FW, MODEL, REGION, IMEI, p.nonce)
        hdrs = {"Authorization": p.auth_header(include_nonce=True),
                "User-Agent": "Kiss2.0_FUS"}
        ck = p.cookie_header()
        if ck:
            hdrs["Cookie"] = ck
        r = p.s.post(f"{FUS}/NF_DownloadBinaryInform.do", data=xml.encode(), headers=hdrs, timeout=60)
        print("HTTP", r.status_code, " body Status:", status_of(r.text))
        print("  body:", r.text[:1200])
        p.consume(r)

    # ---- 4) SMART endpoint (UA = SMART 2.0, temiz cerezler) ----
    q = Probe(ap)
    print("\n== 4) SMART GenerateNonce ==")
    r = q.s.get(f"{FUS}/NF_SmartDownloadGenerateNonce.do",
                headers={"Authorization": 'FUS nonce="", signature="", nc="", type="", realm=""',
                         "User-Agent": "SMART 2.0"},
                timeout=60)
    print("HTTP", r.status_code)
    for k, v in r.headers.items():
        if k.lower() in ("set-cookie", "nonce", "server", "content-type"):
            print(f"  <- {k}: {v}")
    q.consume(r)
    print(f"  nonce={q.nonce!r} auth={q.auth} js={q.jsessionid!r} sess={q.session!r}")


if __name__ == "__main__":
    main()
