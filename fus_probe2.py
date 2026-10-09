#!/usr/bin/env python3
"""FUS probe v2 — requests cookie jar'i YOK (Bifrost parite): sadece manuel Cookie header."""

import xml.etree.ElementTree as ET

import requests

from samfw_decrypt import AuthParam, nonce_auth_hex

FUS = "https://neofussvr.sslcs.cdngc.net"


def logic_check(inp: str, nonce: str) -> str:
    if len(inp) < 16:
        return ""
    return "".join(inp[ord(c) & 0xF] for c in nonce)


def stateless(method, url, headers, data=None):
    """Her istek TAMAMEN bagimsiz: module-level request — cookie kaliciligi YOK."""
    return requests.request(method, url, headers=headers, data=data, timeout=60)


class Client:
    def __init__(self, ap: AuthParam):
        self.ap = ap
        self.nonce = ""
        self.auth = ""
        self.jsessionid = ""
        self.session = ""

    def consume(self, r):
        enc = r.headers.get("NONCE") or r.headers.get("nonce")
        if enc:
            self.nonce = enc[:16]
            self.auth = nonce_auth_hex(self.ap, self.nonce)
        for c in r.headers.get("Set-Cookie", "").split(","):
            pair = c.split(";")[0].strip()
            if pair.startswith("JSESSIONID="):
                self.jsessionid = pair[len("JSESSIONID="):]
            elif pair.startswith("SESSION="):
                self.session = pair[len("SESSION="):]

    def legacy_cookie(self):
        parts = []
        if self.jsessionid:
            parts.append(f"JSESSIONID={self.jsessionid}")
        if self.session:
            parts.append(f"SESSION={self.session}")
        return ";".join(parts)

    def smart_cookie(self):
        # FusClient (Smart): JSESSIONID=<v>;SESSION=<v> — ayni deger
        return f"JSESSIONID={self.session};SESSION={self.session}"


def legacy_inform_xml(fw, model, region, imei, nonce16):
    pda, csc, phone, data = (fw.split("/") + [None, None, None, None])[:4]
    lc = logic_check(fw.upper(), nonce16)
    return (
        "<FUSMsg><FUSHdr><ProtoVer>1.0</ProtoVer></FUSHdr><FUSBody><Put>"
        "<CLIENT_PRODUCT><Data>Smart Switch</Data></CLIENT_PRODUCT>"
        "<CLIENT_VERSION><Data>4.3.23123_1</Data></CLIENT_VERSION>"
        f"<DEVICE_IMEI_PUSH><Data>{imei}</Data></DEVICE_IMEI_PUSH>"
        f"<DEVICE_FW_VERSION><Data>{fw}</Data></DEVICE_FW_VERSION>"
        f"<DEVICE_LOCAL_CODE><Data>{region}</Data></DEVICE_LOCAL_CODE>"
        f"<DEVICE_AID_CODE><Data>{region}</Data></DEVICE_AID_CODE>"
        f"<DEVICE_MODEL_NAME><Data>{model}</Data></DEVICE_MODEL_NAME>"
        f"<DEVICE_CONTENTS_DATA_VERSION><Data>{data or ''}</Data></DEVICE_CONTENTS_DATA_VERSION>"
        f"<DEVICE_CSC_CODE2_VERSION><Data>{csc or ''}</Data></DEVICE_CSC_CODE2_VERSION>"
        f"<DEVICE_PDA_CODE1_VERSION><Data>{pda or ''}</Data></DEVICE_PDA_CODE1_VERSION>"
        f"<DEVICE_PHONE_FONT_VERSION><Data>{phone or ''}</Data></DEVICE_PHONE_FONT_VERSION>"
        "<ACCESS_MODE><Data>2</Data></ACCESS_MODE>"
        "<BINARY_NATURE><Data>1</Data></BINARY_NATURE>"
        f"<LOGIC_CHECK><Data>{lc}</Data></LOGIC_CHECK>"
        "<CLIENT_LANGUAGE><Type>String</Type><Type>ISO 3166-1-alpha-3</Type>"
        "<Data>1033</Data></CLIENT_LANGUAGE>"
        "</Put><Get><LATEST_FW_VERSION/></Get></FUSBody></FUSMsg>"
    )


def smart_inform_xml(fw, model, region, nonce_full):
    lc = logic_check(fw.upper(), nonce_full)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<FUSMsg><FUSHdr><ProtoVer>1</ProtoVer><SessionID>0</SessionID><MsgID>1</MsgID></FUSHdr>"
        "<FUSBody><Put><CmdID>1</CmdID>"
        "<REQUEST_TYPE><Data>2</Data></REQUEST_TYPE>"
        f"<BINARY_SW_VERSION><Data>{fw.upper()}</Data></BINARY_SW_VERSION>"
        "<DEVICE_SN_NUMBER><Data></Data></DEVICE_SN_NUMBER>"
        f"<BINARY_LOCAL_CODE><Data>{region}</Data></BINARY_LOCAL_CODE>"
        f"<BINARY_MODEL_NAME><Data>{model}</Data></BINARY_MODEL_NAME>"
        "<ACCESS_MODE><Data>1</Data></ACCESS_MODE>"
        "<BINARY_NATURE><Data>1</Data></BINARY_NATURE>"
        f"<LOGIC_CHECK><Data>{lc}</Data></LOGIC_CHECK>"
        "<CLIENT_LANGUAGE><Type>String</Type><Type>ISO 3166-1-alpha-3</Type>"
        "<Data>1033</Data></CLIENT_LANGUAGE>"
        "</Put><Get><CmdID>2</CmdID><BINARY_SW_VERSION></BINARY_SW_VERSION></Get>"
        "</FUSBody></FUSMsg>"
    )


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

    # ---------- LEGACY ----------
    c = Client(ap)
    print("== L1) legacy GenerateNonce (stateless) ==")
    r = stateless("GET", f"{FUS}/NF_DownloadGenerateNonce.do",
                  {"Authorization": 'FUS nonce="", signature="", nc="", type="", realm=""',
                   "User-Agent": "Kiss2.0_FUS"})
    print("HTTP", r.status_code, "nonce:", r.headers.get("NONCE", "")[:24], "...")
    c.consume(r)
    print(f"   nonce16={c.nonce!r} auth={c.auth} sess={c.session[:12]!r}...")

    for label, xml, extra in [
        ("L2) imei'li XML", legacy_inform_xml(FW, MODEL, REGION, IMEI, c.nonce), {}),
        ("L3) imei'li XML + text/plain", legacy_inform_xml(FW, MODEL, REGION, IMEI, c.nonce),
         {"Content-Type": "text/plain; charset=UTF-8"}),
    ]:
        hdrs = {"Authorization": f'FUS nonce="{c.nonce}", signature="{c.auth}", nc="", type="", realm=""',
                "User-Agent": "Kiss2.0_FUS"}
        ck = c.legacy_cookie()
        if ck:
            hdrs["Cookie"] = ck
        hdrs.update(extra)
        r = stateless("POST", f"{FUS}/NF_DownloadBinaryInform.do", hdrs, xml.encode())
        st = status_of(r.text)
        print(f"== {label}: HTTP={r.status_code} Status={st}")
        if st in ("200", "S00"):
            print(r.text[:1500])
            return
        print("   ", r.text[100:400])
        c.consume(r)

    # ---------- SMART ----------
    d = Client(ap)
    print("\n== S1) smart GenerateNonce (stateless) ==")
    r = stateless("GET", f"{FUS}/NF_SmartDownloadGenerateNonce.do",
                  {"Authorization": 'FUS nonce="", signature="", nc="", type="", realm=""',
                   "User-Agent": "SMART 2.0"})
    print("HTTP", r.status_code, "nonce:", r.headers.get("NONCE"))
    d.consume(r)
    print(f"   nonce={d.nonce!r} auth={d.auth} sess={d.session[:12]!r}...")

    # Smart: Bifrost Decrypter yolu includeNonce=false -> header nonce="".
    # Ama FusClientLegacy yorumuna gore non-cloud icin nonce her zaman gidiyor.
    # Her iki varyanti da dene.
    for label, nonce_hdr, xml, ckfun in [
        ("S2) smart, header-nonce=YOK (Decrypter yolu)", "", smart_inform_xml(FW, MODEL, REGION, d.nonce), d.smart_cookie),
        ("S3) smart, header-nonce=VAR (legacy-parite)", d.nonce, smart_inform_xml(FW, MODEL, REGION, d.nonce), d.smart_cookie),
    ]:
        hdrs = {"Authorization": f'FUS nonce="{nonce_hdr}", signature="{d.auth}", nc="", type="", realm=""',
                "User-Agent": "SMART 2.0",
                "Cookie": ckfun(),
                "Set-Cookie": ckfun()}
        r = stateless("POST", f"{FUS}/NF_SmartDownloadBinaryInform.do", hdrs, xml.encode())
        st = status_of(r.text)
        print(f"== {label}: HTTP={r.status_code} Status={st}")
        if st in ("200", "S00"):
            print(r.text[:1500])
            return
        print("   ", r.text[100:400])
        d.consume(r)


if __name__ == "__main__":
    main()
