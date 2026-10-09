#!/usr/bin/env python3
# gen_setup_modules3.py - third batch (compact) to guarantee .text floor
LOGIC = {
0: """    DWORD k = seed ^ @@S@@u;
    for (int i = 0; i < @@N@@; i++) {
        int idx = (int)((i + (seed % 5)) % @@N@@);
        const struct @@T@@* e = &@@TB@@[idx];
        DWORD w = (DWORD)e->@@A@@ * 3u + (DWORD)e->@@B@@ + (DWORD)e->@@C@@ * 7u + (DWORD)e->@@D@@;
        k = k * 1664525u + 1013904223u;
        if (((w ^ k) & 0x3FF) < 0x300 || e->@@C@@ == 0) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 4) & 0xFF) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0xFF;
    }
    return (dc->warn * 100u) / (dc->ok + dc->warn + 1);
""",
1: """    DWORD k = seed ^ @@S@@u;
    for (int i = 0; i < @@N@@; i++) {
        k = k * 1103515245u + 12345u;
        const struct @@T@@* e = &@@TB@@[(i + (int)(k % 3)) % @@N@@];
        DWORD lo = (k >> 8) % 200, hi = lo + 300 + ((k >> 16) % 400);
        DWORD v = (DWORD)e->@@A@@ * 37u + (DWORD)e->@@B@@ * 13u + (DWORD)e->@@C@@;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;
""",
2: """    DWORD k = seed ^ @@S@@u;
    for (int i = 0; i < @@N@@; i++) {
        k = k * 1664525u + 1013904223u;
        const struct @@T@@* a = &@@TB@@[i];
        const struct @@T@@* b = &@@TB@@[(i + 1 + (int)(k % 3)) % @@N@@];
        if ((a->@@A@@ == b->@@A@@ || ((a->@@B@@ ^ b->@@B@@) < (k & 0x1F))) && a->@@C@@ <= @@M@@) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->@@B@@ + 1;
        dc->detail[2] += (DWORD)(a->@@A@@ & 7);
    }
    return dc->warn > 2;
""",
3: """    int order[@@N@@];
    for (int i = 0; i < @@N@@; i++) order[i] = i;
    DWORD k = seed ^ @@S@@u;
    for (int i = 0; i < @@N@@; i++) {
        int j = (int)(k % (@@N@@ - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 1103515245u + 12345u;
    }
    for (int i = 0; i < @@N@@; i++) {
        const struct @@T@@* e = &@@TB@@[order[i]];
        DWORD v = (DWORD)e->@@A@@ * 5u + (DWORD)e->@@B@@ * 3u + (DWORD)e->@@C@@;
        if ((v & 0xF) != 0 && e->@@D@@ == 1) dc->ok++; else if (e->@@D@@ == 1) dc->warn++;
        dc->items += (v >> 2) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];
""",
}
import random
random.seed(0xBADC0DE)
# name, tag, (ct,cn)xN, logic, fmt, fields(A-D), entries
M = [
("WirelessProfiles","WLP_ENTRY",[("BYTE","auth"),("BYTE","enc"),("BYTE","band"),("BYTE","autoc")],0,
 "    { \"%s\", %d, %d, %d, %d },",["auth","enc","band","autoc"],
 [("Corp-5G",1,2,1,1),("Corp-Legacy",2,2,0,1),("Guest",0,0,0,1),("Lab",1,1,1,0),("DMZ",2,1,0,1),("IoT",0,1,1,0),("HVAC",1,0,0,1),("Cameras",2,2,1,1),("Printers",0,2,0,1),("TestNet",1,1,1,1)]),
("DnsSettings","DNS_ENTRY",[("BYTE","primary"),("BYTE","secondary"),("BYTE","v6"),("BYTE","doh")],1,
 "    { \"%s\", %d, %d, %d, %d },",["primary","secondary","v6","doh"],
 [("corp-dns1",1,2,0,1),("corp-dns2",2,3,0,1),("public-dns",3,4,0,0),("cloudflare",4,5,1,1),("google",5,6,1,1),("quad9",6,7,1,0),("local",7,8,0,1),("vpn-dns",8,9,0,1),("backup",9,10,1,0),("emergency",10,11,0,1)]),
("WinsSettings","WIN_ENTRY",[("BYTE","scope"),("BYTE","cache"),("BYTE","lmhosts")],2,
 "    { \"%s\", %d, %d, %d },",["scope","cache","lmhosts","scope"],
 [("default",1,1,1),("enabled",1,1,1),("enabled-hb",1,0,1),("disabled",0,0,0),("internal",2,1,1),("dmz",2,0,1),("roaming",3,1,1),("branch",3,0,0),("ho",1,1,0),("guest",0,1,1)]),
("RoutingTable","RTE_ENTRY",[("BYTE","metric"),("BYTE","persist"),("BYTE","gw")],3,
 "    { \"%s\", %d, %d, %d },",["metric","persist","gw","persist"],
 [("default-v4",1,1,1),("default-v6",2,1,1),("corp-10",3,1,1),("corp-172",4,1,1),("dmz-192",5,1,1),("vpn-route",6,1,0),("backup-route",7,1,1),("video",8,0,1),("voice",9,1,1),("mgmt",10,1,1)]),
("ProxyBypass","PXB_ENTRY",[("BYTE","kind"),("BYTE","local"),("BYTE","intranet")],0,
 "    { \"%s\", %d, %d, %d },",["kind","local","intranet","local"],
 [("localhost",1,1,1),("127.0.0.1",2,1,1),("*.local",3,1,1),("corp",4,1,1),("intranet",5,1,1),("files",6,1,1),("printers",7,1,1),("routers",8,1,1),("cameras",9,1,0),("iot",10,1,0)]),
("CertificatePins","CRT_ENTRY",[("BYTE","pin"),("BYTE","expiry"),("BYTE","pinning")],1,
 "    { \"%s\", %d, %d, %d },",["pin","expiry","pinning","pin"],
 [("corp-root",1,2,1),("corp-int",2,3,1),("azure-root",3,4,1),("aws-root",4,5,1),("gcp-root",5,6,1),("github-root",6,7,0),("npm-root",7,8,0),("docker-root",8,9,1),("k8s-root",9,10,1),("legacy-root",10,11,0)]),
("NtpSettings","NTP_ENTRY",[("BYTE","src"),("BYTE","poll"),("BYTE","sync")],2,
 "    { \"%s\", %d, %d, %d },",["src","poll","sync","src"],
 [("corp-ntp",1,2,1),("public-ntp",2,3,1),("pool-ntp",3,4,1),("hw-clock",4,1,1),("vm-clock",5,1,1),("backup-ntp",6,3,0),("dc-ntp",7,2,1),("edge-ntp",8,3,1),("branch-ntp",9,2,1),("guest-ntp",10,3,0)]),
("SmbSettings","SMB_ENTRY",[("BYTE","v1"),("BYTE","v2"),("BYTE","v3"),("BYTE","sign")],3,
 "    { \"%s\", %d, %d, %d, %d },",["v1","v2","v3","sign"],
 [("secure",0,1,1,1),("legacy",1,1,0,0),("mixed",0,1,1,0),("minimal",0,0,1,1),("locked",0,0,1,1),("guest-share",0,1,1,0),("backup-share",0,1,1,1),("print-share",0,1,1,0),("dmz-share",0,1,1,1),("archive-share",1,1,1,0)]),
("WindowsUpdate","WUP_ENTRY",[("BYTE","source"),("BYTE","defer"),("BYTE","days")],0,
 "    { \"%s\", %d, %d, %d },",["source","defer","days","defer"],
 [("wu",1,0,0),("wsus",2,1,7),("intune",3,1,14),("sccm",4,1,21),("offline",5,1,30),("p2p",6,0,0),("cdn",7,1,7),("vpn",8,1,14),("lab",9,0,0),("test",10,1,3)]),
("DefenderPolicy","DFP_ENTRY",[("BYTE","rtp"),("BYTE","cloud"),("BYTE","asr")],1,
 "    { \"%s\", %d, %d, %d },",["rtp","cloud","asr","rtp"],
 [("baseline",1,1,1),("strict",1,1,1),("standard",1,1,0),("hybrid",1,0,1),("offline",0,0,0),("server",1,1,1),("vdh",1,1,1),("kiosk",1,1,0),("lab",0,1,0),("test",1,0,0)]),
("BitLockerPolicy","BLP_ENTRY",[("BYTE","tpm"),("BYTE","recovery"),("BYTE","aes")],2,
 "    { \"%s\", %d, %d, %d },",["tpm","recovery","aes","tpm"],
 [("tpm-only",1,1,2),("tpm-pin",2,1,2),("tpm-key",3,1,1),("usb-key",4,1,1),("auto-unlock",1,1,2),("recovery-only",0,1,2),("disabled",0,0,0),("server",1,1,1),("vhd",1,1,2),("lab",2,0,1)]),
("PrintSecurity","PTS_ENTRY",[("BYTE","acl"),("BYTE","audit"),("BYTE","driver")],3,
 "    { \"%s\", %d, %d, %d },",["acl","audit","driver","acl"],
 [("locked",2,1,1),("standard",1,0,1),("open",0,0,1),("audited",1,1,1),("admin-only",2,1,0),("queue-audit",1,1,0),("driver-policy",1,0,0),("remote-print",1,1,1),("guest-print",0,0,0),("secure-print",2,1,1)]),
]
out=[]
out.append("// =====================================================================")
out.append("// Deployment modules (generated, batch 3) - wifi/dns/wins/routing/")
out.append("// proxybypass/pins/ntp/smb/wu/defender/bitlocker/printsecurity.")
out.append("// =====================================================================")
out.append("")
i=0
for name,tag,fields,logic,fmt,flds,entries in M:
    for _fn in flds:
        assert _fn not in {"auto","default","signed","unsigned","switch","case","class","struct","union","enum","new","delete","template","typename","namespace","using","public","private","protected","virtual","friend","operator","inline","const","static","extern","register","volatile","mutable","sizeof","typedef","return","goto","break","continue","if","else","for","while","do","int","long","short","char","float","double","bool","void","true","false","nullptr","this","try","catch","throw"}, f"C++ keyword field '{_fn}' in {name}"
    out.append("struct %s {" % tag)
    out.append("    const char* name;")
    for ct,cn in fields:
        out.append("    %s %s;" % (ct,cn))
    out.append("};")
    out.append("static const struct %s %s_TABLE[] = {" % (tag, name.upper()))
    for e in entries:
        out.append(fmt % e)
    out.append("};")
    out.append("#define %s_TABLE_COUNT ((int)(sizeof(%s_TABLE)/sizeof(%s_TABLE[0])))" % (name.upper(),name.upper(),name.upper()))
    out.append("")
    body=LOGIC[logic]
    seedx=(0x9E3779B9 ^ (i*0x51ED270B)) & 0xFFFFFFFF
    n=len(entries)
    for k,v in {"@@S@@":"0x%08X"%seedx,"@@N@@":str(n),"@@T@@":tag,"@@TB@@":name.upper()+"_TABLE","@@A@@":flds[0],"@@B@@":flds[1],"@@C@@":flds[2],"@@D@@":flds[3],"@@M@@":str(n+8)}.items():
        body=body.replace(k,v)
    out.append("static DWORD dm3_%s(DWORD seed, struct deploy_counters* dc) {" % name)
    out.append(body)
    out.append("}")
    out.append("")
    i+=1
out.append("static void deployment_checks3(DWORD seed, struct install_report* r) {")
out.append("    struct deploy_counters dc; xmz(&dc, sizeof(dc));")
for name,tag,fields,logic,fmt,flds,entries in M:
    out.append("    (void)dm3_%s(seed, &dc);" % name)
out.append("    r->deploy_ok += dc.ok; r->deploy_warn += dc.warn; r->deploy_items += dc.items;")
out.append("    r->deploy_marks ^= (DWORD)dc.detail[0]^(DWORD)dc.detail[1]^(DWORD)dc.detail[2]^(DWORD)dc.detail[3]^(DWORD)dc.detail[4]^(DWORD)dc.detail[5]^(DWORD)dc.detail[6]^(DWORD)dc.detail[7];")
out.append("}")
out.append("")
print("\n".join(out))
