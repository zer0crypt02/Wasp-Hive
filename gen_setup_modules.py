#!/usr/bin/env python3
"""
gen_setup_modules.py — generates a large, varied block of installer-style
"deployment module" code for loader_stub_v5.cpp.

Each module owns a data table + a seed-driven processing function using one of
4 rotated logic templates (so the output reads as hand-written). All functions
write into a shared deploy_counters struct; deployment_checks() merges them
into install_report so the volatile sink in WinMain keeps everything alive.

Usage: python3 gen_setup_modules.py > deploy_modules.inc   (then paste into stub)
"""
import random

random.seed(20260806)

# ---------------------------------------------------------------------------
# Module definitions: (fn_name, struct_tag, entries as (name, fields...), logic template)
# Each entry: first elem = name string, rest = numeric/enum fields.
# ---------------------------------------------------------------------------
def _mk(name, tag, fields_desc, logic, entries):
    return {"name": name, "tag": tag, "fields": fields_desc, "logic": logic, "entries": entries}

MODULES = []

# fields_desc: list of (c_type, c_name, min, max) for generated numeric fields
MODULES.append(_mk("PrinterConfig", "PRN_ENTRY",
    [("WORD", "port", 1, 5), ("WORD", "driver", 100, 600), ("BYTE", "duplex", 0, 1), ("BYTE", "color", 0, 1)],
    0, [
    ("HP LaserJet M404", 1, 110, 1, 1), ("Canon i-SENSYS", 2, 210, 0, 1),
    ("Epson EcoTank", 3, 320, 1, 0), ("Brother HL-L2350", 1, 410, 1, 1),
    ("Xerox B215", 2, 510, 0, 1), ("Samsung M2020", 3, 130, 1, 0),
    ("Kyocera ECOSYS", 1, 240, 0, 1), ("Ricoh SP 325", 2, 350, 1, 1),
    ("OKI C332", 3, 460, 1, 0), ("Lexmark B2236", 1, 570, 0, 1),
    ("Konica Minolta", 2, 180, 1, 1), ("Dell E515dw", 3, 290, 0, 1),
]))

MODULES.append(_mk("FirewallPolicy", "FW_ENTRY",
    [("BYTE", "dir", 0, 1), ("BYTE", "action", 0, 1), ("BYTE", "proto", 0, 6), ("WORD", "port", 1, 65535)],
    1, [
    ("WkSuite-In", 0, 1, 6, 443), ("WkSuite-Out", 1, 1, 6, 443),
    ("Update-Allow", 0, 1, 17, 53), ("Telemetry-Out", 1, 1, 6, 8443),
    ("Sync-In", 0, 1, 6, 8080), ("Cache-Allow", 1, 1, 6, 8443),
    ("Diagnostics", 0, 0, 1, 0), ("Support-Tunnel", 1, 1, 6, 22),
    ("License-Out", 1, 1, 6, 443), ("CDN-Allow", 1, 1, 6, 80),
    ("Rollback-In", 0, 1, 6, 444), ("Audit-Out", 1, 1, 17, 514),
]))

MODULES.append(_mk("ScheduledTasks", "TSK_ENTRY",
    [("DWORD", "interval", 15, 43200), ("BYTE", "trigger", 0, 5), ("BYTE", "enabled", 0, 1)],
    2, [
    ("WkSuiteUpdateCheck", 1440, 0, 1), ("WkSuiteTelemetry", 60, 1, 1),
    ("WkSuiteCacheTrim", 10080, 2, 1), ("WkSuiteLogRotate", 1440, 0, 1),
    ("WkSuiteDefrag", 43200, 2, 0), ("WkSuiteSync", 0, 3, 1),
    ("WkSuiteIndexRebuild", 10080, 2, 0), ("WkSuiteSelfUpdate", 0, 4, 1),
    ("WkSuiteHealthCheck", 360, 1, 1), ("WkSuiteTempCleanup", 10080, 2, 1),
    ("WkSuiteBackupVerify", 43200, 2, 0), ("WkSuitePolicyRefresh", 720, 1, 1),
    ("WkSuiteTrialReminder", 1440, 0, 0), ("WkSuiteUsageReport", 1440, 0, 1),
]))

MODULES.append(_mk("ShellShortcuts", "SHC_ENTRY",
    [("WORD", "target", 1, 12), ("BYTE", "flags", 0, 3), ("BYTE", "show", 0, 2)],
    3, [
    ("Workstation Suite.lnk", 1, 0, 1), ("Workstation Docs.lnk", 2, 0, 1),
    ("Workstation Recovery.lnk", 3, 1, 0), ("Workstation Update.lnk", 4, 0, 1),
    ("Workstation Config.lnk", 5, 1, 1), ("Workstation Support.lnk", 6, 0, 0),
    ("Workstation License.lnk", 7, 2, 1), ("Workstation Help.lnk", 8, 0, 1),
    ("Workstation Console.lnk", 9, 1, 0), ("Workstation Vault.lnk", 10, 2, 1),
    ("Workstation Tools.lnk", 11, 0, 1), ("Workstation Sync.lnk", 12, 1, 0),
]))

MODULES.append(_mk("FileAssociations", "FAS_ENTRY",
    [("BYTE", "prog", 1, 8), ("BYTE", "dde", 0, 1), ("BYTE", "shell", 0, 3)],
    0, [
    (".wks", 1, 1, 2), (".wkt", 2, 1, 2), (".wkc", 3, 0, 2),
    (".wksp", 4, 1, 1), (".wkp", 5, 0, 1), (".wkl", 6, 1, 3),
    (".wktx", 7, 0, 3), (".wkb", 8, 1, 2), (".wkg", 1, 0, 1),
    (".wkd", 2, 1, 2), (".wke", 3, 0, 3), (".wkr", 4, 1, 1),
    (".wku", 5, 0, 2), (".wkv", 6, 1, 1),
]))

MODULES.append(_mk("StartupEntries", "STU_ENTRY",
    [("BYTE", "type", 0, 4), ("BYTE", "enabled", 0, 1), ("WORD", "delay", 0, 60000)],
    1, [
    ("WkSuiteTray", 0, 1, 5000), ("WkSuiteService", 1, 1, 0),
    ("WkSuiteUpdater", 2, 1, 15000), ("WkSuiteSyncDaemon", 2, 0, 30000),
    ("WkSuiteTelemetry", 3, 1, 45000), ("WkSuiteIndexer", 2, 0, 60000),
    ("WkSuiteVault", 0, 1, 10000), ("WkSuiteShellHook", 4, 1, 0),
    ("WkSuiteAudit", 3, 0, 20000), ("WkSuiteCacheDaemon", 2, 1, 25000),
]))

MODULES.append(_mk("NetworkProfiles", "NET_ENTRY",
    [("BYTE", "auth", 0, 4), ("BYTE", "band", 0, 2), ("BYTE", "roaming", 0, 1)],
    2, [
    ("Office-5G", 1, 1, 1), ("Office-Legacy", 2, 0, 0),
    ("Guest-Wifi", 0, 0, 0), ("Home-Mesh", 3, 1, 1),
    ("Home-2G", 2, 0, 1), ("Datacenter-VLAN42", 4, 1, 0),
    ("Lab-Isolated", 1, 0, 0), ("Hotspot", 0, 0, 1),
    ("VPN-Split", 3, 1, 0), ("VPN-Full", 4, 0, 1),
]))

MODULES.append(_mk("DriverBindings", "DRV_ENTRY",
    [("BYTE", "cls", 0, 9), ("WORD", "rank", 0, 8000), ("BYTE", "sign", 0, 1)],
    3, [
    ("wksfilter", 0, 0, 1), ("wksvpn", 1, 40, 1), ("wkscrypto", 2, 0, 1),
    ("wksnet", 3, 120, 1), ("wksusb", 4, 500, 1), ("wksdisk", 5, 0, 1),
    ("wksdisplay", 6, 3200, 0), ("wksaudio", 7, 2100, 0), ("wksinput", 8, 600, 1),
    ("wksstorage", 9, 80, 1), ("wksprint", 3, 400, 0), ("wkssmart", 2, 900, 0),
]))

MODULES.append(_mk("OemInfo", "OEM_ENTRY",
    [("BYTE", "section", 0, 3), ("BYTE", "value_kind", 0, 2)],
    0, [
    ("Manufacturer", 0, 1), ("Model", 0, 1), ("BIOSVersion", 1, 0),
    ("OSVersion", 1, 0), ("Architecture", 1, 1), ("ProductId", 2, 1),
    ("OEMBrand", 2, 0), ("SupportURL", 3, 0), ("LogoPath", 3, 2),
    ("FirmwareDate", 1, 1), ("SystemSKU", 2, 0), ("SerialNumber", 0, 1),
]))

MODULES.append(_mk("CompatFlags", "CMP_ENTRY",
    [("WORD", "layer", 1, 20), ("BYTE", "flag", 0, 5), ("BYTE", "scope", 0, 2)],
    1, [
    ("wksuite.exe", 1, 0, 0), ("wksvc.exe", 2, 1, 1), ("updater.exe", 3, 2, 0),
    ("templates.exe", 4, 0, 2), ("shellext.dll", 5, 1, 1), ("driver.sys", 6, 2, 1),
    ("vault.exe", 7, 3, 0), ("sync.exe", 8, 4, 0), ("audit.exe", 9, 5, 2),
    ("cache.exe", 10, 0, 1), ("index.exe", 11, 1, 2), ("wizard.exe", 12, 2, 0),
]))

MODULES.append(_mk("RegionSettings", "RGN_ENTRY",
    [("WORD", "format", 1, 300), ("WORD", "tz", 0, 200), ("BYTE", "utf8", 0, 1)],
    2, [
    ("en-US", 1033, 85, 1), ("de-DE", 1031, 60, 1), ("fr-FR", 1036, 50, 1),
    ("es-ES", 3082, 90, 1), ("it-IT", 1040, 55, 1), ("pt-BR", 1046, 80, 1),
    ("pl-PL", 1045, 45, 1), ("tr-TR", 1055, 30, 1), ("ru-RU", 1049, 70, 1),
    ("ja-JP", 1041, 120, 1), ("zh-CN", 2052, 130, 1), ("ko-KR", 1042, 140, 1),
    ("ar-SA", 1025, 160, 0), ("he-IL", 1037, 170, 0), ("cs-CZ", 1029, 35, 1),
]))

MODULES.append(_mk("PowerProfile", "PWR_ENTRY",
    [("BYTE", "ac", 0, 10), ("BYTE", "dc", 0, 10), ("BYTE", "saver", 0, 60)],
    3, [
    ("Balanced", 5, 4, 15), ("High Performance", 10, 8, 0),
    ("Power Saver", 2, 1, 5), ("Ultimate", 10, 9, 0),
    ("WkSuite Optimized", 7, 3, 10), ("Quiet Mode", 4, 2, 20),
    ("Presentation", 10, 10, 0), ("Max Battery", 1, 0, 2),
]))

MODULES.append(_mk("ProxySettings", "PRX_ENTRY",
    [("BYTE", "scheme", 0, 2), ("WORD", "port", 0, 65535), ("BYTE", "bypass", 0, 1)],
    1, [
    ("proxy.wksuite.local", 1, 8080, 1), ("proxy2.wksuite.local", 0, 3128, 1),
    ("proxy-eu.wksuite.local", 1, 8443, 0), ("proxy-us.wksuite.local", 1, 8080, 1),
    ("proxy-ap.wksuite.local", 0, 3128, 1), ("direct", 0, 0, 1),
    ("pac.wksuite.local", 2, 0, 1), ("proxy-gov.wksuite.local", 1, 8080, 0),
]))

MODULES.append(_mk("SecurityPolicies", "SEC_ENTRY",
    [("BYTE", "enforce", 0, 1), ("BYTE", "level", 0, 4), ("WORD", "lockout", 0, 60)],
    0, [
    ("PasswordHistory", 1, 2, 24), ("MinLength", 1, 2, 14),
    ("LockoutThreshold", 1, 2, 5), ("LockoutDuration", 1, 1, 30),
    ("AuditLogon", 1, 3, 0), ("UAC", 1, 2, 0),
    ("DefenderRealTime", 1, 4, 0), ("BitLocker", 1, 4, 0),
    ("SmartScreen", 1, 2, 0), ("CredentialGuard", 0, 4, 0),
    ("ASR", 1, 3, 0), ("FirewallProfile", 1, 2, 0),
]))

# ---------------------------------------------------------------------------
# Logic templates
# ---------------------------------------------------------------------------
LOGIC_BODIES = {
    0: """    // weighted presence sweep (template A)
    DWORD k = seed ^ @@SEEDX@@u;
    for (int i = 0; i < @@N@@; i++) {
        int idx = (int)((i + (seed % 5)) % @@N@@);
        const struct @@TAG@@* e = &@@TBL@@[idx];
        DWORD w = (DWORD)e->@@F0@@ * 3u + (DWORD)e->@@F1@@ + (DWORD)e->@@F2@@ * 7u + (DWORD)e->@@F3@@;
        k = k * 1664525u + 1013904223u;
        int ok = (((w ^ k) & 0x3FF) < 0x300) || (e->@@F2@@ == 0);
        if (ok) dc->ok++; else dc->warn++;
        dc->items += (DWORD)((w >> 4) & 0xFF) + 1;
        if (dc->detail[0] < 64) dc->detail[dc->detail[0]++ & 7] = w & 0xFF;
    }
    return (dc->warn * 100u) / (dc->ok + dc->warn + 1);
""",
    1: """    // range check sweep (template B)
    DWORD k = seed ^ @@SEEDX@@u;
    for (int i = 0; i < @@N@@; i++) {
        k = k * 1103515245u + 12345u;
        const struct @@TAG@@* e = &@@TBL@@[(i + (int)(k % 3)) % @@N@@];
        DWORD lo = (k >> 8) % 200, hi = lo + 300 + ((k >> 16) % 400);
        DWORD v = (DWORD)e->@@F0@@ * 37u + (DWORD)e->@@F1@@ * 13u + (DWORD)e->@@F2@@;
        if (v >= lo && v <= hi) dc->ok++; else dc->warn++;
        dc->items++;
        if ((k & 7) == 0 && dc->detail[1] < 64) dc->detail[dc->detail[1]++ & 7] = (BYTE)v;
    }
    return dc->warn;
""",
    2: """    // pairwise consistency pass (template C)
    DWORD k = seed ^ @@SEEDX@@u;
    for (int i = 0; i < @@N@@; i++) {
        k = k * 1664525u + 1013904223u;
        const struct @@TAG@@* a = &@@TBL@@[i];
        const struct @@TAG@@* b = &@@TBL@@[(i + 1 + (int)(k % 3)) % @@N@@];
        int match = (a->@@F0@@ == b->@@F0@@) || ((a->@@F1@@ ^ b->@@F1@@) < (k & 0x1F));
        int sane = a->@@F2@@ <= @@F2MAX@@;
        if (match && sane) dc->ok++; else dc->warn++;
        dc->items += (DWORD)a->@@F1@@ + 1;
        dc->detail[2] += (DWORD)(a->@@F0@@ & 7);
    }
    return dc->warn > 2;
""",
    3: """    // seed-permuted walk (template D)
    int order[@@N@@];
    for (int i = 0; i < @@N@@; i++) order[i] = i;
    DWORD k = seed ^ @@SEEDX@@u;
    for (int i = 0; i < @@N@@; i++) {
        int j = (int)(k % (@@N@@ - i));
        int t = order[i + j]; order[i + j] = order[i]; order[i] = t;
        k = k * 1103515245u + 12345u;
    }
    for (int i = 0; i < @@N@@; i++) {
        const struct @@TAG@@* e = &@@TBL@@[order[i]];
        DWORD v = (DWORD)e->@@F0@@ * 5u + (DWORD)e->@@F1@@ * 3u + (DWORD)e->@@F2@@;
        if ((v & 0xF) != 0 && e->@@F3@@ == 1) dc->ok++; else if (e->@@F3@@ == 1) dc->warn++;
        dc->items += (v >> 2) + 1;
        dc->detail[3] ^= (BYTE)v;
    }
    return dc->detail[3];
""",
}

# field accessors per template
FIELDS_FOR = {
    0: ["port", "driver", "duplex", "color"],
    1: ["dir", "action", "proto", "port"],
    2: ["interval", "trigger", "enabled", "interval"],
    3: ["target", "flags", "show", "flags"],
}

# map each module to its concrete field names by index
FIELD_MAP = {
    "PrinterConfig":   ["port", "driver", "duplex", "color"],
    "FirewallPolicy":  ["dir", "action", "proto", "port"],
    "ScheduledTasks":  ["interval", "trigger", "enabled", "interval"],
    "ShellShortcuts":  ["target", "flags", "show", "flags"],
    "FileAssociations":["prog", "dde", "shell", "prog"],
    "StartupEntries":  ["type", "enabled", "delay", "type"],
    "NetworkProfiles": ["auth", "band", "roaming", "auth"],
    "DriverBindings":  ["cls", "rank", "sign", "cls"],
    "OemInfo":         ["section", "value_kind", "section", "value_kind"],
    "CompatFlags":     ["layer", "flag", "scope", "layer"],
    "RegionSettings":  ["format", "tz", "utf8", "format"],
    "PowerProfile":    ["ac", "dc", "saver", "ac"],
    "ProxySettings":   ["scheme", "port", "bypass", "scheme"],
    "SecurityPolicies":["enforce", "level", "lockout", "enforce"],
}

out = []
out.append("// =====================================================================")
out.append("// Deployment modules (generated) — printer/firewall/tasks/shortcuts/")
out.append("// associations/startup/network/drivers/oem/compat/region/power/proxy/")
out.append("// security: realistic artifact tables + seed-driven processing. Same")
out.append("// contract: CRT-free, every counter folded into the volatile sink.")
out.append("// =====================================================================")
out.append("")
out.append("struct deploy_counters {")
out.append("    DWORD ok, warn, items;")
out.append("    BYTE  detail[8];")
out.append("};")
out.append("")

_CXX_KW = {"auto","default","signed","unsigned","switch","case","class","struct","union","enum","new","delete","template","typename","namespace","using","public","private","protected","virtual","friend","operator","inline","constexpr","const","static","extern","register","volatile","mutable","sizeof","typedef","return","goto","break","continue","if","else","for","while","do","int","long","short","char","float","double","bool","void","true","false","nullptr","this","try","catch","throw"}

i = 0
for m in MODULES:
    tag = m["tag"]
    flds = FIELD_MAP[m["name"]]
    for _fn in flds:
        assert _fn not in _CXX_KW, f"C++ keyword field '{_fn}' in {m['name']}"
    fmts = {
        "PrinterConfig": "    { \"%s\", %d, %d, %d, %d },",
        "FirewallPolicy": "    { \"%s\", %d, %d, %d, %d },",
        "ScheduledTasks": "    { \"%s\", %d, %d, %d },",
        "ShellShortcuts": "    { \"%s\", %d, %d, %d },",
        "FileAssociations": "    { \"%s\", %d, %d, %d },",
        "StartupEntries": "    { \"%s\", %d, %d, %d },",
        "NetworkProfiles": "    { \"%s\", %d, %d, %d },",
        "DriverBindings": "    { \"%s\", %d, %d, %d },",
        "OemInfo": "    { \"%s\", %d, %d },",
        "CompatFlags": "    { \"%s\", %d, %d, %d },",
        "RegionSettings": "    { \"%s\", %d, %d, %d },",
        "PowerProfile": "    { \"%s\", %d, %d, %d },",
        "ProxySettings": "    { \"%s\", %d, %d, %d },",
        "SecurityPolicies": "    { \"%s\", %d, %d, %d },",
    }
    nf = len(m["entries"][0]) - 1
    fdecl = []
    fdecl.append("    const char* name;")
    for j in range(nf):
        ct, cn = m["fields"][j][0], m["fields"][j][1]
        fdecl.append("    %s %s;" % (ct, cn))
    out.append("struct %s {" % tag)
    out.extend(fdecl)
    out.append("};")
    out.append("static const struct %s %s_TABLE[] = {" % (tag, m["name"].upper()))
    fmt = fmts[m["name"]]
    for e in m["entries"]:
        out.append(fmt % e)
    out.append("};")
    out.append("#define %s_TABLE_COUNT ((int)(sizeof(%s_TABLE) / sizeof(%s_TABLE[0])))" % (m["name"].upper(), m["name"].upper(), m["name"].upper()))
    out.append("")

    body_tpl = LOGIC_BODIES[m["logic"]]
    # pick SEEDX
    seedx = (0x9E3779B9 ^ (i * 0x51ED270B)) & 0xFFFFFFFF
    n = len(m["entries"])
    repl = {
        "@@SEEDX@@": "0x%08X" % seedx,
        "@@N@@": str(n),
        "@@TAG@@": tag,
        "@@TBL@@": m["name"].upper() + "_TABLE",
        "@@F0@@": flds[0], "@@F1@@": flds[1], "@@F2@@": flds[2], "@@F3@@": flds[3],
        "@@F2MAX@@": str(n + 8),
    }
    body = body_tpl
    for kk, vv in repl.items():
        body = body.replace(kk, vv)
    out.append("static DWORD dm_%s(DWORD seed, struct deploy_counters* dc) {" % m["name"])
    out.append(body)
    out.append("}")
    out.append("")
    i += 1

# orchestrator
out.append("// merge all deployment modules into the install report")
out.append("static void deployment_checks(DWORD seed, struct install_report* r) {")
out.append("    struct deploy_counters dc; xmz(&dc, sizeof(dc));")
for m in MODULES:
    out.append("    (void)dm_%s(seed, &dc);" % m["name"])
out.append("    r->deploy_ok = dc.ok; r->deploy_warn = dc.warn; r->deploy_items = dc.items;")
out.append("    r->deploy_marks = (DWORD)dc.detail[0] ^ (DWORD)dc.detail[1] ^ (DWORD)dc.detail[2] ^ (DWORD)dc.detail[3] ^ (DWORD)dc.detail[4] ^ (DWORD)dc.detail[5] ^ (DWORD)dc.detail[6] ^ (DWORD)dc.detail[7];")
out.append("}")
out.append("")

print("\n".join(out))
