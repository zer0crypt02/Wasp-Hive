#!/usr/bin/env python3
"""
gen_setup_modules2.py — second batch of installer deployment modules for
loader_stub_v5.cpp. Same contract as batch 1: CRT-free, seed-driven tables,
counters merged via deployment_checks2() into install_report.

Usage: python3 gen_setup_modules2.py > deploy_modules2.inc
"""
import random
random.seed(0xC0FFEE)

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

def mk(name, tag, fields, logic, fmt, entries):
    return {"name": name, "tag": tag, "fields": fields, "logic": logic, "entries": entries, "fmt": fmt}

M = []
A = M.append

# name, tag, fields, logic, fmt, entries
A(mk("DiskQuota", "DQT_ENTRY", [("DWORD","limit_mb"),("DWORD","warn_mb"),("BYTE","enabled")], 2,
    "    { \"%s\", %d, %d, %d },",
    [("Users", 2048, 1536, 1), ("Administrators", 8192, 6144, 1), ("Guests", 256, 192, 1),
     ("ServiceAccounts", 1024, 768, 1), ("DomainUsers", 4096, 3072, 1), ("BackupAgents", 16384, 12288, 0),
     ("Devices", 512, 384, 0), ("Logs", 4096, 3072, 1), ("Cache", 2048, 1536, 1),
     ("Templates", 512, 384, 1), ("Archives", 32768, 24576, 0), ("Telemetry", 1024, 768, 1)]))
A(mk("FolderRedirection", "FRD_ENTRY", [("WORD","target"),("BYTE","flags"),("BYTE","offline")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("Desktop", 1, 0, 1), ("Documents", 2, 0, 1), ("Downloads", 3, 1, 1),
     ("Pictures", 4, 0, 1), ("Music", 5, 1, 0), ("Videos", 6, 0, 1),
     ("Favorites", 7, 0, 1), ("Contacts", 8, 1, 0), ("Links", 9, 0, 1),
     ("Searches", 10, 0, 1), ("SavedGames", 11, 1, 0), ("OneDrive", 12, 0, 1)]))
A(mk("IntranetZones", "INZ_ENTRY", [("BYTE","zone"),("BYTE","action"),("BYTE","lvl")], 1,
    "    { \"%s\", %d, %d, %d },",
    [("corp.wksuite.local", 0, 1, 2), ("apps.wksuite.local", 0, 1, 1),
     ("files.wksuite.local", 0, 0, 2), ("wiki.wksuite.local", 1, 1, 2),
     ("portal.wksuite.local", 1, 0, 1), ("mail.wksuite.local", 2, 1, 2),
     ("sso.wksuite.local", 2, 0, 3), ("vpn.wksuite.local", 3, 1, 2),
     ("proxy.wksuite.local", 3, 0, 1), ("cdn.wksuite.local", 0, 1, 3),
     ("update.wksuite.local", 1, 1, 2), ("intranet", 0, 1, 2)]))
A(mk("CertStore", "CST_ENTRY", [("BYTE","usage"),("BYTE","trust"),("BYTE","store")], 3,
    "    { \"%s\", %d, %d, %d },",
    [("WkSuite Root CA", 1, 2, 0), ("WkSuite CodeSign", 2, 2, 1),
     ("WkSuite TLS", 3, 2, 1), ("WkSuite TimeStamp", 1, 2, 0),
     ("OEM Intermediate", 2, 1, 1), ("Partner Root", 1, 2, 0),
     ("Legacy Chain", 3, 0, 1), ("Update Signing", 2, 2, 1),
     ("Driver Signing", 3, 2, 1), ("Mail Encryption", 1, 1, 1),
     ("Vault Identity", 2, 2, 0), ("Backup Key", 3, 1, 0)]))
A(mk("GpoSettings", "GPO_ENTRY", [("BYTE","section"),("BYTE","value"),("BYTE","enforce")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("WkSuiteBaseline", 0, 1, 1), ("WkSuiteLockdown", 0, 2, 1),
     ("WkSuitePrivacy", 1, 3, 1), ("WkSuiteNetwork", 2, 4, 1),
     ("WkSuiteAppControl", 3, 5, 1), ("WkSuiteBackup", 1, 6, 0),
     ("WkSuiteUpdate", 2, 7, 1), ("WkSuiteLogon", 0, 8, 0),
     ("WkSuiteAudit", 3, 9, 1), ("WkSuitePower", 1, 10, 0),
     ("WkSuitePrint", 2, 11, 1), ("WkSuiteTerminal", 3, 12, 0)]))
A(mk("AppLockerRules", "APL_ENTRY", [("BYTE","action"),("BYTE","type"),("BYTE","scope")], 1,
    "    { \"%s\", %d, %d, %d },",
    [("wksuite.exe", 1, 0, 1), ("updater.exe", 1, 0, 1), ("templates.exe", 0, 1, 1),
     ("shellext.dll", 1, 1, 1), ("driver.sys", 1, 2, 1), ("vault.exe", 0, 0, 1),
     ("sync.exe", 1, 0, 1), ("powershell.exe", 0, 1, 0), ("cmd.exe", 0, 1, 0),
     ("wmic.exe", 0, 1, 0), ("regsvr32.exe", 0, 1, 0), ("rundll32.exe", 1, 1, 1)]))
A(mk("PrintQueue", "PQE_ENTRY", [("WORD","driver"),("BYTE","priority"),("BYTE","spool")], 2,
    "    { \"%s\", %d, %d, %d },",
    [("HQ-Laser", 110, 9, 1), ("HQ-Color", 210, 7, 1), ("Branch-1", 320, 5, 1),
     ("Branch-2", 410, 5, 1), ("Reception", 510, 3, 1), ("Archive", 130, 1, 1),
     ("Finance", 240, 6, 1), ("HR", 350, 4, 1), ("Legal", 460, 8, 1),
     ("PDF-Spool", 570, 2, 1), ("FaxQueue", 180, 1, 0), ("SecurePrint", 290, 9, 1)]))
A(mk("TaskbarPins", "TBP_ENTRY", [("BYTE","position"),("BYTE","enabled"),("BYTE","runas")], 3,
    "    { \"%s\", %d, %d, %d },",
    [("Workstation Suite.lnk", 1, 1, 0), ("File Explorer.lnk", 2, 1, 0),
     ("Edge.lnk", 3, 1, 0), ("Mail.lnk", 4, 1, 0), ("Calendar.lnk", 5, 0, 0),
     ("Teams.lnk", 6, 1, 0), ("Terminal.lnk", 7, 1, 1), ("Vault.lnk", 8, 1, 1),
     ("Sync.lnk", 9, 0, 0), ("Recovery.lnk", 10, 1, 1), ("Help.lnk", 11, 0, 0),
     ("Console.lnk", 12, 1, 1)]))
A(mk("ContextMenu", "CTM_ENTRY", [("BYTE","verb"),("BYTE","flags"),("BYTE","admin")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("Open with Workstation", 1, 0, 0), ("Send to Vault", 2, 1, 0),
     ("Encrypt", 3, 0, 0), ("Decrypt", 4, 0, 0), ("Sign", 5, 1, 0),
     ("Verify signature", 6, 1, 0), ("Compress", 7, 0, 0),
     ("Deploy to devices", 8, 1, 1), ("Compare", 9, 0, 0),
     ("Hash", 10, 1, 0), ("Open console here", 11, 1, 1),
     ("Sync folder", 12, 0, 0)]))
A(mk("ProtocolHandlers", "PRH_ENTRY", [("BYTE","exe"),("BYTE","enabled"),("BYTE","secure")], 1,
    "    { \"%s\", %d, %d, %d },",
    [("wksuite:", 1, 1, 1), ("wksfile:", 2, 1, 1), ("wksvault:", 3, 1, 1),
     ("wksupdate:", 4, 0, 1), ("wkssync:", 5, 1, 1), ("wksmail:", 6, 1, 0),
     ("wksshare:", 7, 0, 1), ("wksremote:", 8, 1, 1), ("wksprint:", 9, 1, 1),
     ("wkshelp:", 10, 0, 0), ("wksconsole:", 11, 1, 1), ("wksdiag:", 12, 0, 1)]))
A(mk("IndexerSettings", "IDX_ENTRY", [("BYTE","include"),("BYTE","enabled"),("BYTE","ext")], 2,
    "    { \"%s\", %d, %d, %d },",
    [("Documents", 1, 1, 0), ("Downloads", 1, 1, 0), ("Mail", 2, 1, 0),
     ("Vault", 3, 1, 1), ("Archives", 4, 0, 1), ("Templates", 1, 1, 0),
     ("SharePoint", 5, 1, 0), ("Teams", 6, 0, 0), ("OneDrive", 7, 1, 0),
     ("Logs", 8, 0, 1), ("Help", 9, 1, 1), ("Cache", 10, 0, 1)]))
A(mk("BrowserSettings", "BRS_ENTRY", [("BYTE","setting"),("BYTE","value"),("BYTE","applied")], 3,
    "    { \"%s\", %d, %d, %d },",
    [("Homepage", 1, 1, 1), ("SearchProvider", 2, 2, 1), ("DefaultSearch", 3, 2, 1),
     ("Popups", 4, 3, 1), ("Cookies", 5, 4, 1), ("Passwords", 6, 5, 0),
     ("Downloads", 7, 6, 1), ("Extensions", 8, 7, 1), ("SmartScreen", 9, 8, 1),
     ("TrackingPrevention", 10, 9, 1), ("DoNotTrack", 11, 10, 1), ("EdgeStable", 12, 11, 1)]))
A(mk("UpdateRing", "UPR_ENTRY", [("BYTE","ring"),("BYTE","channel"),("DWORD","freq")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("Preview", 0, 1, 360), ("Beta", 1, 1, 720), ("Current", 2, 2, 1440),
     ("Stable", 3, 3, 4320), ("LongTerm", 4, 4, 10080), ("Custom-A", 2, 0, 2880),
     ("Custom-B", 3, 0, 5760), ("Pilot", 0, 2, 1440), ("Canary", 0, 0, 60),
     ("InsiderFast", 1, 0, 1440), ("SemiAnnual", 3, 2, 4320), ("Off", 4, 4, 0)]))
A(mk("DeliveryOptimization", "DOP_ENTRY", [("BYTE","mode"),("DWORD","cache_mb"),("BYTE","p2p")], 1,
    "    { \"%s\", %d, %d, %d },",
    [("LAN", 1, 2048, 1), ("WAN", 2, 1024, 1), ("HTTP", 3, 512, 0),
     ("Group", 1, 4096, 1), ("LocalOnly", 4, 0, 0), ("Internet", 2, 256, 1),
     ("BranchCache", 1, 8192, 1), ("Limited", 3, 128, 0), ("Aggressive", 0, 16384, 1),
     ("Conservative", 4, 512, 1), ("Off", 4, 0, 0), ("Hybrid", 2, 3072, 1)]))
A(mk("SearchProviders", "SRP_ENTRY", [("BYTE","isdefault"),("BYTE","priority"),("BYTE","enabled")], 2,
    "    { \"%s\", %d, %d, %d },",
    [("Bing", 1, 0, 1), ("Google", 0, 1, 1), ("DuckDuckGo", 0, 2, 1),
     ("CorpSearch", 0, 3, 1), ("DocsSearch", 0, 4, 1), ("CodeSearch", 0, 5, 0),
     ("LegalSearch", 0, 6, 0), ("SalesSearch", 0, 7, 1), ("SupportSearch", 0, 8, 1),
     ("KnowledgeBase", 0, 9, 1), ("PartnerSearch", 0, 10, 0), ("Custom", 0, 11, 1)]))
A(mk("ImeSettings", "IME_ENTRY", [("BYTE","locale"),("BYTE","enabled"),("BYTE","mode")], 3,
    "    { \"%s\", %d, %d, %d },",
    [("Microsoft IME", 1, 1, 0), ("Google IME", 1, 0, 1), ("Microsoft Pinyin", 2, 1, 0),
     ("Sogou", 2, 0, 1), ("Wubi", 2, 0, 2), ("Japanese IME", 3, 1, 0),
     ("Korean IME", 4, 1, 0), ("Cherokee", 5, 0, 0), ("Arabic", 6, 1, 0),
     ("Hebrew", 7, 0, 0), ("Persian", 8, 0, 0), ("Thai", 9, 1, 0)]))
A(mk("SoundScheme", "SND_ENTRY", [("BYTE","volume"),("BYTE","mute"),("BYTE","scheme")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("Default", 80, 0, 0), ("Windows Default", 80, 0, 0), ("No Sounds", 100, 1, 1),
     ("Classic", 70, 0, 2), ("Quiet", 30, 0, 3), ("Loud", 100, 0, 4),
     ("Speakers", 90, 0, 0), ("Headset", 75, 0, 0), ("Conference", 60, 0, 5),
     ("Night", 20, 0, 6), ("Custom", 50, 0, 7), ("Studio", 95, 0, 8)]))
A(mk("DisplayProfile", "DSP_ENTRY", [("DWORD","res_x"),("DWORD","res_y"),("BYTE","refresh")], 1,
    "    { \"%s\", %d, %d, %d },",
    [("Primary", 3840, 2160, 120), ("Secondary", 2560, 1440, 144),
     ("Laptop", 1920, 1080, 60), ("External-4K", 3840, 2160, 60),
     ("UltraWide", 3440, 1440, 100), ("Projector", 1280, 720, 60),
     ("Presentation", 1920, 1080, 60), ("Dual", 2560, 1440, 120),
     ("MeetingRoom", 3840, 2160, 30), ("Portable", 1080, 1920, 60),
     ("Kiosk", 1024, 768, 60), ("HDR", 3840, 2160, 144)]))
A(mk("KeyboardLayouts", "KBL_ENTRY", [("BYTE","locale"),("BYTE","enabled"),("BYTE","ltype")], 2,
    "    { \"%s\", %d, %d, %d },",
    [("US", 1, 1, 0), ("UK", 2, 1, 0), ("German", 3, 1, 0), ("French", 4, 0, 0),
     ("Spanish", 5, 1, 0), ("Turkish-Q", 6, 1, 0), ("Turkish-F", 6, 0, 0),
     ("Russian", 7, 1, 0), ("Arabic", 8, 0, 0), ("Hebrew", 9, 0, 0),
     ("Japanese", 10, 1, 1), ("Korean", 11, 1, 1), ("Dvorak", 12, 0, 2)]))
A(mk("TimeZones", "TMZ_ENTRY", [("WORD","tzid"),("BYTE","autotz"),("BYTE","dst")], 3,
    "    { \"%s\", %d, %d, %d },",
    [("UTC", 0, 1, 0), ("Pacific", 85, 1, 1), ("Mountain", 95, 1, 1),
     ("Central", 105, 1, 1), ("Eastern", 115, 1, 1), ("GMT", 60, 1, 1),
     ("CET", 130, 1, 1), ("EET", 135, 1, 1), ("IST", 140, 1, 0),
     ("JST", 170, 1, 0), ("AEST", 190, 1, 1), ("NZST", 195, 1, 1),
     ("Custom", 200, 0, 0)]))
A(mk("LocaleFormats", "LCF_ENTRY", [("BYTE","datefmt"),("BYTE","timefmt"),("BYTE","wk")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("en-US", 1, 1, 0), ("de-DE", 2, 2, 1), ("fr-FR", 2, 2, 1),
     ("es-ES", 3, 1, 1), ("it-IT", 3, 2, 1), ("pt-BR", 4, 1, 0),
     ("ru-RU", 5, 2, 1), ("ja-JP", 6, 2, 0), ("zh-CN", 6, 2, 0),
     ("tr-TR", 5, 2, 1), ("ar-SA", 7, 3, 1), ("ISO-8601", 8, 4, 0)]))
A(mk("NetworkShares", "NSH_ENTRY", [("BYTE","perms"),("BYTE","vis"),("BYTE","csc")], 1,
    "    { \"%s\", %d, %d, %d },",
    [("Public", 1, 1, 1), ("Department", 2, 1, 1), ("Restricted", 3, 0, 1),
     ("Archive", 2, 1, 0), ("Backup", 4, 0, 0), ("Media", 1, 1, 1),
     ("Tools", 2, 1, 1), ("Drivers", 2, 1, 1), ("ISO", 1, 1, 0),
     ("Confidential", 3, 0, 1), ("Temp", 5, 1, 0), ("Home", 6, 1, 1)]))
A(mk("HostsEntries", "HST_ENTRY", [("BYTE","ipv4"),("BYTE","enabled"),("BYTE","local")], 2,
    "    { \"%s\", %d, %d, %d },",
    [("localhost", 1, 1, 1), ("update.wksuite.local", 2, 1, 1),
     ("license.wksuite.local", 3, 1, 1), ("telemetry.wksuite.local", 4, 1, 1),
     ("vpn.wksuite.local", 5, 1, 1), ("proxy.wksuite.local", 6, 1, 1),
     ("gateway.local", 7, 1, 1), ("dns01.local", 8, 1, 1),
     ("dns02.local", 9, 1, 1), ("dc01.local", 10, 1, 1),
     ("adfs.local", 11, 1, 1), ("staging.local", 12, 0, 1)]))
A(mk("EnvVariables", "ENV_ENTRY", [("BYTE","scope"),("BYTE","kind"),("BYTE","overwrite")], 3,
    "    { \"%s\", %d, %d, %d },",
    [("WKS_HOME", 0, 0, 1), ("WKS_DATA", 0, 0, 1), ("WKS_CONFIG", 1, 0, 1),
     ("WKS_CACHE", 0, 1, 1), ("WKS_LOG", 1, 1, 1), ("WKS_TMP", 0, 1, 1),
     ("WKS_SERVER", 1, 2, 1), ("WKS_LOCALE", 0, 2, 1), ("WKS_UPDATE_RING", 1, 2, 1),
     ("WKS_TELEMETRY", 1, 2, 0), ("WKS_PROXY", 1, 2, 1), ("WKS_AUTH", 1, 2, 0)]))
A(mk("FirewallProfiles", "FWP_ENTRY", [("BYTE","state"),("BYTE","defaction"),("BYTE","edge")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("Domain", 1, 1, 1), ("Private", 1, 1, 1), ("Public", 1, 0, 1),
     ("Guest", 1, 0, 0), ("VPN", 1, 1, 1), ("Hotspot", 1, 0, 1),
     ("Lab", 0, 0, 0), ("Datacenter", 1, 1, 1), ("Airgap", 0, 0, 0),
     ("Conference", 1, 1, 1), ("Kiosk", 1, 0, 0), ("Default", 1, 1, 1)]))
A(mk("EventLogSettings", "EVL_ENTRY", [("DWORD","max_mb"),("BYTE","retention"),("BYTE","enabled")], 1,
    "    { \"%s\", %d, %d, %d },",
    [("Application", 256, 1, 1), ("System", 256, 1, 1), ("Security", 1024, 2, 1),
     ("Setup", 64, 0, 1), ("WkSuite", 512, 1, 1), ("WkSuiteOperational", 128, 1, 1),
     ("WkSuiteAudit", 1024, 2, 1), ("WkSuiteNetwork", 128, 1, 1),
     ("WkSuiteUpdates", 256, 1, 1), ("WkSuiteDiagnostics", 512, 1, 1),
     ("WkSuiteTroubleshoot", 64, 0, 0), ("WkSuitePerformance", 128, 1, 1)]))
A(mk("BackupSources", "BKS_ENTRY", [("BYTE","dest"),("BYTE","schedule"),("BYTE","enabled")], 2,
    "    { \"%s\", %d, %d, %d },",
    [("Documents", 1, 0, 1), ("Vault", 1, 0, 1), ("Profiles", 2, 1, 1),
     ("Registry", 2, 1, 1), ("Database", 3, 2, 1), ("Mailbox", 3, 2, 1),
     ("Shares", 4, 3, 0), ("VMImages", 4, 3, 0), ("Config", 5, 4, 1),
     ("Logs", 5, 4, 1), ("SystemState", 6, 5, 1), ("Templates", 1, 5, 0)]))
A(mk("RecoveryPoints", "RCP_ENTRY", [("DWORD","disk_mb"),("DWORD","age_days"),("BYTE","keep")], 3,
    "    { \"%s\", %d, %d, %d },",
    [("LastKnownGood", 4096, 7, 1), ("BeforeUpdate", 8192, 14, 1),
     ("Quarterly", 16384, 90, 1), ("PreRollback", 4096, 30, 1),
     ("Drivers", 2048, 30, 1), ("Baseline", 32768, 180, 1),
     ("Manual-1", 4096, 365, 1), ("Manual-2", 8192, 365, 0),
     ("TestPoint", 1024, 1, 0), ("Migration", 65536, 90, 1),
     ("ImageBackup", 131072, 30, 1), ("FactoryReset", 8192, 999, 1)]))
A(mk("CompatFlags2", "CPF_ENTRY", [("BYTE","layer"),("BYTE","flags"),("BYTE","arch")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("wks32.exe", 1, 0, 0), ("oldapp.exe", 2, 1, 0), ("legacy.exe", 3, 0, 0),
     ("installer2000.exe", 4, 1, 1), ("app8bit.exe", 5, 2, 0), ("vistaapp.exe", 6, 1, 0),
     ("xpapp.exe", 7, 2, 0), ("win7app.exe", 8, 0, 0), ("win8app.exe", 9, 1, 1),
     ("terminalapp.exe", 10, 2, 1), ("webapp.exe", 11, 0, 1), ("packager.exe", 12, 1, 1)]))
A(mk("TelemetrySettings", "TMS_ENTRY", [("BYTE","level"),("BYTE","optin"),("BYTE","sample")], 1,
    "    { \"%s\", %d, %d, %d },",
    [("Basic", 1, 1, 0), ("Enhanced", 2, 1, 1), ("Full", 3, 1, 1),
     ("Security", 0, 0, 0), ("Off", 0, 0, 0), ("Required", 1, 1, 0),
     ("Diagnostics", 2, 1, 1), ("Performance", 2, 0, 1), ("Usage", 1, 1, 1),
     ("CrashOnly", 0, 0, 0), ("Samples", 3, 1, 1), ("Custom", 2, 1, 0)]))
A(mk("PowerSaver2", "PSV_ENTRY", [("BYTE","lid"),("BYTE","sleep"),("BYTE","hdd")], 2,
    "    { \"%s\", %d, %d, %d },",
    [("PluggedIn", 1, 2, 3), ("OnBattery", 0, 1, 2), ("LidClosed", 0, 1, 1),
     ("Presentation", 1, 9, 9), ("Media", 1, 4, 5), ("Burning", 1, 6, 6),
     ("Charging", 0, 3, 3), ("LowBattery", 0, 0, 1), ("Critical", 0, 0, 0),
     ("Hibernate", 0, 0, 0), ("MaxPerf", 1, 9, 9), ("Balanced2", 1, 3, 4)]))
A(mk("UpdatePolicies", "UPL_ENTRY", [("BYTE","hours"),("BYTE","days"),("BYTE","reboot")], 3,
    "    { \"%s\", %d, %d, %d },",
    [("AutoInstall", 1, 7, 1), ("NotifyOnly", 0, 0, 0), ("DownloadOnly", 1, 0, 0),
     ("Manual", 0, 0, 0), ("WeekdayNight", 2, 5, 1), ("Weekend", 2, 2, 1),
     ("Monthly", 3, 1, 1), ("DeferFeature", 1, 30, 1), ("DeferQuality", 1, 14, 1),
     ("FastChannel", 1, 3, 1), ("SlowChannel", 1, 21, 1), ("OffHours", 2, 7, 0)]))
A(mk("FeatureFlags", "FEF_ENTRY", [("BYTE","flag"),("BYTE","deflt"),("BYTE","state")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("DarkMode", 1, 0, 1), ("CompactMode", 2, 0, 0), ("Tabs", 3, 1, 1),
     ("PinnedPanels", 4, 1, 1), ("QuickLaunch", 5, 0, 1), ("GestureNav", 6, 1, 1),
     ("CloudSync", 7, 1, 1), ("OfflineCache", 8, 1, 1), ("VoiceInput", 9, 0, 0),
     ("InlinePreview", 10, 1, 1), ("MultiMonitor", 11, 1, 1), ("HighContrast", 12, 0, 0)]))
A(mk("AppCompat", "APC_ENTRY", [("BYTE","mode"),("BYTE","elevate"),("BYTE","vshost")], 1,
    "    { \"%s\", %d, %d, %d },",
    [("wks-2024", 1, 1, 0), ("wks-2023", 2, 1, 0), ("wks-2022", 3, 0, 0),
     ("wks-lts", 4, 1, 1), ("wks-server", 1, 1, 1), ("wks-vdi", 2, 0, 0),
     ("wks-lite", 3, 0, 0), ("wks-pro", 4, 1, 0), ("wks-enterprise", 1, 1, 0),
     ("wks-edge", 2, 1, 1), ("wks-cmd", 3, 0, 0), ("wks-desktop", 4, 1, 0)]))
A(mk("TelemetryEndpoints", "TEP_ENTRY", [("BYTE","proto"),("BYTE","tier"),("BYTE","enabled")], 2,
    "    { \"%s\", %d, %d, %d },",
    [("metrics.wksuite.local", 1, 1, 1), ("traces.wksuite.local", 1, 2, 1),
     ("events.wksuite.local", 1, 3, 1), ("crash.wksuite.local", 1, 1, 1),
     ("usage.wksuite.local", 0, 2, 1), ("feedback.wksuite.local", 0, 3, 0),
     ("profiling.wksuite.local", 1, 2, 0), ("perf.wksuite.local", 1, 1, 1),
     ("health.wksuite.local", 0, 1, 1), ("experiments.wksuite.local", 1, 3, 1),
     ("a_b.wksuite.local", 1, 3, 0), ("insights.wksuite.local", 0, 2, 1)]))
A(mk("StartupServices2", "SSV_ENTRY", [("BYTE","start"),("BYTE","depend"),("BYTE","recover")], 3,
    "    { \"%s\", %d, %d, %d },",
    [("wkscore", 2, 0, 1), ("wksnet2", 2, 1, 1), ("wkscache2", 2, 1, 1),
     ("wkssched2", 2, 3, 1), ("wksupd2", 2, 5, 1), ("wksaudit2", 2, 3, 1),
     ("wkssync2", 2, 7, 1), ("wksindex2", 1, 9, 0), ("wksgui2", 2, 1, 1),
     ("wksshell2", 2, 11, 1), ("wksdb2", 2, 1, 1), ("wksvpn2", 1, 1, 0)]))
A(mk("CachePolicies", "CPC_ENTRY", [("BYTE","size"),("BYTE","ttl"),("BYTE","verify")], 0,
    "    { \"%s\", %d, %d, %d },",
    [("TemplatesCache", 1, 2, 1), ("ThumbCache", 2, 1, 1), ("IconCache", 3, 3, 1),
     ("FontCache", 4, 4, 1), ("Prefetch", 5, 5, 0), ("DNS", 6, 6, 1),
     ("Delivery", 7, 7, 1), ("Offline", 8, 8, 1), ("UpdateCache", 9, 9, 1),
     ("Index", 10, 10, 0), ("LogCache", 11, 11, 1), ("Metadata", 12, 12, 1)]))

FIELD_MAP = {
    "DiskQuota": ["limit_mb", "warn_mb", "enabled", "enabled"],
    "FolderRedirection": ["target", "flags", "offline", "flags"],
    "IntranetZones": ["zone", "action", "lvl", "action"],
    "CertStore": ["usage", "trust", "store", "trust"],
    "GpoSettings": ["section", "value", "enforce", "value"],
    "AppLockerRules": ["action", "type", "scope", "type"],
    "PrintQueue": ["driver", "priority", "spool", "priority"],
    "TaskbarPins": ["position", "enabled", "runas", "enabled"],
    "ContextMenu": ["verb", "flags", "admin", "flags"],
    "ProtocolHandlers": ["exe", "enabled", "secure", "enabled"],
    "IndexerSettings": ["include", "enabled", "ext", "enabled"],
    "BrowserSettings": ["setting", "value", "applied", "value"],
    "UpdateRing": ["ring", "channel", "freq", "channel"],
    "DeliveryOptimization": ["mode", "cache_mb", "p2p", "cache_mb"],
    "SearchProviders": ["isdefault", "priority", "enabled", "priority"],
    "ImeSettings": ["locale", "enabled", "mode", "enabled"],
    "SoundScheme": ["volume", "mute", "scheme", "mute"],
    "DisplayProfile": ["res_x", "res_y", "refresh", "res_y"],
    "KeyboardLayouts": ["locale", "enabled", "ltype", "enabled"],
    "TimeZones": ["tzid", "autotz", "dst", "autotz"],
    "LocaleFormats": ["datefmt", "timefmt", "wk", "timefmt"],
    "NetworkShares": ["perms", "vis", "csc", "vis"],
    "HostsEntries": ["ipv4", "enabled", "local", "enabled"],
    "EnvVariables": ["scope", "kind", "overwrite", "kind"],
    "FirewallProfiles": ["state", "defaction", "edge", "defaction"],
    "EventLogSettings": ["max_mb", "retention", "enabled", "retention"],
    "BackupSources": ["dest", "schedule", "enabled", "schedule"],
    "RecoveryPoints": ["disk_mb", "age_days", "keep", "age_days"],
    "CompatFlags2": ["layer", "flags", "arch", "flags"],
    "TelemetrySettings": ["level", "optin", "sample", "optin"],
    "PowerSaver2": ["lid", "sleep", "hdd", "sleep"],
    "UpdatePolicies": ["hours", "days", "reboot", "days"],
    "FeatureFlags": ["flag", "deflt", "state", "deflt"],
    "AppCompat": ["mode", "elevate", "vshost", "elevate"],
    "TelemetryEndpoints": ["proto", "tier", "enabled", "tier"],
    "StartupServices2": ["start", "depend", "recover", "depend"],
    "CachePolicies": ["size", "ttl", "verify", "ttl"],
}

out = []
out.append("// =====================================================================")
out.append("// Deployment modules (generated, batch 2) — quota/redirection/zones/")
out.append("// certs/gpo/applocker/queues/pins/menus/protocols/index/browser/ring/")
out.append("// delivery/search/ime/sound/display/kbd/tz/formats/shares/hosts/env/")
out.append("// fwprof/eventlog/backup/recovery + compat/telemetry/power/update/feature")
out.append("// policies. Same contract: CRT-free, seed-driven, folded into the sink.")
out.append("// =====================================================================")
out.append("")

_CXX_KW = {"auto","default","signed","unsigned","switch","case","class","struct","union","enum","new","delete","template","typename","namespace","using","public","private","protected","virtual","friend","operator","inline","constexpr","const","static","extern","register","volatile","mutable","sizeof","typedef","return","goto","break","continue","if","else","for","while","do","int","long","short","char","float","double","bool","void","true","false","nullptr","this","try","catch","throw"}

i = 0
for m in M:
    tag = m["tag"]
    flds = FIELD_MAP[m["name"]]
    for _fn in flds:
        assert _fn not in _CXX_KW, f"C++ keyword field '{_fn}' in {m['name']}"
    nf = len(m["entries"][0]) - 1
    out.append("struct %s {" % tag)
    out.append("    const char* name;")
    for j in range(nf):
        ct, cn = m["fields"][j]
        out.append("    %s %s;" % (ct, cn))
    out.append("};")
    out.append("static const struct %s %s_TABLE[] = {" % (tag, m["name"].upper()))
    for e in m["entries"]:
        out.append(m["fmt"] % e)
    out.append("};")
    out.append("#define %s_TABLE_COUNT ((int)(sizeof(%s_TABLE) / sizeof(%s_TABLE[0])))" % (m["name"].upper(), m["name"].upper(), m["name"].upper()))
    out.append("")

    body_tpl = LOGIC_BODIES[m["logic"]]
    seedx = (0x6D2B79F5 ^ (i * 0x85EBCA6B)) & 0xFFFFFFFF
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
    out.append("static DWORD dm2_%s(DWORD seed, struct deploy_counters* dc) {" % m["name"])
    out.append(body)
    out.append("}")
    out.append("")
    i += 1

out.append("// merge batch-2 modules into the install report")
out.append("static void deployment_checks2(DWORD seed, struct install_report* r) {")
out.append("    struct deploy_counters dc; xmz(&dc, sizeof(dc));")
for m in M:
    out.append("    (void)dm2_%s(seed, &dc);" % m["name"])
out.append("    r->deploy_ok += dc.ok; r->deploy_warn += dc.warn; r->deploy_items += dc.items;")
out.append("    r->deploy_marks ^= (DWORD)dc.detail[0] ^ (DWORD)dc.detail[1] ^ (DWORD)dc.detail[2] ^ (DWORD)dc.detail[3] ^ (DWORD)dc.detail[4] ^ (DWORD)dc.detail[5] ^ (DWORD)dc.detail[6] ^ (DWORD)dc.detail[7];")
out.append("}")
out.append("")

print("\n".join(out))
