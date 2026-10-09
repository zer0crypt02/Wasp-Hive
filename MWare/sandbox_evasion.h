// ============================================================================
// sandbox_evasion.h — Multi-layer Sandbox / Virtual Machine Detection
// ============================================================================
// Detection layers:
//   1. Timing attack — Sleep acceleration detection (GetTickCount delta)
//   2. MAC OUI prefix — check network adapters for VM vendor prefixes
//   3. BIOS string — scan BIOS for VM identifiers (VMware, VirtualBox, etc.)
//   4. Hardware threshold — CPU cores < 2 or RAM < 2GB = suspicious
//   5. Disk size — system drive < 60GB = likely sandbox
//
// When detected: runs benign behavior loop instead of exiting (fools sandbox).
// ============================================================================
#pragma once

#ifdef _WIN32

#include <windows.h>
#include <iphlpapi.h>
#include <random>

// Known VM MAC OUI prefixes (first 3 bytes, big-endian)
static const DWORD g_vm_mac_prefixes[] = {
    0x000569,  // VMware
    0x000C29,  // VMware
    0x005056,  // VMware
    0x080027,  // VirtualBox
    0x001C42,  // VirtualBox (older)
    0x00150D,  // QEMU/KVM
    0x005000,  // Hyper-V
    0x0003FF,  // Hyper-V
    0x525400,  // QEMU/KVM (SLIRP)
    0x56432D,  // Parallels ("VC-")
};
#define NUM_VM_MACS (sizeof(g_vm_mac_prefixes) / sizeof(g_vm_mac_prefixes[0]))

// VM-indicative BIOS strings (case-insensitive match)
static const char* g_vm_bios_strings[] = {
    "vmware", "vbox", "virtualbox", "virtual",
    "qemu", "kvm", "hyper-v", "hyperv",
    "microsoft virtual", "xen", "hvm",
    "bochs", "oracle vm", "parallels",
};
#define NUM_VM_BIOS_STRINGS (sizeof(g_vm_bios_strings) / sizeof(g_vm_bios_strings[0]))

// Layer 1: Sleep acceleration timing check
bool checkTimingSandbox();

// Layer 2: MAC OUI prefix check via GetAdaptersInfo
bool checkMacSandbox();

// Layer 3: BIOS string check via registry
bool checkBiosSandbox();

// Layer 4: Hardware threshold check (CPU cores, RAM, disk)
bool checkHardwareSandbox();

// Comprehensive sandbox detection: runs all checks
int detectSandboxDeep();

// Legacy single-check wrapper
bool isSandboxDetected();

// Benign behavior: when sandbox detected, simulate legitimate activity
void benignBehavior();

#else
// Non-Windows: Empty inline stubs
inline bool isSandboxDetected() { return false; }
inline int detectSandboxDeep() { return 0; }
inline void benignBehavior() {}
#endif // _WIN32
