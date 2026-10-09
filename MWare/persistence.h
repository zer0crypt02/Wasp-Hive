// ============================================================================
// persistence.h — Cross-platform Persistence Module
// ============================================================================
// Survives across reboots and kill attempts on all platforms using
// platform-native persistence mechanisms.
//
// Windows:
//   [1] Registry Run key (HKCU)                     — primary
//
// macOS:
//   [1] LaunchAgent plist (RunAtLoad + KeepAlive)   — primary (launchd respawn)
//
// Linux:
//   [1] XDG autostart .desktop file                 — primary
//
// Design principle: Simplicity over redundancy — one mechanism per OS.
// ============================================================================
#pragma once

#ifdef _WIN32
#include <windows.h>
#endif

#include <string>

// === Master installer — calls the platform-appropriate mechanism ===
// Returns true if the mechanism was installed successfully.
bool installPersistence();

// === Uninstall ALL persistence mechanisms ===
// Removes the installed persistence on the current platform.
// Returns count of mechanisms successfully removed.
int uninstallAllPersistence();
