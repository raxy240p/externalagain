#include "Menu.hpp"
#include <imgui_internal.h>
#include "core/anti_debug/Crash.hpp"
#include <skCrypter/skCrypter.hpp>
#include "fonts_embedded.hpp"
#include "gui/renderer/window/Window.hpp"
#include "config/Config.hpp"   // Save/Load delegate to the single JSON store
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <ctime>
#include <unordered_map>

// ── Font handles ──────────────────────────────────────────────────────────────
static ImFont* g_fontUiMd   = nullptr;
static ImFont* g_fontUiSb   = nullptr;
static ImFont* g_fontUiLg   = nullptr;
static ImFont* g_fontMono22 = nullptr;
static ImFont* g_fontMono9  = nullptr;

// ── Color constants ───────────────────────────────────────────────────────────
static constexpr ImU32 kTxtHi = IM_COL32(240, 240, 242, 255);
static constexpr ImU32 kTxtLo = IM_COL32(118, 118, 128, 255);
static constexpr ImU32 kRed   = IM_COL32(239,  68,  68, 255);

// ── Accent theme ──────────────────────────────────────────────────────────────
static ImVec4 g_accentF{0.259f, 0.529f, 1.f, 1.f};
static int    g_accentCycleIdx = 0;

static ImU32 Accent(int a = 255)
{
    return IM_COL32(int(g_accentF.x * 255.f + 0.5f),
                    int(g_accentF.y * 255.f + 0.5f),
                    int(g_accentF.z * 255.f + 0.5f), a);
}
static ImU32 Accent2(int a = 255)
{
    return IM_COL32(int(g_accentF.x * 194.f + 0.5f),
                    int(g_accentF.y * 194.f + 0.5f),
                    int(g_accentF.z * 194.f + 0.5f), a);
}

// ── Tab-transition animation state ────────────────────────────────────────────
static float g_alpha   = 1.f;
static float g_fade    = 1.f;
static int   g_stagger = 0;

static ImU32 A(ImU32 col, float mul = 1.f)
{
    float a = float((col >> IM_COL32_A_SHIFT) & 0xFF) * g_alpha * mul;
    return (col & ~IM_COL32_A_MASK) | (ImU32(ImClamp(a, 0.f, 255.f)) << IM_COL32_A_SHIFT);
}

static ImU32 ColU32(const color_t& c, float amul = 1.f)
{
    return A(IM_COL32(int(c.r*255), int(c.g*255), int(c.b*255), int(c.a*255)), amul);
}

static ImU32 LerpCol(ImU32 a, ImU32 b, float t)
{
    t = ImClamp(t, 0.f, 1.f);
    int ar = (a >> IM_COL32_R_SHIFT) & 0xFF, ag = (a >> IM_COL32_G_SHIFT) & 0xFF,
        ab = (a >> IM_COL32_B_SHIFT) & 0xFF, aa = (a >> IM_COL32_A_SHIFT) & 0xFF;
    int br = (b >> IM_COL32_R_SHIFT) & 0xFF, bg = (b >> IM_COL32_G_SHIFT) & 0xFF,
        bb = (b >> IM_COL32_B_SHIFT) & 0xFF, ba = (b >> IM_COL32_A_SHIFT) & 0xFF;
    return IM_COL32(int(ar + (br-ar)*t), int(ag + (bg-ag)*t),
                    int(ab + (bb-ab)*t), int(aa + (ba-aa)*t));
}

static float Anim(ImGuiID id, bool target, float speed = 14.f)
{
    static std::unordered_map<ImGuiID, float> s;
    float& v = s[id];
    v += ((target ? 1.f : 0.f) - v) * ImMin(1.f, ImGui::GetIO().DeltaTime * speed);
    return ImClamp(v, 0.f, 1.f);
}

static float Stagger()
{
    return ImClamp((g_fade - float(g_stagger++) * 0.055f) * 3.f, 0.f, 1.f);
}

// ── Config save / load ────────────────────────────────────────────────────────
// Thin bridge to the JSON Config store: keeps everything (colors, sliders,
// binds, trigger, theme) in ONE file at ONE format. The g_accentF <-> cfg::ui
// sync lives here because g_accentF is a Menu-local ImVec4 while persistence
// works in cfg::ui::accent (color_t). Both are single-thread so no lock needed.
static void SyncAccentToCfg()
{
    cfg::ui::accent.r = g_accentF.x;
    cfg::ui::accent.g = g_accentF.y;
    cfg::ui::accent.b = g_accentF.z;
    cfg::ui::accent.a = 1.f;
}
static void SyncAccentFromCfg()
{
    g_accentF = { cfg::ui::accent.r, cfg::ui::accent.g, cfg::ui::accent.b, 1.f };
}

static char   s_cfgMsg[32] = "";
static double s_cfgMsgT    = -100.0;
static void CfgToast(const char* m)
{ snprintf(s_cfgMsg, sizeof(s_cfgMsg), "%s", m); s_cfgMsgT = ImGui::GetTime(); }

static bool SaveConfig()
{
    SyncAccentToCfg();
    return Config::Write();
}

static bool LoadConfig()
{
    if (!Config::Read()) return false;
    SyncAccentFromCfg();
    // Streamproof affinity + VSync toggle apply immediately on load so
    // the runtime state matches the freshly-restored cfg — otherwise
    // the user would have to touch each toggle to re-apply it.
    Window::SetAffinity(Window::hwnd, cfg::settings::streamproof
                        ? WindowAffinity::Invisible : WindowAffinity::Disabled);
    Window::vsync = cfg::settings::vsync;
    return true;
}

// ── Section header: mono label + gradient hairline ────────────────────────────
static void Section(const char* text)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGui::Dummy({0.f, 2.f});
    ImVec2 p = ImGui::GetCursorScreenPos();
    float  w = ImGui::GetContentRegionAvail().x;

    ImGui::PushFont(g_fontMono9);
    ImVec2 ts = ImGui::CalcTextSize(text);
    dl->AddText(p, A(Accent(210)), text);
    ImGui::PopFont();

    float ly = p.y + ts.y * 0.5f;
    float lx = p.x + ts.x + 12.f;
    if (p.x + w > lx)
        dl->AddRectFilledMultiColor({lx, ly}, {p.x + w, ly + 1.f},
            A(Accent(55)), A(Accent(0)), A(Accent(0)), A(Accent(55)));

    ImGui::Dummy({0.f, ts.y + 8.f});
}

// ── ZukToggle: animated pill switch with optional color swatches ───────────────
static bool ZukToggle(const char* label, bool* v,
                      color_t* c1 = nullptr, color_t* c2 = nullptr)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2      p  = ImGui::GetCursorScreenPos();
    const float w  = ImGui::GetContentRegionAvail().x;
    constexpr float h = 36.f;

    float st    = Stagger();
    float aSave = g_alpha;
    g_alpha     = ImMin(g_alpha, st);
    ImVec2 pd(p.x, p.y + (1.f - st) * 6.f);

    ImGuiID id  = ImGui::GetID(label);
    bool    hov = ImGui::IsWindowHovered() &&
                  ImGui::IsMouseHoveringRect(p, {p.x + w, p.y + h});
    float   ha  = Anim(id,     hov, 16.f);
    float   t   = Anim(id + 1, *v,  14.f);

    if (ha > 0.01f) {
        dl->AddRectFilled(pd, {pd.x + w, pd.y + h}, A(IM_COL32(255,255,255,5), ha), 8.f);
        dl->AddRectFilled(pd, {pd.x + w, pd.y + h}, A(Accent(7), ha), 8.f);
    }

    ImGui::PushFont(g_fontUiMd);
    float lh = ImGui::GetTextLineHeight();
    dl->AddText({pd.x + 10.f, pd.y + (h - lh) * 0.5f},
                A(LerpCol(kTxtLo, kTxtHi, ImMax(t, ha * 0.35f))), label);
    ImGui::PopFont();

    constexpr float tw = 32.f, th = 18.f;
    ImVec2 tmin(pd.x + w - 10.f - tw, pd.y + (h - th) * 0.5f);
    ImVec2 tmax(tmin.x + tw, tmin.y + th);

    constexpr float sw = 16.f, sgap = 6.f;
    color_t* cols[2]{c1, c2};
    int nsw = (c1 ? 1 : 0) + (c2 ? 1 : 0);
    ImVec2 srect[2][2];
    bool overSwatch    = false;
    int  hovSwatchIdx  = -1;
    {
        float sx = tmin.x - 12.f - float(nsw) * sw - (nsw > 1 ? sgap : 0.f);
        float sy = pd.y + (h - sw) * 0.5f;
        for (int i = 0; i < 2; i++) {
            if (!cols[i]) continue;
            srect[i][0] = {sx, sy}; srect[i][1] = {sx + sw, sy + sw};
            if (ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(srect[i][0], srect[i][1]))
                hovSwatchIdx = i;
            sx += sw + sgap;
        }
        overSwatch = (hovSwatchIdx >= 0);
    }

    bool prev = *v;
    ImGui::InvisibleButton(label, {w, h});
    bool rowClicked = ImGui::IsItemClicked();
    if (rowClicked && hovSwatchIdx < 0) *v = !*v;

    if (nsw && t > 0.02f) {
        for (int i = 0; i < 2; i++) {
            if (!cols[i]) continue;
            color_t* c = cols[i];
            bool sh = (hovSwatchIdx == i);
            ImU32 fill = IM_COL32(int(c->r*255), int(c->g*255), int(c->b*255), int(c->a*255));
            dl->AddRectFilled(srect[i][0], srect[i][1], A(fill, t), 5.f);
            dl->AddRect(srect[i][0], srect[i][1],
                        A(IM_COL32(255,255,255, sh ? 120 : 45), t), 5.f, 0, 1.f);

            char pid[96];
            snprintf(pid, sizeof(pid), "##col%d_%s", i, label);
            if (sh) {
                ImGui::PushFont(g_fontMono9);
                ImGui::SetTooltip("%s", i == 0 ? (const char*)skCrypt("TEAM") : (const char*)skCrypt("ENEMY"));
                ImGui::PopFont();
            }
            if (rowClicked && sh) {
                ImGui::SetNextWindowPos({srect[i][0].x, srect[i][1].y + 4.f}, ImGuiCond_Always);
                ImGui::OpenPopup(pid);
            }
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {10.f, 10.f});
            if (ImGui::BeginPopup(pid)) {
                float cc[4]{c->r, c->g, c->b, c->a};
                if (ImGui::ColorPicker4("##p", cc,
                        ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_NoInputs |
                        ImGuiColorEditFlags_NoSidePreview))
                { c->r = cc[0]; c->g = cc[1]; c->b = cc[2]; c->a = cc[3]; }
                ImGui::EndPopup();
            }
            ImGui::PopStyleVar();
        }
    }

    if (t > 0.01f)
        dl->AddRectFilled({tmin.x - 2.f, tmin.y - 2.f}, {tmax.x + 2.f, tmax.y + 2.f},
                          A(Accent(36), t), th * 0.5f + 2.f);
    dl->AddRectFilled(tmin, tmax, A(LerpCol(IM_COL32(255,255,255,20), Accent(255), t)), th * 0.5f);
    if (t < 0.99f)
        dl->AddRect(tmin, tmax, A(IM_COL32(255,255,255,26), 1.f - t), th * 0.5f, 0, 1.f);

    float kx = tmin.x + 9.f + (tw - 18.f) * t;
    dl->AddCircleFilled({kx + 0.5f, tmin.y + th * 0.5f + 1.f}, 6.5f, A(IM_COL32(0,0,0,60)));
    dl->AddCircleFilled({kx,        tmin.y + th * 0.5f},        6.5f,
                        A(LerpCol(IM_COL32(205,205,212,255), IM_COL32(255,255,255,255), t)));

    g_alpha = aSave;
    return *v != prev;
}

// ── ZukSlider: accent-filled track with value readout ─────────────────────────
static bool ZukSlider(const char* label, float* v, float vmin, float vmax, const char* fmt)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2      p  = ImGui::GetCursorScreenPos();
    const float w  = ImGui::GetContentRegionAvail().x;
    constexpr float h = 40.f;

    float st    = Stagger();
    float aSave = g_alpha;
    g_alpha     = ImMin(g_alpha, st);
    ImVec2 pd(p.x, p.y + (1.f - st) * 6.f);

    ImGuiID id  = ImGui::GetID(label);
    bool    hov = ImGui::IsWindowHovered() &&
                  ImGui::IsMouseHoveringRect(p, {p.x + w, p.y + h});
    float   ha  = Anim(id, hov, 16.f);

    if (ha > 0.01f) {
        dl->AddRectFilled(pd, {pd.x + w, pd.y + h}, A(IM_COL32(255,255,255,5), ha), 8.f);
        dl->AddRectFilled(pd, {pd.x + w, pd.y + h}, A(Accent(7), ha), 8.f);
    }

    ImGui::PushFont(g_fontUiMd);
    dl->AddText({pd.x + 10.f, pd.y + 4.f},
                A(LerpCol(kTxtLo, kTxtHi, ImMax(0.6f, ha))), label);
    ImGui::PopFont();

    char buf[24];
    snprintf(buf, sizeof(buf), fmt, *v);
    ImGui::PushFont(g_fontMono9);
    ImVec2 ts = ImGui::CalcTextSize(buf);
    dl->AddText({pd.x + w - 10.f - ts.x, pd.y + 7.f}, A(Accent(230)), buf);
    ImGui::PopFont();

    float tx0 = pd.x + 10.f, tx1 = pd.x + w - 10.f, ty = pd.y + 30.f;
    float t   = ImClamp((*v - vmin) / (vmax - vmin), 0.f, 1.f);
    float kxp = tx0 + (tx1 - tx0) * t;
    dl->AddRectFilled({tx0, ty - 2.f}, {tx1, ty + 2.f}, A(IM_COL32(255,255,255,18)), 2.f);
    if (kxp > tx0 + 1.f)
        dl->AddRectFilledMultiColor({tx0, ty - 2.f}, {kxp, ty + 2.f},
            A(Accent2(255)), A(Accent(255)), A(Accent(255)), A(Accent2(255)));
    dl->AddCircleFilled({kxp, ty}, 7.f,  A(Accent(60)));
    dl->AddCircleFilled({kxp, ty}, 4.5f, A(IM_COL32(255,255,255,255)));

    bool changed = false;
    ImGui::InvisibleButton(label, {w, h});
    if (ImGui::IsItemActive()) {
        float nt = ImClamp((ImGui::GetIO().MousePos.x - tx0) / (tx1 - tx0), 0.f, 1.f);
        float nv = vmin + nt * (vmax - vmin);
        changed  = (nv != *v);
        *v       = nv;
    }

    g_alpha = aSave;
    return changed;
}

// ── ZukSelect: horizontal pill strip radio (label + N options) ────────────────
static bool ZukSelect(const char* label, int* v, const char* const* opts, int n)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2      p  = ImGui::GetCursorScreenPos();
    const float w  = ImGui::GetContentRegionAvail().x;
    constexpr float h = 36.f;

    float st    = Stagger();
    float aSave = g_alpha;
    g_alpha     = ImMin(g_alpha, st);
    ImVec2 pd(p.x, p.y + (1.f - st) * 6.f);

    ImGuiID id  = ImGui::GetID(label);
    bool    hov = ImGui::IsWindowHovered() &&
                  ImGui::IsMouseHoveringRect(p, {p.x + w, p.y + h});
    float   ha  = Anim(id, hov, 16.f);

    if (ha > 0.01f) {
        dl->AddRectFilled(pd, {pd.x + w, pd.y + h}, A(IM_COL32(255,255,255,5), ha), 8.f);
        dl->AddRectFilled(pd, {pd.x + w, pd.y + h}, A(Accent(7), ha), 8.f);
    }

    ImGui::PushFont(g_fontUiMd);
    float lh = ImGui::GetTextLineHeight();
    dl->AddText({pd.x + 10.f, pd.y + (h - lh) * 0.5f},
                A(LerpCol(kTxtLo, kTxtHi, ImMax(0.5f, ha * 0.35f))), label);
    ImGui::PopFont();

    // Strip on the right — each pill sized to fit its label
    if (n > 8) n = 8;
    ImGui::PushFont(g_fontMono9);
    constexpr float chH = 20.f, chGap = 4.f, chPadX = 8.f;
    float total = 0.f;
    for (int i = 0; i < n; i++) {
        ImVec2 ts = ImGui::CalcTextSize(opts[i]);
        total += ts.x + chPadX * 2.f + (i > 0 ? chGap : 0.f);
    }
    float sx = pd.x + w - 10.f - total;
    float sy = pd.y + (h - chH) * 0.5f;

    bool changed = false;
    int  hovIdx  = -1;
    float cx = sx;
    struct Rect { float x0, y0, x1, y1; };
    Rect rects[8];
    for (int i = 0; i < n; i++) {
        ImVec2 ts = ImGui::CalcTextSize(opts[i]);
        float cw = ts.x + chPadX * 2.f;
        rects[i] = { cx, sy, cx + cw, sy + chH };
        cx += cw + chGap;
    }
    for (int i = 0; i < n; i++) {
        bool sh = ImGui::IsWindowHovered() &&
                  ImGui::IsMouseHoveringRect({rects[i].x0, rects[i].y0}, {rects[i].x1, rects[i].y1});
        if (sh) hovIdx = i;
        bool sel = (*v == i);
        ImU32 fill = sel ? Accent(int(60))
                         : IM_COL32(255, 255, 255, sh ? 20 : 9);
        ImU32 ring = sel ? Accent(int(220))
                         : IM_COL32(255, 255, 255, sh ? 90 : 30);
        ImU32 tc   = sel ? Accent(255)
                         : IM_COL32(255, 255, 255, sh ? 210 : 150);
        dl->AddRectFilled({rects[i].x0, rects[i].y0}, {rects[i].x1, rects[i].y1}, A(fill), 5.f);
        dl->AddRect      ({rects[i].x0, rects[i].y0}, {rects[i].x1, rects[i].y1}, A(ring), 5.f, 0, 1.f);
        ImVec2 ts = ImGui::CalcTextSize(opts[i]);
        dl->AddText({rects[i].x0 + chPadX, rects[i].y0 + (chH - ts.y) * 0.5f}, A(tc), opts[i]);
    }
    ImGui::PopFont();

    ImGui::InvisibleButton(label, {w, h});
    if (ImGui::IsItemClicked() && hovIdx >= 0 && *v != hovIdx) {
        *v = hovIdx;
        changed = true;
    }

    g_alpha = aSave;
    return changed;
}

// ── EspPreviewCanvas: live mock player driven by cfg ─────────────────────────
static void EspPreviewCanvas(float height)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2      p  = ImGui::GetCursorScreenPos();
    const float w  = ImGui::GetContentRegionAvail().x;

    float st    = Stagger();
    float aSave = g_alpha;
    g_alpha     = ImMin(g_alpha, st);

    ImVec2 c0(p.x, p.y + (1.f - st) * 6.f), c1(c0.x + w, c0.y + height);
    dl->AddRectFilled(c0, c1, A(IM_COL32(11, 11, 14, 255)), 8.f);
    dl->AddRect(c0, c1, A(Accent(22)), 8.f, 0, 1.f);
    dl->PushClipRect({c0.x + 1.f, c0.y + 1.f}, {c1.x - 1.f, c1.y - 1.f}, true);

    for (float gx = c0.x + 18.f; gx < c1.x; gx += 24.f)
        dl->AddLine({gx, c0.y}, {gx, c1.y}, A(IM_COL32(255,255,255,4)));
    for (float gy = c0.y + 18.f; gy < c1.y; gy += 24.f)
        dl->AddLine({c0.x, gy}, {c1.x, gy}, A(IM_COL32(255,255,255,4)));

    float cx = (c0.x + c1.x) * 0.5f;
    float py = c0.y + 64.f + sinf(float(ImGui::GetTime()) * 1.6f) * 2.f;

    ImVec2 head  {cx,        py +  16.f};
    ImVec2 neck  {cx,        py +  30.f};
    ImVec2 chest {cx,        py +  46.f};
    ImVec2 pelvis{cx,        py +  78.f};
    ImVec2 shL   {cx - 14.f, py +  35.f}, shR{cx + 14.f, py +  35.f};
    ImVec2 elL   {cx - 21.f, py +  58.f}, elR{cx + 21.f, py +  58.f};
    ImVec2 haL   {cx - 25.f, py +  81.f}, haR{cx + 25.f, py +  81.f};
    ImVec2 hiL   {cx -  9.f, py +  80.f}, hiR{cx +  9.f, py +  80.f};
    ImVec2 knL   {cx - 12.f, py + 113.f}, knR{cx + 12.f, py + 113.f};
    ImVec2 ftL   {cx - 14.f, py + 146.f}, ftR{cx + 14.f, py + 146.f};

    float bx0 = cx - 34.f, bx1 = cx + 34.f;
    float by0 = py + 1.f,  by1 = py + 152.f;

    if (cfg::esp::tracers)
        dl->AddLine({cx, c1.y}, {cx, by1}, ColU32(cfg::esp::colors::tracer_enemy), 1.5f);

    ImU32 body = A(IM_COL32(52, 52, 60, 255));
    auto  Limb = [&](ImVec2 a, ImVec2 b, float th) {
        dl->AddLine(a, b, body, th);
        dl->AddCircleFilled(a, th * 0.5f, body);
        dl->AddCircleFilled(b, th * 0.5f, body);
    };
    dl->AddCircleFilled(head, 9.f, body);
    Limb(neck, pelvis, 19.f);
    Limb(shL,  elL,    7.f);  Limb(elL, haL, 6.f);
    Limb(shR,  elR,    7.f);  Limb(elR, haR, 6.f);
    Limb(hiL,  knL,    9.f);  Limb(knL, ftL, 8.f);
    Limb(hiR,  knR,    9.f);  Limb(knR, ftR, 8.f);

    if (cfg::esp::skeleton) {
        ImU32 sc = ColU32(cfg::esp::colors::skeleton_enemy);
        const ImVec2* pairs[][2]{
            {&head,   &neck},   {&neck,   &chest},  {&chest, &pelvis},
            {&neck,   &shL},    {&shL,    &elL},    {&elL,   &haL},
            {&neck,   &shR},    {&shR,    &elR},    {&elR,   &haR},
            {&pelvis, &hiL},    {&hiL,    &knL},    {&knL,   &ftL},
            {&pelvis, &hiR},    {&hiR,    &knR},    {&knR,   &ftR},
        };
        for (auto& pr : pairs) dl->AddLine(*pr[0], *pr[1], sc, 1.5f);
    }
    if (cfg::esp::head_tracker)
        dl->AddCircle(head, 11.f, ColU32(cfg::esp::colors::tracker_enemy), 0, 1.5f);

    if (cfg::esp::box) {
        float bt = cfg::esp::box_thickness;
        dl->AddRect({bx0 - 1.f, by0 - 1.f}, {bx1 + 1.f, by1 + 1.f},
                    A(IM_COL32(0,0,0,140)), 0.f, 0, bt + 2.f);
        dl->AddRect({bx0, by0}, {bx1, by1},
                    ColU32(cfg::esp::colors::box_enemy), 0.f, 0, bt);
    }

    constexpr float kHp = 0.84f, kAr = 0.55f;
    float barX = bx0 - 9.f;
    if (cfg::esp::health) {
        dl->AddRectFilled({barX - 2.f, by0 - 1.f}, {barX + 2.f, by1 + 1.f},
                          A(IM_COL32(0,0,0,170)), 2.f);
        float ft = by1 - (by1 - by0) * kHp;
        dl->AddRectFilledMultiColor({barX - 1.f, ft}, {barX + 1.f, by1},
            A(IM_COL32(96,224,112,255)), A(IM_COL32(96,224,112,255)),
            A(IM_COL32(46,150,62,255)),  A(IM_COL32(46,150,62,255)));
        if (cfg::esp::health_number) {
            char hp[8]; snprintf(hp, sizeof(hp), "%d", int(kHp * 100));
            ImVec2 hpts = g_fontMono9->CalcTextSizeA(8.5f, FLT_MAX, 0.f, hp);
            dl->AddText(g_fontMono9, 8.5f, {barX - 5.f - hpts.x, ft - 4.f},
                        A(IM_COL32(255,255,255,210)), hp);
        }
    }
    if (cfg::esp::armor) {
        float ax = barX - (cfg::esp::health ? 7.f : 0.f);
        dl->AddRectFilled({ax - 2.f, by0 - 1.f}, {ax + 2.f, by1 + 1.f},
                          A(IM_COL32(0,0,0,170)), 2.f);
        float ft = by1 - (by1 - by0) * kAr;
        dl->AddRectFilled({ax - 1.f, ft}, {ax + 1.f, by1}, A(IM_COL32(88,148,255,255)), 1.f);
    }

    float tsz = cfg::esp::text_size;
    if (cfg::esp::flags::name) {
        const char* nm  = "zuk";
        ImVec2 nts = g_fontMono9->CalcTextSizeA(tsz + 1.f, FLT_MAX, 0.f, nm);
        dl->AddText(g_fontMono9, tsz + 1.f, {cx - nts.x * 0.5f, by0 - nts.y - 5.f},
                    A(IM_COL32(255,255,255,225)), nm);
    }
    if (cfg::esp::flags::weapon) {
        const char* wep = "AK-47";
        ImVec2 wts = g_fontMono9->CalcTextSizeA(tsz, FLT_MAX, 0.f, wep);
        dl->AddText(g_fontMono9, tsz, {cx - wts.x * 0.5f, by1 + 6.f},
                    A(IM_COL32(255,255,255,170)), wep);
    }
    {
        const char* fl[8]; int nf = 0;
        if (cfg::esp::flags::money)     fl[nf++] = "$4750";
        if (cfg::esp::flags::ammo)      fl[nf++] = "17/30";
        if (cfg::esp::flags::ping)      fl[nf++] = "23MS";
        if (cfg::esp::flags::flashed)   fl[nf++] = "FLASHED";
        if (cfg::esp::flags::scoped)    fl[nf++] = "SCOPED";
        if (cfg::esp::flags::reloading) fl[nf++] = "RELOAD";
        if (cfg::esp::flags::defusing)  fl[nf++] = "DEFUSE";
        float fy = by0;
        for (int i = 0; i < nf; i++) {
            dl->AddText(g_fontMono9, tsz, {bx1 + 7.f, fy},
                        A(IM_COL32(255,255,255,190)), fl[i]);
            fy += tsz + 2.f;
        }
    }

    ImGui::PushFont(g_fontMono9);
    dl->AddText({c0.x + 8.f, c1.y - 16.f}, A(IM_COL32(255,255,255,45)), skCrypt("LIVE // ENEMY"));
    ImGui::PopFont();

    dl->PopClipRect();
    ImGui::Dummy({w, height});
    g_alpha = aSave;
}

// ── KeybindRow: click chip, press key to rebind, ESC cancels ─────────────────
static void KeybindRow(const char* label, int* key)
{
    static ImGuiID s_listening = 0;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2      p  = ImGui::GetCursorScreenPos();
    const float w  = ImGui::GetContentRegionAvail().x;
    constexpr float h = 36.f;

    float st    = Stagger();
    float aSave = g_alpha;
    g_alpha     = ImMin(g_alpha, st);
    ImVec2 pd(p.x, p.y + (1.f - st) * 6.f);

    ImGuiID id        = ImGui::GetID(label);
    bool    listening = (s_listening == id);
    bool    hov       = ImGui::IsWindowHovered() &&
                        ImGui::IsMouseHoveringRect(p, {p.x + w, p.y + h});
    float   ha        = Anim(id, hov, 16.f);

    if (ha > 0.01f) {
        dl->AddRectFilled(pd, {pd.x + w, pd.y + h}, A(IM_COL32(255,255,255,5), ha), 8.f);
        dl->AddRectFilled(pd, {pd.x + w, pd.y + h}, A(Accent(7), ha), 8.f);
    }

    ImGui::PushFont(g_fontUiMd);
    float lh = ImGui::GetTextLineHeight();
    dl->AddText({pd.x + 10.f, pd.y + (h - lh) * 0.5f},
                A(LerpCol(kTxtLo, kTxtHi, ImMax(listening ? 1.f : 0.f, ha * 0.35f))), label);
    ImGui::PopFont();

    char name[32];
    if (listening) {
        snprintf(name, sizeof(name), "PRESS KEY");
    } else {
        const char* kn = ImGui::GetKeyName((ImGuiKey)*key);
        int i = 0;
        for (; kn[i] && i < 30; i++) name[i] = char(toupper((unsigned char)kn[i]));
        name[i] = 0;
    }
    ImGui::PushFont(g_fontMono9);
    ImVec2 ts = ImGui::CalcTextSize(name);
    float  cw = ts.x + 16.f, ch = 20.f;
    ImVec2 bmin(pd.x + w - 10.f - cw, pd.y + (h - ch) * 0.5f);
    ImVec2 bmax(bmin.x + cw, bmin.y + ch);
    if (listening) {
        float pulse = 0.5f + 0.5f * sinf(float(ImGui::GetTime()) * 6.f);
        dl->AddRectFilled(bmin, bmax, A(Accent(int(30 + 30 * pulse))),  6.f);
        dl->AddRect(bmin,       bmax, A(Accent(int(120 + 100 * pulse))), 6.f, 0, 1.f);
        dl->AddText({bmin.x + 8.f, bmin.y + (ch - ts.y) * 0.5f}, A(Accent(255)), name);
    } else {
        dl->AddRectFilled(bmin, bmax, A(IM_COL32(255,255,255, hov ? 14 : 9)), 6.f);
        dl->AddRect(bmin,       bmax, A(IM_COL32(255,255,255,30)), 6.f, 0, 1.f);
        dl->AddText({bmin.x + 8.f, bmin.y + (ch - ts.y) * 0.5f},
                    A(IM_COL32(255,255,255,160)), name);
    }
    ImGui::PopFont();

    ImGui::InvisibleButton(label, {w, h});
    if (ImGui::IsItemClicked() && !listening) s_listening = id;

    if (listening) {
        for (int k = ImGuiKey_NamedKey_BEGIN; k < ImGuiKey_NamedKey_END; k++) {
            // Skip: LMB (used to enter listen mode, would insta-bind) and
            // wheel deltas (not holdable). Allow RMB/MMB/X1/X2 so the
            // trigger key can be bound to a mouse side button.
            if (k == ImGuiKey_MouseLeft ||
                k == ImGuiKey_MouseWheelX || k == ImGuiKey_MouseWheelY) continue;
            if (!ImGui::IsKeyPressed((ImGuiKey)k, false)) continue;
            if (k != ImGuiKey_Escape) *key = k;
            s_listening = 0;
            break;
        }
    }

    g_alpha = aSave;
}

// ── AccentPicker: 8 preset chips + custom rainbow chip ────────────────────────
static void AccentPicker()
{
    struct Preset { ImU32 col; const char* name; };
    static const Preset kPresets[]{
        {IM_COL32(255,  66, 252, 255), "PINK"},
        {IM_COL32(155,  92, 255, 255), "PURPLE"},
        {IM_COL32( 66, 135, 255, 255), "BLUE"},
        {IM_COL32( 34, 211, 238, 255), "CYAN"},
        {IM_COL32( 52, 211, 153, 255), "GREEN"},
        {IM_COL32(250, 204,  21, 255), "GOLD"},
        {IM_COL32(251, 146,  60, 255), "ORANGE"},
        {IM_COL32(244,  63,  94, 255), "RED"},
    };
    constexpr int kN = int(sizeof(kPresets) / sizeof(kPresets[0]));

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2      p  = ImGui::GetCursorScreenPos();
    const float w  = ImGui::GetContentRegionAvail().x;
    constexpr float cs = 18.f, gap = 6.f, h = 28.f;

    float st    = Stagger();
    float aSave = g_alpha;
    g_alpha     = ImMin(g_alpha, st);
    float y     = p.y + (1.f - st) * 6.f + (h - cs) * 0.5f;

    ImU32 cur      = Accent(255);
    bool  isCustom = true;
    int   hoverIdx = -1;

    for (int i = 0; i < kN; i++) {
        float x   = p.x + 4.f + float(i) * (cs + gap);
        bool  sel = (kPresets[i].col == cur);
        if (sel) isCustom = false;
        bool  sh  = ImGui::IsWindowHovered() &&
                    ImGui::IsMouseHoveringRect({x, y}, {x + cs, y + cs});
        if (sh) hoverIdx = i;
        dl->AddRectFilled({x, y}, {x + cs, y + cs}, A(kPresets[i].col), 6.f);
        if (sel)
            dl->AddRect({x - 2.f, y - 2.f}, {x + cs + 2.f, y + cs + 2.f},
                        A(IM_COL32(255,255,255,220)), 7.f, 0, 2.f);
        else if (sh)
            dl->AddRect({x - 2.f, y - 2.f}, {x + cs + 2.f, y + cs + 2.f},
                        A(IM_COL32(255,255,255,80)), 7.f, 0, 1.f);
    }

    float rcx = p.x + 4.f + float(kN) * (cs + gap) + cs * 0.5f;
    float rcy  = y + cs * 0.5f;
    {
        static const ImU32 ring[6]{
            IM_COL32(244, 63, 94,255), IM_COL32(251,146, 60,255), IM_COL32(250,204,21,255),
            IM_COL32( 52,211,153,255), IM_COL32( 66,135,255,255), IM_COL32(199, 66,252,255)};
        for (int s = 0; s < 6; s++) {
            dl->PathArcTo({rcx, rcy}, 6.5f,
                          float(s)     / 6.f * IM_PI * 2.f,
                          float(s + 1) / 6.f * IM_PI * 2.f + 0.12f);
            dl->PathStroke(A(ring[s]), 0, 3.f);
        }
        bool sh = ImGui::IsWindowHovered() &&
                  ImGui::IsMouseHoveringRect({rcx - cs*0.5f, y}, {rcx + cs*0.5f, y + cs});
        if (sh) hoverIdx = kN;
        if (isCustom)
            dl->AddCircle({rcx, rcy}, 10.5f, A(IM_COL32(255,255,255,220)), 0, 2.f);
        else if (sh)
            dl->AddCircle({rcx, rcy}, 10.5f, A(IM_COL32(255,255,255,80)),  0, 1.f);
    }

    if (hoverIdx >= 0) {
        ImGui::PushFont(g_fontMono9);
        ImGui::SetTooltip("%s", hoverIdx < kN ? kPresets[hoverIdx].name : "CUSTOM");
        ImGui::PopFont();
    }

    ImGui::InvisibleButton("##accents", {w, h});
    if (ImGui::IsItemClicked() && hoverIdx >= 0) {
        if (hoverIdx < kN) {
            ImU32 c = kPresets[hoverIdx].col;
            g_accentF = {float((c >> IM_COL32_R_SHIFT) & 0xFF) / 255.f,
                         float((c >> IM_COL32_G_SHIFT) & 0xFF) / 255.f,
                         float((c >> IM_COL32_B_SHIFT) & 0xFF) / 255.f, 1.f};
        } else {
            ImGui::OpenPopup("##accent_custom");
        }
    }
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {10.f, 10.f});
    if (ImGui::BeginPopup("##accent_custom")) {
        float cc[3]{g_accentF.x, g_accentF.y, g_accentF.z};
        if (ImGui::ColorPicker3("##ap", cc,
                ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoSidePreview))
            g_accentF = {cc[0], cc[1], cc[2], 1.f};
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar();

    g_alpha = aSave;
}

// ── KeyValue: micro label pair ────────────────────────────────────────────────
static void KeyValue(const char* key, const char* val)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p  = ImGui::GetCursorScreenPos();
    float  st = Stagger();
    float  aSave = g_alpha;
    g_alpha = ImMin(g_alpha, st);
    float  y = p.y + (1.f - st) * 6.f;
    ImGui::PushFont(g_fontMono9);
    dl->AddText({p.x + 10.f, y + 4.f}, A(IM_COL32(255,255,255, 60)), key);
    dl->AddText({p.x + 96.f, y + 4.f}, A(IM_COL32(255,255,255,170)), val);
    ImGui::PopFont();
    ImGui::Dummy({0.f, 20.f});
    g_alpha = aSave;
}

// ── GhostButton: outlined, fills on hover ─────────────────────────────────────
static bool GhostButton(const char* label, ImU32 col, float w, float h)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2  p  = ImGui::GetCursorScreenPos();
    ImGuiID id = ImGui::GetID(label);
    bool    hov = ImGui::IsWindowHovered() &&
                  ImGui::IsMouseHoveringRect(p, {p.x + w, p.y + h});
    float   ha  = Anim(id, hov, 14.f);

    dl->AddRectFilled(p, {p.x + w, p.y + h}, A(col, 0.07f + 0.14f * ha), 8.f);
    dl->AddRect(p,       {p.x + w, p.y + h}, A(col, 0.35f + 0.45f * ha), 8.f, 0, 1.f);

    ImGui::PushFont(g_fontUiSb);
    ImVec2 ts = ImGui::CalcTextSize(label);
    dl->AddText({p.x + (w - ts.x) * 0.5f, p.y + (h - ts.y) * 0.5f},
                A(LerpCol(A(col, 0.9f), IM_COL32(255,255,255,255), ha * 0.6f)), label);
    ImGui::PopFont();

    ImGui::InvisibleButton(label, {w, h});
    return ImGui::IsItemClicked();
}

// ── Sidebar nav icons (hand-drawn) ────────────────────────────────────────────
static void DrawNavIcon(ImDrawList* dl, int idx, ImVec2 c, ImU32 col)
{
    constexpr float thk = 1.4f;
    switch (idx) {
    case 0: // player silhouette
        dl->AddCircle({c.x, c.y - 3.4f}, 2.8f, col, 0, thk);
        dl->PathArcTo({c.x, c.y + 5.8f}, 4.8f, IM_PI, IM_PI * 2.f);
        dl->PathStroke(col, 0, thk);
        break;
    case 1: // globe
        dl->AddCircle(c, 6.2f, col, 0, thk);
        dl->AddLine({c.x - 6.2f, c.y}, {c.x + 6.2f, c.y}, col, thk * 0.85f);
        dl->AddEllipse(c, {2.9f, 6.2f}, col, 0.f, 0, thk * 0.85f);
        break;
    case 2: // sliders
        for (int i = -1; i <= 1; i++) {
            float iy = c.y + float(i) * 4.6f;
            dl->AddLine({c.x - 6.5f, iy}, {c.x + 6.5f, iy}, col, thk * 0.85f);
        }
        dl->AddCircleFilled({c.x - 2.5f, c.y - 4.6f}, 2.2f, col);
        dl->AddCircleFilled({c.x + 3.0f, c.y        }, 2.2f, col);
        dl->AddCircleFilled({c.x - 0.5f, c.y + 4.6f }, 2.2f, col);
        break;
    }
}

static bool NavItem(int idx, const char* label, bool active, int count)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p  = ImGui::GetCursorScreenPos();
    float  w  = ImGui::GetContentRegionAvail().x;
    constexpr float h = 36.f;

    ImGuiID id  = ImGui::GetID(label);
    bool    hov = ImGui::IsWindowHovered() &&
                  ImGui::IsMouseHoveringRect(p, {p.x + w, p.y + h});
    float   ha  = Anim(id,     hov && !active, 14.f);
    float   at  = Anim(id + 1, active,         14.f);

    if (ha > 0.01f)
        dl->AddRectFilled(p, {p.x + w, p.y + h}, IM_COL32(255,255,255, int(6 * ha)), 9.f);

    DrawNavIcon(dl, idx, {p.x + 20.f, p.y + h * 0.5f},
                LerpCol(IM_COL32(255,255,255,80), Accent(255), at));

    ImGui::PushFont(g_fontUiSb);
    float lh = ImGui::GetTextLineHeight();
    dl->AddText({p.x + 38.f, p.y + (h - lh) * 0.5f},
                LerpCol(kTxtLo, kTxtHi, ImMax(at, ha * 0.45f)), label);
    ImGui::PopFont();

    if (count > 0) {
        char buf[8]; snprintf(buf, sizeof(buf), "%d", count);
        ImGui::PushFont(g_fontMono9);
        ImVec2 ts = ImGui::CalcTextSize(buf);
        float  pw = ts.x + 10.f, ph = 15.f;
        ImVec2 bmin(p.x + w - 10.f - pw, p.y + (h - ph) * 0.5f);
        dl->AddRectFilled(bmin, {bmin.x + pw, bmin.y + ph},
                          LerpCol(IM_COL32(255,255,255,10), Accent(38), at), ph * 0.5f);
        dl->AddText({bmin.x + 5.f, bmin.y + (ph - ts.y) * 0.5f},
                    LerpCol(IM_COL32(255,255,255,90), Accent(255), at), buf);
        ImGui::PopFont();
    }

    ImGui::InvisibleButton(label, {w, h});
    return ImGui::IsItemClicked();
}

// ── Accent-dependent style colors (called every frame) ────────────────────────
static void UpdateAccentStyle()
{
    auto& c  = ImGui::GetStyle().Colors;
    ImVec4 a = g_accentF;
    auto v   = [&](float al) { return ImVec4(a.x, a.y, a.z, al); };
    c[ImGuiCol_Border]           = v(0.11f);
    c[ImGuiCol_FrameBgHovered]   = v(0.06f);
    c[ImGuiCol_FrameBgActive]    = v(0.10f);
    c[ImGuiCol_Header]           = v(0.08f);
    c[ImGuiCol_HeaderHovered]    = v(0.10f);
    c[ImGuiCol_HeaderActive]     = v(0.14f);
    c[ImGuiCol_SliderGrab]       = v(1.f);
    c[ImGuiCol_SliderGrabActive] = ImVec4(a.x*0.76f, a.y*0.76f, a.z*0.76f, 1.f);
    c[ImGuiCol_Button]           = v(0.08f);
    c[ImGuiCol_ButtonHovered]    = v(0.14f);
    c[ImGuiCol_ButtonActive]     = v(0.22f);
    c[ImGuiCol_Separator]        = v(0.10f);
    c[ImGuiCol_NavCursor]        = v(0.8f);
}

// ═════════════════════════════════════════════════════════════════════════════
//  Menu class
// ═════════════════════════════════════════════════════════════════════════════

void Menu::CycleAccent()
{
    static const ImU32 kCycle[]{
        IM_COL32(255,  66, 252, 255),
        IM_COL32(155,  92, 255, 255),
        IM_COL32( 66, 135, 255, 255),
        IM_COL32( 34, 211, 238, 255),
        IM_COL32( 52, 211, 153, 255),
        IM_COL32(250, 204,  21, 255),
        IM_COL32(251, 146,  60, 255),
        IM_COL32(244,  63,  94, 255),
    };
    constexpr int kN = int(sizeof(kCycle) / sizeof(kCycle[0]));
    g_accentCycleIdx = (g_accentCycleIdx + 1) % kN;
    ImU32 c = kCycle[g_accentCycleIdx];
    g_accentF = {float((c >> IM_COL32_R_SHIFT) & 0xFF) / 255.f,
                 float((c >> IM_COL32_G_SHIFT) & 0xFF) / 255.f,
                 float((c >> IM_COL32_B_SHIFT) & 0xFF) / 255.f, 1.f};
}

bool   Menu::Init()              { return GetInstance().InitImpl(); }
void   Menu::Render()            { GetInstance().RenderImpl(); }
bool   Menu::Save()              { return SaveConfig(); }
ImVec2 Menu::GetPos()            { return GetInstance().pos; }
ImVec2 Menu::GetSize()           { return GetInstance().size; }
void   Menu::RenderStartupHelp() { GetInstance().RenderStartupHelpImpl(); }

bool Menu::InitImpl()
{
    if (!isSetup) return true;
    SetupStyles();
    // Pull persisted accent forward — Config::Read fired earlier in
    // Engine::Init(), so cfg::ui::accent already carries the user's last
    // choice (or the default). Menu's g_accentF holds the runtime copy.
    SyncAccentFromCfg();
    isSetup = false;
    return true;
}

void Menu::SetupStyles()
{
    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig fc;
    fc.FontDataOwnedByAtlas = false;

    g_fontUiMd   = io.Fonts->AddFontFromMemoryTTF((void*)g_fInterMedium,   g_fInterMedium_size,   14.5f, &fc);
    g_fontUiSb   = io.Fonts->AddFontFromMemoryTTF((void*)g_fInterSemiBold, g_fInterSemiBold_size, 14.0f, &fc);
    g_fontUiLg   = io.Fonts->AddFontFromMemoryTTF((void*)g_fInterSemiBold, g_fInterSemiBold_size, 17.5f, &fc);
    g_fontMono22 = io.Fonts->AddFontFromMemoryTTF((void*)g_fJetBrainsEB,   g_fJetBrainsEB_size,   21.0f, &fc);
    g_fontMono9  = io.Fonts->AddFontFromMemoryTTF((void*)g_fJetBrainsEB,   g_fJetBrainsEB_size,    9.5f, &fc);

    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding    = 16.f;   s.ChildRounding     =  8.f;
    s.FrameRounding     =  5.f;   s.PopupRounding     = 10.f;
    s.ScrollbarRounding = 99.f;   s.GrabRounding      =  4.f;
    s.WindowBorderSize  =  1.f;   s.ChildBorderSize   =  0.f;
    s.FrameBorderSize   =  0.f;   s.PopupBorderSize   =  1.f;
    s.WindowPadding     = { 0.f, 0.f};
    s.FramePadding      = {10.f, 7.f};
    s.ItemSpacing       = { 8.f, 4.f};
    s.ScrollbarSize     =  0.f;

    auto& c = s.Colors;
    c[ImGuiCol_WindowBg]             = {0.043f, 0.043f, 0.051f, 1.f};
    c[ImGuiCol_ChildBg]              = {0, 0, 0, 0};
    c[ImGuiCol_ScrollbarBg]          = {0, 0, 0, 0};
    c[ImGuiCol_ScrollbarGrab]        = {0, 0, 0, 0};
    c[ImGuiCol_ScrollbarGrabHovered] = {0, 0, 0, 0};
    c[ImGuiCol_ScrollbarGrabActive]  = {0, 0, 0, 0};
    c[ImGuiCol_FrameBg]              = {1.f, 1.f, 1.f, 0.03f};
    c[ImGuiCol_CheckMark]            = {1, 1, 1, 1};
    c[ImGuiCol_Text]                 = {0.94f, 0.94f, 0.95f, 1.f};
    c[ImGuiCol_TextDisabled]         = {0.35f, 0.35f, 0.38f, 1.f};
    c[ImGuiCol_PopupBg]              = {0.055f, 0.055f, 0.068f, 0.985f};
    UpdateAccentStyle();
}

void Menu::RenderImpl()
{
    static int   tab      = 0;
    static float navSlide = 0.f;
    static float fade     = 1.f;

    constexpr float kW     = 920.f, kH    = 540.f;
    constexpr float kSideW = 176.f, kTopH =  64.f;
    constexpr float kColW  = (kW - kSideW) * 0.5f;
    constexpr float kCol3  = (kW - kSideW) / 3.f;
    const     float kPanH  = kH - kTopH;

    ImGuiIO& io = ImGui::GetIO();
    fade      = ImMin(1.f, fade + io.DeltaTime * 5.f);
    navSlide += (float(tab) - navSlide) * ImMin(1.f, io.DeltaTime * 16.f);
    g_fade    = fade;
    UpdateAccentStyle();

    ImGui::SetNextWindowSize({kW, kH}, ImGuiCond_Always);
    ImGui::SetNextWindowPos({io.DisplaySize.x * 0.5f - kW * 0.5f,
                             io.DisplaySize.y * 0.5f - kH * 0.5f}, ImGuiCond_FirstUseEver);

    ImGui::Begin("##esp_menu", nullptr,
        ImGuiWindowFlags_NoTitleBar  | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoScrollbar);

    pos  = ImGui::GetWindowPos();
    size = ImGui::GetWindowSize();

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wp      = ImGui::GetWindowPos();
    g_alpha        = 1.f;

    // ── Chrome ────────────────────────────────────────────────────────────────
    dl->AddRectFilled(wp, {wp.x + kSideW, wp.y + kH}, IM_COL32(7, 7, 9, 255),
                      16.f, ImDrawFlags_RoundCornersLeft);
    dl->AddLine({wp.x + kSideW, wp.y + 8.f}, {wp.x + kSideW, wp.y + kH - 8.f},
                Accent(22), 1.f);

    float midX = wp.x + kSideW + (kW - kSideW) * 0.5f;
    dl->AddRectFilledMultiColor({wp.x + kSideW, wp.y}, {midX,      wp.y + 1.f},
        Accent(0), Accent(90), Accent(90), Accent(0));
    dl->AddRectFilledMultiColor({midX,           wp.y}, {wp.x + kW, wp.y + 1.f},
        Accent(90), Accent(0), Accent(0), Accent(90));

    for (float gy = wp.y + kTopH + 20.f; gy < wp.y + kH - 16.f; gy += 26.f)
        for (float gx = wp.x + kSideW + 20.f; gx < wp.x + kW - 16.f; gx += 26.f)
            dl->AddCircleFilled({gx, gy}, 1.f, IM_COL32(255,255,255,5), 4);

    // ── Sidebar: logo ─────────────────────────────────────────────────────────
    ImGui::PushFont(g_fontMono22);
    ImVec2 zukSz = ImGui::CalcTextSize(skCrypt("Zuk"));
    dl->AddText(g_fontMono22, g_fontMono22->LegacySize,
                {wp.x + 20.f, wp.y + 26.f}, kTxtHi, skCrypt("Zuk"));
    dl->AddText(g_fontMono22, g_fontMono22->LegacySize,
                {wp.x + 20.f + zukSz.x, wp.y + 26.f}, Accent(255), skCrypt("Core"));
    ImGui::PopFont();

    ImGui::PushFont(g_fontMono9);
    dl->AddText({wp.x + 21.f, wp.y + 58.f}, Accent(95), skCrypt("V1.5"));
    ImGui::PopFont();

    dl->AddRectFilledMultiColor(
        {wp.x + 16.f, wp.y + 76.f}, {wp.x + kSideW - 16.f, wp.y + 77.f},
        Accent(70), Accent(0), Accent(0), Accent(70));

    // ── Sidebar: nav + sliding indicator ──────────────────────────────────────
    const int navCounts[3]{
        int(cfg::esp::box) + cfg::esp::skeleton + cfg::esp::head_tracker +
        cfg::esp::tracers  + cfg::esp::health   + cfg::esp::health_number +
        cfg::esp::armor    + cfg::esp::team      +
        cfg::esp::flags::name    + cfg::esp::flags::weapon + cfg::esp::flags::ammo +
        cfg::esp::flags::reloading + cfg::esp::flags::defusing + cfg::esp::flags::money +
        cfg::esp::flags::flashed + cfg::esp::flags::scoped  + cfg::esp::flags::ping +
        int(cfg::esp::trigger::enabled),
        cfg::world::spectators::enabled +
        (cfg::world::spectators::enabled
            ? int(cfg::world::spectators::detailed) + cfg::world::spectators::self_only
            : 0) +
        cfg::world::crosshair::enabled + cfg::world::velocity::enabled,
        int(cfg::settings::streamproof) + cfg::settings::watermark +
        cfg::settings::vsync            + cfg::settings::free_cpu,
    };

    ImGui::SetCursorPos({10.f, 92.f});
    ImGui::BeginChild("##nav", {kSideW - 20.f, 3.f * 40.f}, ImGuiChildFlags_None,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBackground);
    {
        ImDrawList* ndl = ImGui::GetWindowDrawList();
        ImVec2 np  = ImGui::GetWindowPos();
        float  nw  = ImGui::GetContentRegionAvail().x;
        float  iy  = np.y + navSlide * 40.f;
        ndl->AddRectFilled({np.x,       iy},        {np.x + nw,  iy + 36.f}, Accent(20), 9.f);
        ndl->AddRect      ({np.x,       iy},        {np.x + nw,  iy + 36.f}, Accent(40), 9.f, 0, 1.f);
        ndl->AddRectFilled({np.x - 1.f, iy + 9.f}, {np.x + 2.f, iy + 27.f}, Accent(255), 2.f);

        auto _nP = skCrypt("Players"), _nW = skCrypt("World"), _nG = skCrypt("General");
        const char* names[]{(const char*)_nP, (const char*)_nW, (const char*)_nG};
        for (int i = 0; i < 3; i++)
            if (NavItem(i, names[i], tab == i, navCounts[i]) && tab != i)
            { tab = i; fade = 0.f; }
    }
    ImGui::EndChild();

    // ── Sidebar: footer ───────────────────────────────────────────────────────
    dl->AddRectFilledMultiColor(
        {wp.x + 16.f, wp.y + kH - 48.f}, {wp.x + kSideW - 16.f, wp.y + kH - 47.f},
        Accent(45), Accent(0), Accent(0), Accent(45));


    // ── Header ────────────────────────────────────────────────────────────────
    g_alpha = fade;
    auto _tP  = skCrypt("Players"),     _tW  = skCrypt("World"),    _tG  = skCrypt("General");
    auto _sP  = skCrypt("ESP VISUALS, FLAGS & LIVE PREVIEW");
    auto _sW  = skCrypt("BOMB, SPECTATORS & OVERLAYS");
    auto _sG  = skCrypt("CLIENT BEHAVIOUR & SESSION");
    const char* kTitles[]   {(const char*)_tP, (const char*)_tW, (const char*)_tG};
    const char* kSubtitles[]{(const char*)_sP, (const char*)_sW, (const char*)_sG};
    ImGui::PushFont(g_fontUiLg);
    dl->AddText(g_fontUiLg, g_fontUiLg->LegacySize,
                {wp.x + kSideW + 24.f, wp.y + 13.f}, A(kTxtHi), kTitles[tab]);
    ImGui::PopFont();
    ImGui::PushFont(g_fontMono9);
    dl->AddText({wp.x + kSideW + 25.f, wp.y + 38.f},
                A(IM_COL32(255,255,255,56)), kSubtitles[tab]);
    ImGui::PopFont();
    g_alpha = 1.f;

    for (int i = 0; i < 3; i++)
        dl->AddCircleFilled({wp.x + kW - 26.f - float(i) * 12.f, wp.y + 32.f},
                            2.5f, Accent(46 - i * 16));

    dl->AddRectFilledMultiColor(
        {wp.x + kSideW, wp.y + kTopH}, {wp.x + kW, wp.y + kTopH + 1.f},
        Accent(55), Accent(8), Accent(8), Accent(55));

    // ── Content panels ────────────────────────────────────────────────────────
    g_alpha    = fade;
    float slide = (1.f - fade) * 8.f;
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, fade);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {16.f, 14.f});

    auto Divider = [&](float x) {
        dl->AddRectFilledMultiColor(
            {wp.x + x,        wp.y + kTopH + 14.f},
            {wp.x + x + 1.f,  wp.y + kH   - 14.f},
            A(Accent(20)), A(Accent(20)), A(Accent(0)), A(Accent(0)));
    };

    if (tab == 0) {
        // Players — 3 columns: PLAYER ESP | FLAGS | PREVIEW
        Divider(kSideW + kCol3);
        Divider(kSideW + kCol3 * 2.f);

        ImGui::SetCursorPos({kSideW, kTopH + slide});
        ImGui::BeginChild("##esp", {kCol3, kPanH - slide},
                          ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_NoScrollbar);
        g_stagger = 0;
        Section(skCrypt("PLAYER ESP"));
        ZukToggle(skCrypt("Box"),           &cfg::esp::box,          &cfg::esp::colors::box_team,      &cfg::esp::colors::box_enemy);
        ZukToggle(skCrypt("Skeleton"),      &cfg::esp::skeleton,     &cfg::esp::colors::skeleton_team, &cfg::esp::colors::skeleton_enemy);
        ZukToggle(skCrypt("Head Tracker"),  &cfg::esp::head_tracker, &cfg::esp::colors::tracker_team,  &cfg::esp::colors::tracker_enemy);
        ZukToggle(skCrypt("Tracers"),       &cfg::esp::tracers,      &cfg::esp::colors::tracer_team,   &cfg::esp::colors::tracer_enemy);
        ZukToggle(skCrypt("Health Bar"),    &cfg::esp::health);
        ZukToggle(skCrypt("Health Number"), &cfg::esp::health_number);
        ZukToggle(skCrypt("Armor Bar"),     &cfg::esp::armor);
        ZukToggle(skCrypt("Show Team"),     &cfg::esp::team);
        ZukToggle(skCrypt("Only Spotted"),  &cfg::esp::spotted);
        ZukToggle(skCrypt("Spotted Color"), &cfg::esp::spotted_color,
                  &cfg::esp::colors::box_spotted);
        ImGui::EndChild();

        ImGui::SetCursorPos({kSideW + kCol3, kTopH + slide});
        ImGui::BeginChild("##flags", {kCol3, kPanH - slide},
                          ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_None);
        g_stagger = 0;
        Section(skCrypt("FLAGS"));
        ZukToggle(skCrypt("Name"),     &cfg::esp::flags::name);
        ZukToggle(skCrypt("Weapon"),   &cfg::esp::flags::weapon);
        ZukToggle(skCrypt("Ammo"),     &cfg::esp::flags::ammo);
        ZukToggle(skCrypt("Reload"),   &cfg::esp::flags::reloading);
        ZukToggle(skCrypt("Defusing"), &cfg::esp::flags::defusing);
        ZukToggle(skCrypt("Money"),    &cfg::esp::flags::money);
        ZukToggle(skCrypt("Flashed"),  &cfg::esp::flags::flashed);
        ZukToggle(skCrypt("Scoped"),   &cfg::esp::flags::scoped);
        ZukToggle(skCrypt("Ping"),     &cfg::esp::flags::ping);

        ImGui::Dummy({0.f, 8.f});
        Section(skCrypt("TRIGGER"));
        ZukToggle(skCrypt("Enabled"),  &cfg::esp::trigger::enabled);
        KeybindRow(skCrypt("Key"),     &cfg::esp::trigger::key);
        {
            auto _zH = skCrypt("HEAD"), _zB = skCrypt("BODY"),
                 _zL = skCrypt("LEGS"), _zA = skCrypt("ANY");
            const char* zopts[]{(const char*)_zH, (const char*)_zB,
                                (const char*)_zL, (const char*)_zA};
            ZukSelect(skCrypt("Zone"), &cfg::esp::trigger::zone, zopts, 4);
        }
        ZukSlider(skCrypt("Hit Radius"), &cfg::esp::trigger::hit_radius_px,
                  1.f, 24.f, skCrypt("%.1fPX"));
        {
            // int → float wrapper so ZukSlider (float*) can drive delay_ms
            static float _delayF = (float)cfg::esp::trigger::delay_ms;
            _delayF = (float)cfg::esp::trigger::delay_ms;
            if (ZukSlider(skCrypt("Delay"), &_delayF, 20.f, 500.f, skCrypt("%.0fMS")))
                cfg::esp::trigger::delay_ms = (int)_delayF;
        }
        ZukToggle(skCrypt("Ignore Flashed"), &cfg::esp::trigger::ignore_flashed);
        ImGui::EndChild();

        ImGui::SetCursorPos({kSideW + kCol3 * 2.f, kTopH + slide});
        ImGui::BeginChild("##preview", {kCol3, kPanH - slide},
                          ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_NoScrollbar);
        g_stagger = 0;
        Section(skCrypt("PREVIEW"));
        EspPreviewCanvas(288.f);
        ImGui::Dummy({0.f, 6.f});
        ZukSlider(skCrypt("Box Width"),  &cfg::esp::box_thickness,      1.f, 4.f,  skCrypt("%.1fPX"));
        ZukSlider(skCrypt("Skel Width"), &cfg::esp::skeleton_thickness, 0.5f, 4.f, skCrypt("%.1fPX"));
        ZukSlider(skCrypt("Text Size"),  &cfg::esp::text_size,          6.f, 14.f, skCrypt("%.1f"));
        ImGui::EndChild();
    }
    else if (tab == 1) {
        // World — 2 columns
        Divider(kSideW + kColW);

        ImGui::SetCursorPos({kSideW, kTopH + slide});
        ImGui::BeginChild("##wleft", {kColW, kPanH - slide},
                          ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_NoScrollbar);
        g_stagger = 0;
        Section(skCrypt("SPECTATORS"));
        ZukToggle(skCrypt("Enable"), &cfg::world::spectators::enabled);
        if (cfg::world::spectators::enabled) {
            ImGui::Indent(12.f);
            ZukToggle(skCrypt("Detailed"),  &cfg::world::spectators::detailed);
            ZukToggle(skCrypt("Only Self"), &cfg::world::spectators::self_only);
            ImGui::Unindent(12.f);
        }
        ImGui::EndChild();

        ImGui::SetCursorPos({kSideW + kColW, kTopH + slide});
        ImGui::BeginChild("##wright", {kColW, kPanH - slide},
                          ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_NoScrollbar);
        g_stagger = 0;
        Section(skCrypt("OVERLAY"));
        ZukToggle(skCrypt("Crosshair"),      &cfg::world::crosshair::enabled);
        ZukToggle(skCrypt("Velocity Graph"), &cfg::world::velocity::enabled);
        if (cfg::world::velocity::enabled) {
            ImGui::Indent(12.f);
            static float _velRate  = (float)cfg::world::velocity::sample_rate;
            static float _velLen   =        cfg::world::velocity::sample_length;
            _velRate = (float)cfg::world::velocity::sample_rate;
            if (ZukSlider(skCrypt("Sample Rate"),   &_velRate, 5.f, 120.f, skCrypt("%.0fHZ")))
                cfg::world::velocity::sample_rate = (int)_velRate;
            if (ZukSlider(skCrypt("Sample Length"), &_velLen,  1.f,  10.f, skCrypt("%.1fS")))
                cfg::world::velocity::sample_length = _velLen;
            ImGui::Unindent(12.f);
        }
        ImGui::EndChild();
    }
    else {
        // General — 2 columns: CLIENT/THEME/BINDS/CONFIG | SESSION
        Divider(kSideW + kColW);

        ImGui::SetCursorPos({kSideW, kTopH + slide});
        ImGui::BeginChild("##gen", {kColW, kPanH - slide},
                          ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_NoScrollbar);
        g_stagger = 0;
        Section(skCrypt("CLIENT"));
        if (ZukToggle(skCrypt("Streamproof"), &cfg::settings::streamproof))
            Window::SetAffinity(Window::hwnd, cfg::settings::streamproof
                                ? WindowAffinity::Invisible : WindowAffinity::Disabled);
        ZukToggle(skCrypt("Watermark"), &cfg::settings::watermark);
        if (ZukToggle(skCrypt("VSync"), &cfg::settings::vsync))
            Window::vsync = cfg::settings::vsync;
        ZukToggle(skCrypt("Free CPU"), &cfg::settings::free_cpu);
        ImGui::Dummy({0.f, 10.f});
        Section(skCrypt("THEME"));
        AccentPicker();
        ImGui::Dummy({0.f, 10.f});
        Section(skCrypt("BINDS"));
        KeybindRow(skCrypt("Menu Key"), &cfg::settings::menu_key);
        ImGui::Dummy({0.f, 10.f});
        Section(skCrypt("CONFIG"));
        {
            float bw = (ImGui::GetContentRegionAvail().x - 8.f) * 0.5f;
            if (GhostButton(skCrypt("SAVE"), Accent(255), bw, 30.f))
                CfgToast(SaveConfig() ? (const char*)skCrypt("CONFIG SAVED") : (const char*)skCrypt("SAVE FAILED"));
            ImGui::SameLine(0.f, 8.f);
            if (GhostButton(skCrypt("LOAD"), Accent(255), bw, 30.f))
                CfgToast(LoadConfig() ? (const char*)skCrypt("CONFIG LOADED") : (const char*)skCrypt("NO CONFIG FILE"));

            float ma = 1.f - ImClamp(float(ImGui::GetTime() - s_cfgMsgT - 1.5) / 0.5f, 0.f, 1.f);
            if (ma > 0.f && s_cfgMsg[0]) {
                ImGui::Dummy({0.f, 6.f});
                ImVec2 mp = ImGui::GetCursorScreenPos();
                ImGui::PushFont(g_fontMono9);
                ImGui::GetWindowDrawList()->AddText({mp.x + 10.f, mp.y},
                                                   A(Accent(210), ma), s_cfgMsg);
                ImGui::PopFont();
                ImGui::Dummy({0.f, 12.f});
            }
        }
        ImGui::EndChild();

        ImGui::SetCursorPos({kSideW + kColW, kTopH + slide});
        ImGui::BeginChild("##session", {kColW, kPanH - slide},
                          ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_NoScrollbar);
        g_stagger = 0;
        Section(skCrypt("SESSION"));
        {
            char up[16], fps[16];
            int secs = int(ImGui::GetTime());
            snprintf(up,  sizeof(up),  skCrypt("%02d:%02d"), secs / 60, secs % 60);
            snprintf(fps, sizeof(fps), skCrypt("%.0f"), io.Framerate);
            KeyValue(skCrypt("BUILD"),  skCrypt("V1.5"));
            KeyValue(skCrypt("UPTIME"), up);
            KeyValue(skCrypt("FPS"),    fps);
        }
        float btnY = kPanH - slide - 14.f - 36.f - 14.f;
        if (ImGui::GetCursorPosY() < btnY) ImGui::SetCursorPosY(btnY);
        if (GhostButton(skCrypt("UNLOAD"), kRed, ImGui::GetContentRegionAvail().x, 36.f))
            CRASH();
        ImGui::EndChild();
    }

    ImGui::PopStyleVar(2);
    g_alpha = 1.f;

    ImGui::End();
}

void Menu::RenderStartupHelpImpl()
{
    // No startup help overlay needed
}
