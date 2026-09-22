#include "Renderer.hpp"
#include "window/Window.hpp"

#include "core/engine/Engine.hpp"
#include "core/anti_debug/AntiDebug.hpp"
#include "gui/frontend/esp/Esp.hpp"
#include "gui/frontend/menu/Menu.hpp"
#include "gui/frontend/overlays/Overlays.hpp"
#include "config/Current.hpp"
#include <thread>
#include <chrono>

bool Renderer::Init() {
    return GetInstance().InitImpl();
}

void Renderer::Thread() {
    return GetInstance().ThreadImpl();
}

void Renderer::Destroy() {
    return GetInstance().DestroyImpl();
}   

bool Renderer::IsOpen() {
    return GetInstance().isOpen;
}

bool Renderer::InitImpl() {
    if (!Window::SpawnWindow()) {
        LOGF(FATAL, "Failed to create window");
        return false;
    }

    if (!Window::CreateDevice()) {
        LOGF(FATAL, "Failed to create device");
        return false;
    }

    if (!Window::CreateImGui()) {
        LOGF(FATAL, "Failed to create ImGui");
        return false;
    }

    Menu::Init();
    Menu::CycleAccent(); // pick accent colour once per session
    Esp::Init();
    Overlays::Init();
    if (cfg::settings::streamproof)
        Window::SetAffinity(Window::hwnd, WindowAffinity::Invisible);

    if (cfg::settings::vsync)
        Window::vsync = true;

    LOGF(INFO, "Successfully initialized renderer...");
    return true;
}

void Renderer::DestroyImpl() {
    isRunning = false; // Prepare to stop thread loop
    LOGF(VERBOSE, "Successfully programed renderer destruction...");
}

void Renderer::ThreadImpl() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    while (isRunning) {
        Render();
        if (this->isFocused && HandleState())
            continue;
        HandleWindowOrder();
        // When CS2 is not the foreground window and free_cpu is on, throttle
        // the render loop so we don't waste GPU/CPU cycles CS2 needs.
        if (cfg::settings::free_cpu && !this->isFocused)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    Window::DestroyImGui();
    Window::DestroyDevice();
    Window::DespawnWindow();
}

void Renderer::Render() {
    Window::StartRender();

    // Non-world-space elements first (don't need a fresh view matrix)
    Overlays::Render();
    Menu::RenderStartupHelp();
    if (isOpen) Menu::Render();

    // ESP last: view-matrix physical read happens here, immediately before Present
    Esp::Render();

    Window::EndRender();
}

bool Renderer::HandleState() {
    isRunning = Window::shouldRun; // From the window event handler

    // Toggle driven by WM_HOTKEY — INSERT registered system-wide via RegisterHotKey.
    // isFocused is already checked by the caller so this only fires inside CS2.
    bool should_toggle = Window::togglePending;
    if (should_toggle)
        Window::togglePending = false;

    // END key exits.
    bool pressed_end = (GetAsyncKeyState(VK_END) & 0x8000);

    if (should_toggle || pressed_end) {
        this->isOpen = !isOpen;

        Window::SetClickthrough(Window::hwnd, !this->isOpen);

        if (this->isOpen) {
            ClipCursor(NULL);
            ImGui::GetIO().MouseDrawCursor = true;
        } else {
            ImGui::GetIO().MouseDrawCursor = false;
        }
        LOGF(VERBOSE, "Menu toggled to {}", this->isOpen);

        // Menu::Save() runs the accent-sync before Config::Write so a theme
        // tweak this session actually lands on disk; bare Config::Write would
        // persist the stale cfg::ui::accent from the previous read.
        std::thread([]() { AntiDebug::HideThread(); Menu::Save(); }).detach();
    }

    if (pressed_end)
        this->isRunning = false;

    return should_toggle;
}

bool Renderer::HandleWindowOrder() {
    auto p = Engine::GetProcess();

    if (!p || (!p->hwnd_ && !p->UpdateHWND()))
        return false;

    // Check if game window is still valid, if not, most likely game closed
    if (!IsWindow(p->hwnd_))
        this->isRunning = false;

    auto foreground = GetForegroundWindow();
    this->isFocused = (foreground == Window::hwnd || foreground == p->hwnd_);

    RECT client_rect;
    if (!GetClientRect(p->hwnd_, &client_rect))
        return false;

    POINT top_left     = { client_rect.left,  client_rect.top };
    POINT bottom_right = { client_rect.right, client_rect.bottom };
    ClientToScreen(p->hwnd_, &top_left);
    ClientToScreen(p->hwnd_, &bottom_right);

    int left   = top_left.x;
    int top    = top_left.y;
    int width  = bottom_right.x - top_left.x;
    int height = bottom_right.y - top_left.y;

    // Anti-blackscreen: when CS2 doesn't have focus the overlay would fully
    // cover the game window, which can cause it to go black in windowed mode.
    // Shrink the overlay by 1 px on the bottom to avoid that (Valthrun trick).
    if (foreground != p->hwnd_)
        height -= 1;

    // Maintain z-order without HWND_TOPMOST: check every ~30 frames (~0.5s at 60fps)
    static int zorder_ctr = 0;
    if (++zorder_ctr >= 30) {
        zorder_ctr = 0;
        if (GetWindow(p->hwnd_, GW_HWNDPREV) != Window::hwnd)
            SetWindowPos(Window::hwnd, HWND_TOP, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    static RECT last_rect = {};
    RECT new_rect = { left, top, left + width, top + height };
    if (memcmp(&new_rect, &last_rect, sizeof(RECT)) == 0)
        return true;
    last_rect = new_rect;

    // Valthrun: MoveWindow to reposition, then WM_PAINT to acknowledge new bounds
    MoveWindow(Window::hwnd, left, top, width, height, FALSE);
    SendMessage(Window::hwnd, WM_PAINT, 0, 0);

    return true;
}