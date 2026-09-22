#pragma once

class Menu {
public:
    ~Menu() = default;
    Menu(const Menu&) = delete;
    Menu(Menu&&) = delete;
    Menu& operator=(const Menu&) = delete;
    Menu& operator=(Menu&&) = delete;

    static bool Init();
    static void Render();
    static void CycleAccent();

    // Save the current cfg (with accent-sync) — call from anywhere outside
    // Menu.cpp that needs a persisted snapshot, e.g. the menu-toggle
    // autosave in Renderer.cpp. Direct Config::Write bypasses the accent
    // sync and drops any theme change made this session.
    static bool Save();

    static void RenderStartupHelp();

    static ImVec2 GetPos();
    static ImVec2 GetSize();
private:
    Menu() {};

    static Menu& GetInstance()
    {
        static Menu i{};
        return i;
    }

    bool InitImpl();
    void RenderImpl();
    void RenderStartupHelpImpl();

    void SetupStyles();
private:
    bool isSetup = true;

    ImVec2 pos;
    ImVec2 size;
};
