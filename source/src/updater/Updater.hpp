#pragma once
#include <string>

// Stub — the original Updater fetched remote notices from a server.
// Kept as a no-op so Overlays::RenderNotice() compiles and silently returns
// (status.notice is always empty, so nothing draws).
class Updater {
public:
    struct Status {
        std::string notice;
    };

    static Status GetStatus() { return {}; }
};
