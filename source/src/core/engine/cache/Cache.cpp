#include "Cache.hpp"

#include "core/engine/Engine.hpp"
#include "core/offsets/Dumper.hpp"
#include "core/memory/Memory.hpp"
#include "core/memory/WinDrvReader.hpp"
#include "core/anti_debug/Opaque.hpp"
#include "core/anti_debug/AntiDebug.hpp"
#include <cstring>
#include <unordered_map>
#include <tlhelp32.h>
#include <numeric>
#include <cstdarg>

// FLog was a diagnostic writer to "esp_debug.txt" next to the exe.
// Both the filename string and the "esp_debug" identifier are trivial
// IOCs for static scanners. Neutered to an inline no-op — the compiler
// drops the call sites entirely so no diagnostic strings leak.
static inline void FLog(const char*, ...) {}

bool Cache::Refresh() {
    return Get().RefreshImpl();
}

Snapshot Cache::CopySnapshot() {
    std::lock_guard<std::mutex> lock(Get().mtx);
    return {
        Get().game,
        Get().local,
        Get().globals,
        Get().players,
        Get().last   // time the scan completed — used by renderer for velocity prediction
    };
}

bool Cache::RefreshImpl() {
    auto p = Engine::GetProcess();

    if (!p)
        return false;

    auto now = steady_clock::now();

    // PA cache is intentionally never cleared mid-session: CS2 does not remap
    // its data sections during a match, so cached VAs stay valid for the session.

    if (!game.Update())
        return false;

    game.UpdateEntityList();

#ifdef _DEBUG
    if (now - last < (cfg::dev::cache_refresh_rate * 1ms))
        return true;
#endif

    globals.Update();

    // LCG for all randomisation this frame
    static uint64_t s_rng = 0;
    if (!s_rng) {
        s_rng = (uint64_t)steady_clock::now().time_since_epoch().count() ^ 0x517CC1B727220A95ULL;
    }
    auto lcgNext = [&]() -> uint64_t {
        s_rng = s_rng * 6364136223846793005ULL + 1442695040888963407ULL;
        return s_rng;
    };

    // Decoy reads: occasionally read a few pages from explorer.exe to dilute
    // the "only touches CS2 physical pages" pattern visible to kernel ACs.
    {
        static uint64_t s_decoyCr3   = 0;
        static int      s_decoyTick  = 0;
        static int      s_decoyEvery = 6;

        if (!s_decoyCr3) {
            using PFN_Snap  = HANDLE(WINAPI*)(DWORD, DWORD);
            using PFN_Proc  = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32);
            using PFN_Close = BOOL(WINAPI*)(HANDLE);
            auto pSnap  = reinterpret_cast<PFN_Snap>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("CreateToolhelp32Snapshot")));
            auto pFirst = reinterpret_cast<PFN_Proc>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("Process32First")));
            auto pNext  = reinterpret_cast<PFN_Proc>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("Process32Next")));
            auto pClose = reinterpret_cast<PFN_Close>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("CloseHandle")));
            if (pSnap && pFirst && pNext && pClose) {
                HANDLE snap = pSnap(TH32CS_SNAPPROCESS, 0);
                if (snap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32 pe = { sizeof(pe) };
                    if (pFirst(snap, &pe)) {
                        do {
                            if (_stricmp(pe.szExeFile, skCrypt("explorer.exe")) == 0) {
                                s_decoyCr3 = WinDrvReader::Get().GetCr3ForProcess(pe.th32ProcessID);
                                break;
                            }
                        } while (pNext(snap, &pe));
                    }
                    pClose(snap);
                }
            }
        }

        if (++s_decoyTick >= s_decoyEvery && s_decoyCr3) {
            s_decoyTick  = 0;
            s_decoyEvery = (int)(4 + (lcgNext() >> 61) % 5); // next interval: 4-8 frames
            // Read 2 random user-mode pages from the decoy process and discard
            for (int d = 0; d < 2; d++) {
                uint64_t decoyVA = 0x10000 + ((lcgNext() >> 16) & 0x3FFF) * 0x1000;
                uint8_t  dummy[16];
                WinDrvReader::Get().ReadVirtual(s_decoyCr3, decoyVA, dummy, sizeof(dummy));
            }
        }
    }

    // Always scan all 64 slots. Using max_clients here caused "only 2 ESP" after
    // warmup end: mp_restartgame briefly sets maxClients=2 via a stale PA read,
    // shrinking the scan to 2 indices. Empty slots fail GetController() cheaply.
    constexpr int maxPlayers = 64;
    std::vector<Player> scan;
    scan.reserve(maxPlayers);

    // Randomise entity read order each frame so the physical-page access sequence
    // is never a predictable 0→N stride (Fisher-Yates with the per-frame LCG).
    std::vector<int> indices(maxPlayers);
    std::iota(indices.begin(), indices.end(), 0);
    for (int i = maxPlayers - 1; i > 0; i--) {
        int j = (int)(lcgNext() >> 33) % (i + 1);
        std::swap(indices[i], indices[j]);
    }

    int passed_update = 0;
    for (int k = 0; k < maxPlayers; k++) {
        int i = indices[k];

        auto player = Player(i, game.entity_list, game.list_entry);

        if (!player.Update())
            continue;
        passed_update++;

        scan.push_back(player);
    }

#ifdef _DEBUG
    static bool s_scanLog = false;
    if (!s_scanLog && !scan.empty()) {
        s_scanLog = true;
        int alive = 0;
        for (auto& pl : scan) if (pl.alive) alive++;
        printf("[SCAN] total=%d alive=%d passed_update=%d local_team=%d local_found=%d\n",
               (int)scan.size(), alive, passed_update, (int)local.team, (int)local.localplayer);
        FLog("[SCAN] total=%d alive=%d passed_update=%d local_team=%d local_found=%d\n",
             (int)scan.size(), alive, passed_update, (int)local.team, (int)local.localplayer);
        FLog("[VM] m[0][0]=%.3f m[0][1]=%.3f m[0][2]=%.3f m[0][3]=%.3f\n",
             game.view_matrix.matrix[0][0], game.view_matrix.matrix[0][1],
             game.view_matrix.matrix[0][2], game.view_matrix.matrix[0][3]);
    }
#else
    (void)passed_update; (void)local;
#endif

    {
        std::lock_guard<std::mutex> lock(mtx);
        for (const auto& pl : scan)
            if (pl.localplayer) { local = pl; break; }
        players = std::move(scan);

        duration = duration_cast<std::chrono::milliseconds>(now - last);
        last = now;
    }

    return true;
}
