#include "Engine.hpp"
#include "core/offsets/Dumper.hpp"
#include "core/engine/cache/Cache.hpp"
#include "core/memory/WinDrvReader.hpp"
#include "core/anti_debug/AntiDebug.hpp"
#include <psapi.h>
#include <thread>
#include <chrono>
#include <tlhelp32.h>
#include <lazy_importer/lazy_importer.hpp>

bool Engine::Init() {
    return GetInstance().InitImpl();
}

ProcessModule Engine::GetClient() {
    return GetInstance().client;
}

ProcessModule Engine::GetEngine() {
    return GetInstance().engine;
}

std::shared_ptr<pProcess> Engine::GetProcess() {
    return GetInstance().process;
}

void Engine::StartCacheThread() {
    static std::once_flag started;
    std::call_once(started, [] {
        std::thread(&Engine::Thread, &GetInstance()).detach();
        });
}

bool Engine::InitImpl() {
    auto& drv = WinDrvReader::Get();

    printf(skCrypt("[SysMonitor] starting...\n"));

    // Reset breaker/armed state FIRST so Open()'s NtioArm run genuinely
    // arms the driver (rather than being skipped by a stale m_armed=true
    // from a previous Engine::Init attempt in the same process lifetime).
    drv.ResetIoBreaker();

    if (!drv.Open()) {
        printf(skCrypt("[SysMonitor] Failed to open device\n"));
        return false;
    }
    printf(skCrypt("[SysMonitor] NTIOLib driver ready\n"));

    process = std::make_shared<pProcess>();

    if (!this->AwaitProcess()) {
        printf(skCrypt("[SysMonitor] CS2 not found\n"));
        return false;
    }

    if (!drv.ResolveSystemCr3()) {
        printf(skCrypt("[SysMonitor] Failed to resolve system CR3\n"));
        return false;
    }

    uint64_t cr3 = drv.GetProcessCr3(process->pid_);
    if (!cr3) {
        printf(skCrypt("[SysMonitor] Failed to resolve CS2 CR3\n"));
        return false;
    }
    process->m_cachedCr3 = cr3;
    printf(skCrypt("[SysMonitor] CR3 resolved: 0x%llX\n"), (unsigned long long)cr3);

    // Faster poll cadence (250ms) with the same ~60s total budget: modules
    // usually appear within a few seconds of the CS2 window; the old 2s
    // cadence added up to ~2s of idle wait even in the fast path. 240
    // attempts × 250 ms = 60 s cap.
    uint32_t clientSize = 0, engineSize = 0;
    uint64_t clientBase = 0, engineBase = 0;
    for (int attempt = 0; attempt < 240; attempt++) {
        clientBase = drv.GetModuleBasePhysical(cr3, skCryptW(L"client.dll"), &clientSize);
        engineBase = drv.GetModuleBasePhysical(cr3, skCryptW(L"engine2.dll"), &engineSize);
        if (clientBase && engineBase) break;
        if (attempt == 0)
            printf(skCrypt("[SysMonitor] waiting for modules...\n"));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    if (!clientBase || !engineBase) {
        printf(skCrypt("[SysMonitor] modules not found\n"));
        return false;
    }

    this->client = { clientBase, clientSize };
    this->engine = { engineBase, engineSize };
    process->base_client_ = this->client;
    printf(skCrypt("[SysMonitor] modules loaded\n"));

    if (!Dumper::Init()) {
        printf(skCrypt("[SysMonitor] offsets failed\n"));
        return false;
    }

    if (!Config::Read())
        printf(skCrypt("[SysMonitor] config load failed, using defaults\n"));

    StartCacheThread();

    printf(skCrypt("[SysMonitor] ready\n"));
    return true;
}

void Engine::Thread() {
    {
        using FSTP = BOOL(WINAPI*)(HANDLE, int);
        auto pSetThreadPriority = reinterpret_cast<FSTP>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("SetThreadPriority")));
        pSetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    }
    using FGTC = ULONGLONG(WINAPI*)();
    auto pGetTickCount64 = reinterpret_cast<FGTC>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("GetTickCount64")));
    uint64_t lcg = (uint64_t)pGetTickCount64() ^ 0xDEADBEEFCAFEBABEULL;
    while (true) {
        auto start = std::chrono::steady_clock::now();
        bool active = Cache::Refresh();
        static int s_fails = 0;
        if (active) s_fails = 0;
        else        s_fails++;

        lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
        if (s_fails > 30) {
            int jitter = (int)(lcg >> 57) % 20;
            std::this_thread::sleep_until(start + std::chrono::milliseconds(60 + jitter));
        } else {
            int jitter = (int)(lcg >> 59) % 8;
            std::this_thread::sleep_until(start + std::chrono::milliseconds(5 + jitter));
        }
    }
}

bool Engine::AwaitProcess() {
    // 200ms poll cadence (5x faster than the old 1s) with the same 60s
    // total budget: 300 attempts × 200 ms. Typical case wins within a
    // couple of iterations of CS2 opening; the tight cadence just means
    // we don't waste up to 800 ms staring at nothing on the fast path.
    using FFWA = HWND(WINAPI*)(LPCSTR, LPCSTR);
    using FGWTPID = DWORD(WINAPI*)(HWND, LPDWORD);
    auto pFindWindowA = reinterpret_cast<FFWA>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("FindWindowA")));
    auto pGetWindowThreadProcessId = reinterpret_cast<FGWTPID>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("GetWindowThreadProcessId")));
    for (int i = 0; i < 300; i++) {
        HWND hwnd = pFindWindowA(nullptr, skCrypt("Counter-Strike 2"));
        if (hwnd) {
            DWORD pid = 0;
            pGetWindowThreadProcessId(hwnd, &pid);
            if (pid) {
                process->pid_ = pid;
                process->hwnd_ = hwnd;
                printf(skCrypt("[SysMonitor] CS2 found\n"));
                return true;
            }
        }
        if (i == 0) printf(skCrypt("[SysMonitor] waiting for CS2...\n"));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return false;
}

bool Engine::AwaitModules() {
    return true;
}
