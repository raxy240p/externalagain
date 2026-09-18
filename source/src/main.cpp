
#include <iostream>
#include <tlhelp32.h>
#pragma comment(lib, "Winmm.lib")
#include <timeapi.h>
#include <intrin.h>

#include "core/anti_debug/Crash.hpp"
#include "core/engine/Engine.hpp"
#include "gui/renderer/Renderer.hpp"
#include "core/memory/WinDrvReader.hpp"

#include <external/exception.hpp>
#include <skCrypter/skCrypter.hpp>
#include <lazy_importer/lazy_importer.hpp>
#include "core/anti_debug/AntiDebug.hpp"
#include "core/anti_debug/Opaque.hpp"

#define RESOLVE(fn) reinterpret_cast<decltype(&fn)>( \
    AntiDebug::ResolveExport(AntiDebug::Fnv1a(#fn)))

// ── Per-machine hardware fingerprint ─────────────────────────────────────────
// Mixes volume serial number + CPUID family/stepping into a stable DWORD.
// Used to generate a machine-unique driver drop path that avoids a predictable
// filename IOC like "iqvw64e.sys" while remaining stable across reboots.
static DWORD GetHwKey() {
    DWORD serial = 0;
    using GVI_fn = BOOL(WINAPI*)(LPCSTR, LPSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPSTR, DWORD);
    auto pGVI = (GVI_fn)AntiDebug::ResolveExport(AntiDebug::Fnv1a("GetVolumeInformationA"));
    if (pGVI) pGVI("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
    int cpu[4] = {};
    __cpuid(cpu, 1);
    return serial ^ (DWORD)cpu[0] ^ ((DWORD)cpu[3] << 7);
}

// ── Driver drop path ──────────────────────────────────────────────────────────
// Generates a machine-stable path like %SystemRoot%\System32\drivers\A3F19C2B.sys.
// Copy iqvw64e.sys (Intel NAL) to this path before launching.
static const char* GetDriverPath() {
    static char s_path[MAX_PATH] = {};
    static bool s_ready = false;
    if (!s_ready) {
        char sysDir[MAX_PATH] = {};
        GetSystemDirectoryA(sysDir, MAX_PATH);
        snprintf(s_path, MAX_PATH, "%s\\drivers\\%08lX.sys", sysDir, (unsigned long)GetHwKey());
        s_ready = true;
    }
    return s_path;
}

// ── SCM service name — derived from driver filename ───────────────────────────
static const char* GetSvcName() {
    static char s_name[16] = {};
    static bool s_ready = false;
    if (!s_ready) {
        const char* p     = GetDriverPath();
        const char* slash = strrchr(p, '\\');
        const char* src   = slash ? slash + 1 : p;
        int i = 0;
        while (*src && *src != '.' && i < 15) s_name[i++] = *src++;
        s_name[i] = '\0';
        s_ready = true;
    }
    return s_name;
}

static bool IsProcessRunning(const char* exeName) {
    auto pCreateToolhelp32Snapshot = RESOLVE(CreateToolhelp32Snapshot);
    auto pProcess32First           = RESOLVE(Process32First);
    auto pProcess32Next            = RESOLVE(Process32Next);
    auto pCloseHandle              = RESOLVE(CloseHandle);
    HANDLE snap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe = { sizeof(pe) };
    bool found = false;
    if (pProcess32First(snap, &pe))
        do { if (_stricmp(pe.szExeFile, exeName) == 0) { found = true; break; } }
        while (pProcess32Next(snap, &pe));
    pCloseHandle(snap);
    return found;
}

static bool IsDriverLoaded() {
    auto pCreateFileA = RESOLVE(CreateFileA);
    auto pCloseHandle = RESOLVE(CloseHandle);
    if (!pCreateFileA || !pCloseHandle) return false;
    HANDLE h = pCreateFileA(skCrypt("\\\\.\\Nal"),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    bool ok = (h != INVALID_HANDLE_VALUE);
    if (ok) pCloseHandle(h);
    return ok;
}

// Fast sanity check: the file at drvPath must exist, start with MZ,
// and be a plausible driver size. Catches a mis-copied file before
// SCM turns "bad content" into a useless err=577/1275.
static bool ValidateDriverFile(const char* drvPath) {
    auto pCreateFileA  = RESOLVE(CreateFileA);
    auto pCloseHandle  = RESOLVE(CloseHandle);
    auto pGetFileSizeEx = RESOLVE(GetFileSizeEx);
    auto pReadFile     = RESOLVE(ReadFile);
    if (!pCreateFileA || !pCloseHandle || !pGetFileSizeEx || !pReadFile) return false;
    HANDLE h = pCreateFileA(drvPath, GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!pGetFileSizeEx(h, &sz) || sz.QuadPart < 0x1000 || sz.QuadPart > 0x2000000) {
        pCloseHandle(h); return false;
    }
    uint16_t mz = 0;
    DWORD got = 0;
    bool ok = pReadFile(h, &mz, sizeof(mz), &got, nullptr) && got == sizeof(mz) && mz == 0x5A4D;
    pCloseHandle(h);
    return ok;
}

// Turn opaque Win32 codes into a one-line hint. Kept as static text —
// no dynamic lookup, no leaked format strings from resource DLLs.
static const char* DecodeStartErr(DWORD err) {
    switch (err) {
        case 5:    return "access denied — not elevated, or another handle holds the sys";
        case 32:   return "sharing violation — the sys file is in use, close and retry";
        case 87:   return "invalid parameter — CreateService args rejected";
        case 577:  return "ERROR_INVALID_IMAGE_HASH — driver blocklist rejected the signature";
        case 1275: return "ERROR_DRIVER_BLOCKED — blocklist / code integrity refused load";
        case 1058: return "service disabled";
        case 1073: return "service already exists under a different config";
        case 1450: return "no system resources (file may be delete-pending, wait and retry)";
        default:   return "";
    }
}

static bool StartDriver() {
    if (IsDriverLoaded()) return true;

    auto pOpenSCManagerA     = RESOLVE(OpenSCManagerA);
    auto pOpenServiceA       = RESOLVE(OpenServiceA);
    auto pCreateServiceA     = RESOLVE(CreateServiceA);
    auto pDeleteService      = RESOLVE(DeleteService);
    auto pStartServiceA      = RESOLVE(StartServiceA);
    auto pCloseServiceHandle = RESOLVE(CloseServiceHandle);
    auto pControlService     = RESOLVE(ControlService);
    auto pQueryServiceStatus = RESOLVE(QueryServiceStatus);
    auto pGetLastError       = RESOLVE(GetLastError);

    const char* svcName = GetSvcName();
    const char* drvPath = GetDriverPath();

    SC_HANDLE hSCM = pOpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        std::cout << "[!] SCM open failed\n";
        return false;
    }

    // Reuse existing service entry after reboot — avoids Event ID 7045 on every launch.
    SC_HANDLE hExist = pOpenServiceA(hSCM, svcName, SERVICE_ALL_ACCESS);
    if (hExist) {
        SERVICE_STATUS ss{};
        bool reused = false;

        if (pQueryServiceStatus && pQueryServiceStatus(hExist, &ss)) {
            for (int i = 0; i < 15 && ss.dwCurrentState == SERVICE_STOP_PENDING; i++) {
                Sleep(200);
                pQueryServiceStatus(hExist, &ss);
            }
            if (ss.dwCurrentState == SERVICE_STOPPED) {
                BOOL ok2  = pStartServiceA(hExist, 0, nullptr);
                DWORD e2  = pGetLastError();
                reused    = ok2 || e2 == ERROR_SERVICE_ALREADY_RUNNING;
            } else if (ss.dwCurrentState == SERVICE_RUNNING) {
                reused = true;
            }
        }

        if (reused) {
            pCloseServiceHandle(hExist);
            pCloseServiceHandle(hSCM);
            return true;
        }

        if (pControlService) {
            SERVICE_STATUS ss2{};
            pControlService(hExist, SERVICE_CONTROL_STOP, &ss2);
            for (int i = 0; i < 20; i++) {
                if (!pQueryServiceStatus || !pQueryServiceStatus(hExist, &ss2)) break;
                if (ss2.dwCurrentState == SERVICE_STOPPED) break;
                Sleep(150);
            }
        }
        pDeleteService(hExist);
        pCloseServiceHandle(hExist);
        Sleep(300);
    }

    if (GetFileAttributesA(drvPath) == INVALID_FILE_ATTRIBUTES) {
        std::cout << "[!] Driver file not found at: " << drvPath << "\n";
        std::cout << "    Copy iqvw64e.sys to that path and retry.\n";
        pCloseServiceHandle(hSCM);
        return false;
    }
    if (!ValidateDriverFile(drvPath)) {
        std::cout << "[!] Driver file at " << drvPath << " is not a valid PE image.\n";
        std::cout << "    Re-copy iqvw64e.sys to that path.\n";
        pCloseServiceHandle(hSCM);
        return false;
    }

    SC_HANDLE hSvc = pCreateServiceA(hSCM, svcName, svcName,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        drvPath, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hSvc) {
        DWORD e = pGetLastError();
        const char* hint = DecodeStartErr(e);
        std::cout << "[!] CreateService failed (err=" << e << ")";
        if (*hint) std::cout << " — " << hint;
        std::cout << "\n";
        pCloseServiceHandle(hSCM);
        return false;
    }

    BOOL started = pStartServiceA(hSvc, 0, nullptr);
    DWORD err    = pGetLastError();
    bool  ok     = started || err == ERROR_SERVICE_ALREADY_RUNNING;

    if (!ok) {
        const char* hint = DecodeStartErr(err);
        std::cout << "[!] StartService failed (err=" << err << ")";
        if (*hint) std::cout << " — " << hint;
        std::cout << "\n";
        if (err == 577 || err == 1275) {
            std::cout << "    Driver blocklist rejected iqvw64e. Options:\n"
                         "      - HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
                         " → VulnerableDriverBlocklistEnable = 0, reboot\n"
                         "      - Or use a Windows build/SKU without the blocklist\n";
        }
        pDeleteService(hSvc);
        DeleteFileA(drvPath);
    }

    pCloseServiceHandle(hSvc);
    pCloseServiceHandle(hSCM);
    return ok;
}

// Stops the SCM service and deletes the driver file on clean exit.
static void StopDriver() {
    auto pOpenSCManagerA     = RESOLVE(OpenSCManagerA);
    auto pOpenServiceA       = RESOLVE(OpenServiceA);
    auto pControlService     = RESOLVE(ControlService);
    auto pQueryServiceStatus = RESOLVE(QueryServiceStatus);
    auto pDeleteService      = RESOLVE(DeleteService);
    auto pCloseServiceHandle = RESOLVE(CloseServiceHandle);
    if (!pOpenSCManagerA || !pOpenServiceA || !pCloseServiceHandle) return;

    SC_HANDLE hSCM = pOpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return;

    SC_HANDLE hSvc = pOpenServiceA(hSCM, GetSvcName(),
                                   SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (hSvc) {
        if (pControlService) {
            SERVICE_STATUS ss{};
            pControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
            // Poll until SERVICE_STOPPED — a fixed sleep is insufficient.
            // The kernel must fully release the image file before DeleteFileA;
            // otherwise the file enters delete-pending state and causes err=1450 on
            // the next load attempt.
            if (pQueryServiceStatus) {
                for (int i = 0; i < 80; i++) {
                    if (pQueryServiceStatus(hSvc, &ss) &&
                        ss.dwCurrentState == SERVICE_STOPPED)
                        break;
                    Sleep(100);
                }
            } else {
                Sleep(3000);
            }
        }
        if (pDeleteService) pDeleteService(hSvc);
        pCloseServiceHandle(hSvc);
    }
    pCloseServiceHandle(hSCM);
    DeleteFileA(GetDriverPath());
}

static bool IsElevated() {
    using NtOPT_fn  = NTSTATUS(NTAPI*)(HANDLE, ACCESS_MASK, PHANDLE);
    using NtQIT_fn  = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtCH_fn   = NTSTATUS(NTAPI*)(HANDLE);
    auto pNtOPT = (NtOPT_fn)AntiDebug::ResolveExport(AntiDebug::Fnv1a("NtOpenProcessToken"));
    auto pNtQIT = (NtQIT_fn)AntiDebug::ResolveExport(AntiDebug::Fnv1a("NtQueryInformationToken"));
    auto pNtCH  = (NtCH_fn) AntiDebug::ResolveExport(AntiDebug::Fnv1a("NtClose"));
    if (!pNtOPT || !pNtQIT || !pNtCH) return false;
    HANDLE hToken = nullptr;
    if (pNtOPT((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &hToken) < 0) return false;
    TOKEN_ELEVATION te{};
    ULONG sz = sizeof(te);
    NTSTATUS st = pNtQIT(hToken, 20 /*TokenElevation*/, &te, sz, &sz);
    pNtCH(hToken);
    return st >= 0 && te.TokenIsElevated;
}

int main()
{
    SetConsoleTitleA(skCrypt("CS2 External ESP"));
    {
        HANDLE _h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD  _m = 0;
        if (GetConsoleMode(_h, &_m))
            SetConsoleMode(_h, _m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    if (!IsElevated()) {
        std::cout << "  \033[91m[!]\033[0m Run as administrator.\n\n  Press Enter to exit.\n";
        std::cin.get();
        return 1;
    }

    RESOLVE(timeBeginPeriod)(1);
    c_exception_handler::setup();

    std::cout << "\033[2J\033[H\n";
    std::cout << skCrypt("  \033[94mCS2 External ESP\033[0m\n");
    std::cout << "  \033[34m------------------------------------------\033[0m\n\n";

    AntiDebug::Assert();

    // ── Driver loading ────────────────────────────────────────────────────────
    std::cout << "  \033[96m[*]\033[0m Starting driver...\n";
    bool drvStarted = StartDriver();
    std::cout << (drvStarted
        ? "  \033[92m[+]\033[0m Driver ready.\n\n"
        : "  \033[91m[!]\033[0m Driver start failed.\n\n");

    if (!drvStarted) {
        std::cout << "  Press Enter to exit.\n";
        std::cin.get();
        goto exit;
    }

    std::cout << skCrypt("  \033[96m[*]\033[0m Waiting for driver and CS2...\n\n");
    {
        bool drvReady  = false, cs2Ready = false;
        int  waitedMs  = 0;
        int  spinIdx   = 0;
        const char* sp = "|/-\\";

        while (!drvReady || !cs2Ready) {
            drvReady = IsDriverLoaded();
            cs2Ready = IsProcessRunning(skCrypt("cs2.exe"));

            std::cout
                << "\r    \033[90m" << sp[spinIdx++ % 4] << "\033[0m  "
                << "\033[96m[\033[0m"
                << (drvReady ? "\033[92m+\033[0m" : "\033[91m-\033[0m")
                << "\033[96m]\033[0m drv   \033[96m[\033[0m"
                << (cs2Ready  ? "\033[92m+\033[0m" : "\033[91m-\033[0m")
                << "\033[96m]\033[0m game     ";
            std::cout.flush();

            if (!drvReady && waitedMs >= 15000) {
                std::cout << "\n\n  \033[91m[!]\033[0m Driver did not load.\n\n  Press Enter to exit.\n";
                std::cin.get();
                goto exit;
            }
            if (!drvReady || !cs2Ready) {
                Sleep(1500);
                waitedMs += 1500;
            }
        }
    }

    std::cout << "\n\n  \033[92m[+]\033[0m All checks passed.\n\n";

    {
        auto pGetAsyncKeyState = RESOLVE(GetAsyncKeyState);
        auto pSleep            = RESOLVE(Sleep);
        int  ai = 0;
        while (!(pGetAsyncKeyState('R') & 1)) {
            if (ai % 16 < 8)
                std::cout << "\r  \033[94m>> Press R to launch the overlay <<\033[0m  ";
            else
                std::cout << "\r  \033[34m>> Press R to launch the overlay <<\033[0m  ";
            std::cout.flush();
            ++ai;
            pSleep(50);
        }
        std::cout << "\r  \033[92m>> Launching...                     \033[0m\n\n";
    }

    // ── Engine + Renderer init ────────────────────────────────────────────────
    LogHelper::Init();
    {
        auto pSetPriorityClass  = RESOLVE(SetPriorityClass);
        auto pGetCurrentProcess = RESOLVE(GetCurrentProcess);
        pSetPriorityClass(pGetCurrentProcess(), HIGH_PRIORITY_CLASS);
    }

    {
        bool engineOk   = Engine::Init();
        bool rendererOk = engineOk && Renderer::Init();

        if (!engineOk) {
            std::cout << "  \033[91m[!]\033[0m Engine init failed. Press Enter to exit.\n";
            std::cin.get();
            goto exit;
        }
        if (!rendererOk) {
            std::cout << "  \033[91m[!]\033[0m Renderer init failed. Press Enter to exit.\n";
            std::cin.get();
            goto exit;
        }
    }

    std::cout << "  \033[92m[+]\033[0m Overlay running.\n";

    AntiDebug::LateHarden();
    WinDrvReader::Get().SetIdleMode(true);
    AntiDebug::SanitizePebModuleList();
    RESOLVE(FreeConsole)();
    Renderer::Thread();

exit:
    StopDriver();
    LogHelper::Destroy();
    RESOLVE(timeEndPeriod)(1);
}
