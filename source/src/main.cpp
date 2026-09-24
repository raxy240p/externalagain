
#include <iostream>
#include <vector>
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
// filename IOC like "RTCore64.sys" while remaining stable across reboots.
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
// Copy RTCore64.sys (MSI Afterburner monitoring driver, Micro-Star INT'L CO.,
// LTD, WHCP-signed via GlobalSign EV + Microsoft Windows Hardware Compatibility
// Publisher) to this path before launching. RTCore64 exports a plain
// MmMapIoSpace read/write primitive without an arm-magic gate.
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

// Attempt the device open with a specific (path, access) combination.
// Returns handle or INVALID_HANDLE_VALUE. Fills outErr on failure.
static HANDLE TryOpenDevice(const char* path, DWORD access, DWORD* outErr) {
    auto pCreateFileA  = RESOLVE(CreateFileA);
    auto pGetLastError = RESOLVE(GetLastError);
    HANDLE h = pCreateFileA
        ? pCreateFileA(path, access,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       nullptr, OPEN_EXISTING, 0, nullptr)
        : INVALID_HANDLE_VALUE;
    if (h == INVALID_HANDLE_VALUE && outErr && pGetLastError)
        *outErr = pGetLastError();
    return h;
}

// RTCore64 hardcodes its \Device\RTCore64 path at DriverEntry —
// we can't rename it without patching the signed driver. The SCM service
// name and on-disk filename remain machine-stable-hex to hide THOSE two
// IOCs; the device path itself has to be accepted as-is.
static const char* GetDevicePathUserMode() {
    return "\\\\.\\RTCore64";
}
static const char* GetDevicePathGlobal() {
    return "\\\\.\\GLOBALROOT\\Device\\RTCore64";
}

// Recovery probe: try several access modes + path spellings against the
// device RTCore64 publishes at DriverEntry. First success wins.
static bool ProbeDeviceAllVariants(DWORD* outErr) {
    auto pCloseHandle = RESOLVE(CloseHandle);
    if (!pCloseHandle) { if (outErr) *outErr = 0; return false; }

    const char* pathA = GetDevicePathUserMode();
    const char* pathB = GetDevicePathGlobal();

    struct Attempt { const char* path; DWORD access; };
    Attempt attempts[] = {
        { pathA, GENERIC_READ | GENERIC_WRITE },
        { pathA, GENERIC_READ                 },
        { pathA, SYNCHRONIZE                  },
        { pathA, 0                            },
        { pathB, GENERIC_READ | GENERIC_WRITE },
        { pathB, 0                            },
    };
    DWORD lastErr = 0;
    for (auto& a : attempts) {
        DWORD e = 0;
        HANDLE h = TryOpenDevice(a.path, a.access, &e);
        if (h != INVALID_HANDLE_VALUE) {
            pCloseHandle(h);
            if (outErr) *outErr = 0;
            return true;
        }
        lastErr = e;
    }
    if (outErr) *outErr = lastErr;
    return false;
}

// Backward-compat shim — most callers use this shape.
static bool IsDriverLoaded(DWORD* outErr = nullptr) {
    return ProbeDeviceAllVariants(outErr);
}

// ── Manual-map payload path (replaces SCM-based driver load) ─────────────────
//
// The old flow started a signed BYOVD via SCM. That model's dead — every
// signed hardware-sensor driver has a PA whitelist (verified via disassembly
// of NTIOLib, RTCore64, and WinRing0). New flow: TheCruZ/kdmapper.exe
// exploits iqvw64e.sys to manual-map source/payload/payload.sys into kernel
// memory. The payload creates a named shared section, spawns a system
// thread, and services read/write requests without a device object.
//
// IsPayloadLoaded checks the shared section presence — that's proof the
// payload is running and the reader thread is servicing requests.
static bool IsPayloadLoaded() {
    HANDLE h = OpenFileMappingA(FILE_MAP_READ, FALSE, PAYLOAD_SECTION_NAME);
    if (!h) return false;
    CloseHandle(h);
    return true;
}

// Locate mapper + payload alongside our exe. Both must sit next to the
// launcher on disk: <exe_dir>\kdmapper.exe and <exe_dir>\payload.sys.
static bool GetSiblingPath(const char* filename, char out[MAX_PATH]) {
    char self[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, self, MAX_PATH)) return false;
    char* slash = strrchr(self, '\\');
    if (!slash) return false;
    *slash = '\0';
    return snprintf(out, MAX_PATH, "%s\\%s", self, filename) < MAX_PATH;
}

// Spawn kdmapper.exe with payload.sys as its argument. Blocks until the
// mapper exits. Returns true iff exit code is 0 AND the shared section
// is now visible.
static bool LaunchMapper() {
    if (IsPayloadLoaded()) {
        std::cout << "  \033[96m[*]\033[0m Payload already mapped (survived from earlier run).\n";
        return true;
    }

    char mapper[MAX_PATH] = {};
    char payload[MAX_PATH] = {};
    if (!GetSiblingPath("kdmapper.exe", mapper) ||
        !GetSiblingPath("payload.sys", payload)) {
        std::cout << "  \033[91m[!]\033[0m Path resolution failed for mapper/payload.\n";
        return false;
    }
    if (GetFileAttributesA(mapper) == INVALID_FILE_ATTRIBUTES) {
        std::cout << "  \033[91m[!]\033[0m " << mapper << " not found.\n"
                     "      Build TheCruZ/kdmapper (see source/mapper/README.md) and drop\n"
                     "      kdmapper.exe next to this launcher.\n";
        return false;
    }
    if (GetFileAttributesA(payload) == INVALID_FILE_ATTRIBUTES) {
        std::cout << "  \033[91m[!]\033[0m " << payload << " not found.\n"
                     "      Build the payload (see source/payload/README.md) and drop\n"
                     "      payload.sys next to this launcher.\n";
        return false;
    }

    char cmdline[MAX_PATH * 3] = {};
    snprintf(cmdline, sizeof(cmdline), "\"%s\" \"%s\"", mapper, payload);

    STARTUPINFOA si{}; si.cb = sizeof(si);
    si.dwFlags   = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};

    if (!CreateProcessA(nullptr, cmdline, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        std::cout << "  \033[91m[!]\033[0m CreateProcess failed err=" << GetLastError() << "\n";
        return false;
    }
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD ec = 1;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (ec != 0) {
        std::cout << "  \033[91m[!]\033[0m kdmapper exit code " << ec
                  << " -- check its output for BYOVD load failure or blocklist.\n";
        return false;
    }

    // Section may take a tick to appear even after mapper exits (payload's
    // DriverEntry runs after the mapper's exploit thread returns). Poll briefly.
    for (int i = 0; i < 40; i++) {
        if (IsPayloadLoaded()) return true;
        Sleep(50);
    }
    std::cout << "  \033[91m[!]\033[0m Mapper reported success but payload section never appeared.\n";
    return false;
}

// Case-C recovery: SCM says the service crashed (state=STOPPED) or the
// device is unopenable after a fresh start. Stop the service if it's
// stuck and restart it once. Returns true if the restart cycle produced
// a working device.
static bool RestartDriverService(const char* svcName) {
    auto pOpenSCManagerA     = RESOLVE(OpenSCManagerA);
    auto pOpenServiceA       = RESOLVE(OpenServiceA);
    auto pControlService     = RESOLVE(ControlService);
    auto pQueryServiceStatus = RESOLVE(QueryServiceStatus);
    auto pStartServiceA      = RESOLVE(StartServiceA);
    auto pCloseServiceHandle = RESOLVE(CloseServiceHandle);
    if (!pOpenSCManagerA || !pOpenServiceA || !pStartServiceA || !pCloseServiceHandle)
        return false;

    SC_HANDLE hSCM = pOpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = pOpenServiceA(hSCM, svcName,
                                    SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) { pCloseServiceHandle(hSCM); return false; }

    // Stop if currently running (or in a transitional state).
    if (pControlService && pQueryServiceStatus) {
        SERVICE_STATUS ss{};
        if (pQueryServiceStatus(hSvc, &ss) && ss.dwCurrentState != SERVICE_STOPPED) {
            SERVICE_STATUS discard{};
            pControlService(hSvc, SERVICE_CONTROL_STOP, &discard);
            for (int i = 0; i < 40; i++) {
                if (pQueryServiceStatus(hSvc, &ss) && ss.dwCurrentState == SERVICE_STOPPED) break;
                Sleep(100);
            }
        }
    }

    Sleep(200);
    BOOL started = pStartServiceA(hSvc, 0, nullptr);
    pCloseServiceHandle(hSvc);
    pCloseServiceHandle(hSCM);
    if (!started) return false;

    // Wait up to 4 s for the fresh device to publish.
    for (int i = 0; i < 40; i++) {
        if (ProbeDeviceAllVariants(nullptr)) return true;
        Sleep(100);
    }
    return false;
}

// Full three-case recovery. Returns true when the device is ready.
//   Case A (svc=RUNNING, err=2)  → give the driver longer to publish,
//                                  then try a stop/start cycle
//   Case B (svc=RUNNING, err=5)  → already covered by ProbeDeviceAllVariants
//                                  above (multiple access-mode fallbacks)
//   Case C (svc=STOPPED)         → restart cycle
static bool RecoverDriverDevice(const char* svcName, int budgetMs = 20000) {
    auto pOpenSCManagerA     = RESOLVE(OpenSCManagerA);
    auto pOpenServiceA       = RESOLVE(OpenServiceA);
    auto pQueryServiceStatus = RESOLVE(QueryServiceStatus);
    auto pCloseServiceHandle = RESOLVE(CloseServiceHandle);
    if (!pOpenSCManagerA || !pOpenServiceA || !pQueryServiceStatus || !pCloseServiceHandle)
        return ProbeDeviceAllVariants(nullptr);

    int waited = 0;
    bool triedRestart = false;
    while (waited < budgetMs) {
        // Case B fix runs first inside ProbeDeviceAllVariants (access variants).
        if (ProbeDeviceAllVariants(nullptr)) return true;

        // Sample service state to decide next action.
        SC_HANDLE hSCM = pOpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        DWORD state = 0;
        if (hSCM) {
            SC_HANDLE hSvc = pOpenServiceA(hSCM, svcName, SERVICE_QUERY_STATUS);
            if (hSvc) {
                SERVICE_STATUS ss{};
                if (pQueryServiceStatus(hSvc, &ss)) state = ss.dwCurrentState;
                pCloseServiceHandle(hSvc);
            }
            pCloseServiceHandle(hSCM);
        }

        // Case C — driver crashed after load. One clean restart cycle.
        if (state == SERVICE_STOPPED && !triedRestart) {
            triedRestart = true;
            if (RestartDriverService(svcName)) return true;
            waited += 5000; // restart cycle already burns ~4-5 s
            continue;
        }

        // Case A — service running but device still absent. Wait longer
        // (some drivers publish the symlink lazily after WdfDeviceCreate)
        // then try a restart cycle once.
        if (state == SERVICE_RUNNING && !triedRestart) {
            // Give it another 3 s of settle time before escalating.
            for (int i = 0; i < 30 && waited < budgetMs; i++) {
                Sleep(100); waited += 100;
                if (ProbeDeviceAllVariants(nullptr)) return true;
            }
            if (waited >= budgetMs) break;
            // Escalate to restart cycle.
            triedRestart = true;
            if (RestartDriverService(svcName)) return true;
            waited += 5000;
            continue;
        }

        Sleep(200); waited += 200;
    }
    return false;
}

// Query current service state via SCM. Useful to distinguish "driver
// crashed after load" (state=STOPPED) from "driver running but device
// never published" (state=RUNNING, but device unopenable).
static DWORD QueryServiceState(const char* svcName) {
    auto pOpenSCManagerA     = RESOLVE(OpenSCManagerA);
    auto pOpenServiceA       = RESOLVE(OpenServiceA);
    auto pQueryServiceStatus = RESOLVE(QueryServiceStatus);
    auto pCloseServiceHandle = RESOLVE(CloseServiceHandle);
    if (!pOpenSCManagerA || !pOpenServiceA || !pQueryServiceStatus || !pCloseServiceHandle) return 0;
    SC_HANDLE hSCM = pOpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return 0;
    SC_HANDLE hSvc = pOpenServiceA(hSCM, svcName, SERVICE_QUERY_STATUS);
    DWORD state = 0;
    if (hSvc) {
        SERVICE_STATUS ss{};
        if (pQueryServiceStatus(hSvc, &ss)) state = ss.dwCurrentState;
        pCloseServiceHandle(hSvc);
    }
    pCloseServiceHandle(hSCM);
    return state;
}
static const char* SvcStateName(DWORD s) {
    switch (s) {
        case SERVICE_STOPPED:          return "STOPPED";
        case SERVICE_START_PENDING:    return "START_PENDING";
        case SERVICE_STOP_PENDING:     return "STOP_PENDING";
        case SERVICE_RUNNING:          return "RUNNING";
        case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
        case SERVICE_PAUSE_PENDING:    return "PAUSE_PENDING";
        case SERVICE_PAUSED:           return "PAUSED";
        default:                       return "(no service / unknown)";
    }
}

// RTCore64's DriverEntry publishes \Device\RTCore64 unconditionally and
// reads no Parameters subkey values. Plain SCM registration under
// HKLM\SYSTEM\...\Services\<svc> is enough for SCM to load it.

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
        case 1072: return "service marked for deletion — SCM still finalising, retry momentarily";
        case 1073: return "service already exists under a different config";
        case 1275: return "ERROR_DRIVER_BLOCKED — blocklist / code integrity refused load";
        case 1058: return "service disabled";
        case 1450: return "no system resources (file may be delete-pending, wait and retry)";
        default:   return "";
    }
}

static bool StartDriver() {
    // No early "device already open, skip everything" shortcut here on
    // purpose. dj's spec: "if already opened kill it, start the same
    // service/device/driver again". Every invocation walks the self-healing
    // lifecycle — stop any pre-existing instance, delete its service,
    // recreate ours, start it — so we never inherit hidden state from a
    // previous session, a crashed run, or another cheat that happened to
    // land on the same machine-stable service name.
    //
    // SCM APIs live in advapi32.dll. It's not necessarily loaded yet at this
    // point (static CRT + no direct advapi32 references), so ResolveExport
    // would return nullptr and the first call would crash silently.
    // Force-load it once, then resolve.
    {
        using LLA_fn = HMODULE(WINAPI*)(LPCSTR);
        auto pLoadLibraryA = reinterpret_cast<LLA_fn>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("LoadLibraryA")));
        if (pLoadLibraryA) pLoadLibraryA(skCrypt("advapi32.dll"));
    }

    auto pOpenSCManagerA     = RESOLVE(OpenSCManagerA);
    auto pOpenServiceA       = RESOLVE(OpenServiceA);
    auto pCreateServiceA     = RESOLVE(CreateServiceA);
    auto pDeleteService      = RESOLVE(DeleteService);
    auto pStartServiceA      = RESOLVE(StartServiceA);
    auto pCloseServiceHandle = RESOLVE(CloseServiceHandle);
    auto pControlService     = RESOLVE(ControlService);
    auto pQueryServiceStatus = RESOLVE(QueryServiceStatus);
    auto pGetLastError       = RESOLVE(GetLastError);

    if (!pOpenSCManagerA || !pOpenServiceA || !pCreateServiceA ||
        !pDeleteService || !pStartServiceA || !pCloseServiceHandle) {
        std::cout << "[!] SCM API resolution failed (advapi32 not loaded?)\n";
        return false;
    }

    const char* svcName = GetSvcName();
    const char* drvPath = GetDriverPath();

    SC_HANDLE hSCM = pOpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        std::cout << "[!] SCM open failed\n";
        return false;
    }

    // (RTCore64.sys reads no Parameters values at DriverEntry — device
    // creation is unconditional, so no pre-start registry writes needed.)

    // Validate the on-disk image BEFORE tearing down any existing service so
    // we don't leave dj without a working service AND without a valid file.
    if (GetFileAttributesA(drvPath) == INVALID_FILE_ATTRIBUTES) {
        std::cout << "[!] Driver file not found at: " << drvPath << "\n";
        std::cout << "    Copy RTCore64.sys to that path and retry.\n";
        pCloseServiceHandle(hSCM);
        return false;
    }
    if (!ValidateDriverFile(drvPath)) {
        std::cout << "[!] Driver file at " << drvPath << " is not a valid PE image.\n";
        std::cout << "    Re-copy RTCore64.sys to that path.\n";
        pCloseServiceHandle(hSCM);
        return false;
    }

    // Reuse existing service entry after reboot — avoids Event ID 7045 on every launch.
    SC_HANDLE hExist = pOpenServiceA(hSCM, svcName, SERVICE_ALL_ACCESS);
    if (hExist) {
        // Self-healing lifecycle: if the service already exists (from a
        // previous run or a crashed session), stop → delete → recreate.
        // This guarantees the device object was published fresh under our
        // expected name, and no stale driver-state carries into this session.
        SERVICE_STATUS ss{};
        if (pQueryServiceStatus && pQueryServiceStatus(hExist, &ss)) {
            for (int i = 0; i < 25 && (ss.dwCurrentState == SERVICE_STOP_PENDING ||
                                        ss.dwCurrentState == SERVICE_START_PENDING); i++) {
                Sleep(200);
                pQueryServiceStatus(hExist, &ss);
            }
        }

        if (pControlService && ss.dwCurrentState != SERVICE_STOPPED) {
            SERVICE_STATUS ss2{};
            pControlService(hExist, SERVICE_CONTROL_STOP, &ss2);
            for (int i = 0; i < 40; i++) {
                if (!pQueryServiceStatus || !pQueryServiceStatus(hExist, &ss2)) break;
                if (ss2.dwCurrentState == SERVICE_STOPPED) break;
                Sleep(100);
            }
        }
        pDeleteService(hExist);
        pCloseServiceHandle(hExist);

        // Poll for the deletion to actually finalize. SCM marks the service
        // for deletion and only frees the name once every handle is closed
        // AND its image is unmapped from the kernel. A blind Sleep(300) is
        // often enough but the drop-and-recreate path here can race on
        // slower boxes; poll up to ~2 s and any subsequent CreateService
        // ERROR_SERVICE_MARKED_FOR_DELETE is retried below.
        for (int i = 0; i < 20; i++) {
            SC_HANDLE hChk = pOpenServiceA(hSCM, svcName, SERVICE_QUERY_STATUS);
            if (!hChk) break;                       // truly gone — good
            pCloseServiceHandle(hChk);
            Sleep(100);
        }
    }

    // Create the service. Retry ERROR_SERVICE_MARKED_FOR_DELETE (1072) for
    // up to ~2 s — the delete above was polled, but a leftover kernel-side
    // image reference can keep the name blocked briefly on slower SCMs.
    SC_HANDLE hSvc = nullptr;
    DWORD     eCreate = 0;
    for (int i = 0; i < 20 && !hSvc; i++) {
        hSvc = pCreateServiceA(hSCM, svcName, svcName,
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            drvPath, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (hSvc) break;
        eCreate = pGetLastError();
        if (eCreate != 1072) break;                 // only retry marked-for-delete
        Sleep(100);
    }
    if (!hSvc) {
        const char* hint = DecodeStartErr(eCreate);
        std::cout << "[!] CreateService failed (err=" << eCreate << ")";
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
            std::cout << "    Driver blocklist or signature policy rejected RTCore64.\n"
                         "    Options:\n"
                         "      - Verify the .sys file is the WHCP-signed MSI Afterburner build\n"
                         "        and the file wasn't truncated on copy\n"
                         "      - HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
                         " → VulnerableDriverBlocklistEnable = 0, reboot\n"
                         "      - Confirm HVCI / Memory Integrity is disabled\n"
                         "        (Windows Security → Device security → Core isolation)\n";
        }
        pDeleteService(hSvc);
        // Leave the .sys file on disk so the user can diagnose (blocklist,
        // wrong version, etc.) without re-copying before each retry.
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
    // Keep the driver file on disk between runs — the machine-stable filename
    // acts as a persistent one-shot cache. Deleting it forces a re-copy of
    // RTCore64.sys before every launch. If you want strict clean-up on
    // exit for stealth, uncomment the DeleteFileA call below.
    // DeleteFileA(GetDriverPath());
}

// Enable admin-available-but-disabled-by-default privileges on the current
// process token.
//
// RTCore64's IRP_MJ_CREATE is a trivial no-op — the device's DACL
// (D:P(A;;GA;;;SY)(A;;GA;;;BA) — SYSTEM + Built-in Admins full access,
// applied at DriverEntry) is what decides who gets in. An elevated cmd
// (Admin group + UAC-elevated) clears that DACL. This helper isn't
// strictly required for RTCore64, but enabling SeDebug / SeSecurity / etc.
// is still useful for other paths (process handle open, module walks) and
// costs nothing on the happy path.
static void EnableAdminPrivileges() {
    using PFN_LoadLibraryA         = HMODULE(WINAPI*)(LPCSTR);
    using PFN_GetProcAddress       = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    using PFN_OpenProcessToken     = BOOL(WINAPI*)(HANDLE, DWORD, PHANDLE);
    using PFN_LookupPrivilegeValueA = BOOL(WINAPI*)(LPCSTR, LPCSTR, PLUID);
    using PFN_LookupPrivilegeNameA  = BOOL(WINAPI*)(LPCSTR, PLUID, LPSTR, LPDWORD);
    using PFN_AdjustTokenPrivileges = BOOL(WINAPI*)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
    using PFN_GetTokenInformation  = BOOL(WINAPI*)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
    using PFN_GetCurrentProcess    = HANDLE(WINAPI*)();
    using PFN_CloseHandle          = BOOL(WINAPI*)(HANDLE);
    using PFN_GetLastError         = DWORD(WINAPI*)();

    // Force-load advapi32 so its exports are available even when the CRT
    // hasn't touched it yet (static CRT + no direct advapi32 references).
    auto pLoadLibraryA_e = reinterpret_cast<PFN_LoadLibraryA>(
        AntiDebug::ResolveExport(AntiDebug::Fnv1a("LoadLibraryA")));
    HMODULE hAdvapi = pLoadLibraryA_e ? pLoadLibraryA_e(skCrypt("advapi32.dll")) : nullptr;

    auto pGetProcAddress_e = reinterpret_cast<PFN_GetProcAddress>(
        AntiDebug::ResolveExport(AntiDebug::Fnv1a("GetProcAddress")));

    // Two-source resolver: try GetProcAddress on advapi32 first (bypasses any
    // FNV1A collision or corrupted export-table state that AntiDebug relies
    // on), fall back to the lazy-importer-style resolver.
    auto resolve = [&](const char* name, uint32_t hash) -> void* {
        if (hAdvapi && pGetProcAddress_e) {
            if (auto p = pGetProcAddress_e(hAdvapi, name)) return (void*)p;
        }
        return (void*)AntiDebug::ResolveExport(hash);
    };

    auto pOpenProcessToken      = reinterpret_cast<PFN_OpenProcessToken>(
        resolve("OpenProcessToken",       AntiDebug::Fnv1a("OpenProcessToken")));
    auto pLookupPrivilegeValueA = reinterpret_cast<PFN_LookupPrivilegeValueA>(
        resolve("LookupPrivilegeValueA",  AntiDebug::Fnv1a("LookupPrivilegeValueA")));
    auto pLookupPrivilegeNameA  = reinterpret_cast<PFN_LookupPrivilegeNameA>(
        resolve("LookupPrivilegeNameA",   AntiDebug::Fnv1a("LookupPrivilegeNameA")));
    auto pAdjustTokenPrivileges = reinterpret_cast<PFN_AdjustTokenPrivileges>(
        resolve("AdjustTokenPrivileges",  AntiDebug::Fnv1a("AdjustTokenPrivileges")));
    auto pGetTokenInformation   = reinterpret_cast<PFN_GetTokenInformation>(
        resolve("GetTokenInformation",    AntiDebug::Fnv1a("GetTokenInformation")));
    auto pGetCurrentProcess     = reinterpret_cast<PFN_GetCurrentProcess>(
        AntiDebug::ResolveExport(AntiDebug::Fnv1a("GetCurrentProcess")));
    auto pCloseHandle           = reinterpret_cast<PFN_CloseHandle>(
        AntiDebug::ResolveExport(AntiDebug::Fnv1a("CloseHandle")));
    auto pGetLastError          = reinterpret_cast<PFN_GetLastError>(
        AntiDebug::ResolveExport(AntiDebug::Fnv1a("GetLastError")));

    if (!pOpenProcessToken || !pLookupPrivilegeValueA
        || !pAdjustTokenPrivileges || !pGetCurrentProcess || !pCloseHandle) {
        std::cout << "  \033[91m[!]\033[0m EnableAdminPrivileges: advapi32 resolver failed"
                  << " (OPT=" << (void*)pOpenProcessToken
                  << " LPV=" << (void*)pLookupPrivilegeValueA
                  << " ATP=" << (void*)pAdjustTokenPrivileges << ")\n";
        return;
    }

    HANDLE hTok = nullptr;
    if (!pOpenProcessToken(pGetCurrentProcess(),
                           TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok) || !hTok) {
        std::cout << "  \033[91m[!]\033[0m EnableAdminPrivileges: OpenProcessToken failed err="
                  << (pGetLastError ? pGetLastError() : 0) << "\n";
        return;
    }

    static const char* const kPrivs[] = {
        "SeLoadDriverPrivilege",
        "SeDebugPrivilege",
        "SeSecurityPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeSystemProfilePrivilege",
        "SeManageVolumePrivilege",
    };
    for (const char* name : kPrivs) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        if (!pLookupPrivilegeValueA(nullptr, name, &tp.Privileges[0].Luid)) {
            std::cout << "  \033[93m[!]\033[0m LookupPrivilegeValueA(" << name
                      << ") failed err=" << (pGetLastError ? pGetLastError() : 0) << "\n";
            continue;
        }
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        pAdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }

    // Re-query the token and print a summary. RTCore64's DACL gates on
    // SYSTEM+BA, not on SeLoadDriverPrivilege, but we still surface its
    // state — an err=5 on an unusual host may correlate with an unexpected
    // token shape.
    if (pGetTokenInformation) {
        DWORD needed = 0;
        pGetTokenInformation(hTok, TokenPrivileges, nullptr, 0, &needed);
        if (needed) {
            std::vector<uint8_t> buf(needed);
            if (pGetTokenInformation(hTok, TokenPrivileges, buf.data(), needed, &needed)) {
                auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
                bool loadDrvHeld = false, loadDrvEnabled = false;
                for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
                    // LUID low DWORD 10 = SeLoadDriverPrivilege
                    if (tp->Privileges[i].Luid.LowPart == 10
                        && tp->Privileges[i].Luid.HighPart == 0) {
                        loadDrvHeld = true;
                        loadDrvEnabled = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                    }
                }
                std::cout << "  \033[96m[*]\033[0m Token privileges: "
                          << tp->PrivilegeCount << " held.  SeLoadDriverPrivilege: "
                          << (loadDrvHeld ? (loadDrvEnabled ? "\033[92mENABLED\033[0m"
                                                            : "\033[93mheld but DISABLED\033[0m")
                                          : "\033[91mNOT HELD\033[0m") << "\n";
                (void)loadDrvHeld; (void)loadDrvEnabled;
            }
        }
    }
    pCloseHandle(hTok);
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

    // Enable admin-token privileges before the driver load. RTCore64's DACL
    // is what gates our access — SeDebug/SeSecurity being enabled early
    // helps downstream (process token dupe, module walks). Cheap on
    // happy path.
    EnableAdminPrivileges();

    // MSI Afterburner and RivaTuner Statistics Server hold RTCore64 open
    // for hardware polling. Their handles won't block ours (DACL allows
    // SHARE_READ|SHARE_WRITE and the driver has no arm state to race on),
    // but killing them removes any chance of their high-cadence IOCTLs
    // interleaving with our page-cache reads. MSI Center and Dragon Center
    // are kept in the kill list too — they may still touch this device via
    // helper services.
    {
        auto pCreateToolhelp32Snapshot = RESOLVE(CreateToolhelp32Snapshot);
        auto pProcess32First           = RESOLVE(Process32First);
        auto pProcess32Next            = RESOLVE(Process32Next);
        auto pOpenProcess              = RESOLVE(OpenProcess);
        auto pTerminateProcess         = RESOLVE(TerminateProcess);
        auto pCloseHandle              = RESOLVE(CloseHandle);
        if (pCreateToolhelp32Snapshot && pProcess32First && pProcess32Next
            && pOpenProcess && pTerminateProcess && pCloseHandle) {
            HANDLE snap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe = { sizeof(pe) };
                int killed = 0;
                if (pProcess32First(snap, &pe)) {
                    do {
                        const char* n = pe.szExeFile;
                        if (_stricmp(n, skCrypt("MSI Center.exe")) == 0 ||
                            _stricmp(n, skCrypt("MSICenter.exe")) == 0 ||
                            _stricmp(n, skCrypt("MSI_Central_Service.exe")) == 0 ||
                            _stricmp(n, skCrypt("Dragon Center.exe")) == 0 ||
                            _stricmp(n, skCrypt("MSIAfterburner.exe")) == 0 ||
                            _stricmp(n, skCrypt("HardwareMonitor.exe")) == 0) {
                            HANDLE hp = pOpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                            if (hp) {
                                if (pTerminateProcess(hp, 0)) killed++;
                                pCloseHandle(hp);
                            }
                        }
                    } while (pProcess32Next(snap, &pe));
                }
                pCloseHandle(snap);
                if (killed) {
                    std::cout << "  \033[96m[*]\033[0m Stopped " << killed
                              << " MSI helper process(es) holding the driver open.\n";
                    Sleep(500);   // let their handle-close IRPs drain
                }
            }
        }
    }

    // RTCore64 publishes \Device\RTCore64 at DriverEntry — the path is
    // hardcoded in the signed driver's .rdata and can't be changed without
    // breaking the signature. WinDrvReader already knows the constant; no
    // runtime path injection needed.

    // ── Payload loading (manual map via kdmapper) ─────────────────────────────
    std::cout << "  \033[96m[*]\033[0m Loading payload (manual-map)...\n";
    bool drvStarted = LaunchMapper();
    if (drvStarted) {
        std::cout << "  \033[92m[+]\033[0m Payload ready.  section=Global\\Xh7Km2p9Qr4tZ8\n\n";
    } else {
        std::cout << "  \033[91m[!]\033[0m Payload load failed.\n\n";
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
            drvReady = IsPayloadLoaded();
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
                std::cout << "\n\n  \033[91m[!]\033[0m Payload section vanished after mapper reported success.\n";
                std::cout << "      Likely causes: payload's reader thread crashed, section was unmapped by\n"
                             "      an AC scan, or a KAPC_STATE-related bugcheck happened (check the last\n"
                             "      BSOD).\n";
                std::cout << "\n\n  Press Enter to exit.\n";
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
