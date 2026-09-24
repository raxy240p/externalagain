#pragma once
#include "core/debug.hpp"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>
#include <atomic>
#include <skCrypter/skCrypter.hpp>
#include <lazy_importer/lazy_importer.hpp>
#include "core/anti_debug/AntiDebug.hpp"

// NTIOLib_X64.sys (Micro-Star INT'L CO., LTD., v3.0.0.11, WHCP-signed).
// SHA256: 2A36D9A22DFF680CE46284EF718E647BD5A8FC5F095C2ACBBEC3A7F50926EB7F
// Signer: MICRO-STAR INTERNATIONAL CO., LTD. via GlobalSign GCC R45 EV
//         CodeSigning CA 2020 (EV code-signing chain), attribute-signed
//         via Microsoft Windows Third Party Component CA 2014 →
//         Microsoft Windows Hardware Compatibility Publisher. Loads on
//         stock Windows 11 with Secure Boot.
//
// Ships with MSI Center 2.0.35.0. Older NTIOLib/MsIo64 SHA256s are on
// Microsoft's HVCI vulnerable-driver blocklist and LOLDrivers, but this
// specific 2024-01 build (SHA256 above) is OFF both lists as verified
// against the current dataset. Should HVCI enforcement flip against it,
// swap to the sibling v3.0.0.10 build shipped in the same package
// (SHA256 3BBBCD444C82E287C9E06D198580FF4B500994072F804A59B204DAAA968324E4,
// device path \Device\NTIOLib_CC_Clock).
//
// Device path: HARDCODED at DriverEntry (verified against the .rdata
// UNICODE_STRING at 0x140001af0). Publishes:
//   \Device\NTIOLib_CC_COMM
//   \DosDevices\NTIOLib_CC_COMM
// User-mode path: "\\.\NTIOLib_CC_COMM". The SERVICE name we register
// under (see GetSvcName in main.cpp — machine-stable hex) affects only
// SCM registration and the on-disk .sys filename, NOT the device path.
// The device-path IOC is mitigated by idle-mode handle closure between
// scans; the handle is open only during the tight IOCTL burst.
//
// IRP_MJ_CREATE gate (verified against CREATE dispatcher @ 0x1400010d0):
//   trivial no-op — returns STATUS_SUCCESS unconditionally. DACL comes
//   from IoCreateDevice's default (admin+SYSTEM RW; FILE_DEVICE_SECURE_OPEN
//   flag on the device object). Elevated admin passes; standard user is
//   refused by the DACL before CREATE runs.
//
// Activation gate: before any read/write IOCTL succeeds, the driver's
// arm-global must equal 0x2F405A34. The arm handler is reached ONLY by
// IOCTL 0xC350214C — it reads SystemBuffer[0..3] (METHOD_BUFFERED,
// InputLength=4) and, if the dword equals the magic, writes the magic
// into the arm-global. Any other IOCTL (including the plausible-looking
// 0xC3502000, which is a DEAD CASE that always returns STATUS_INVALID_HANDLE)
// won't arm the driver. Once armed it stays armed for the driver's lifetime.
//
// IOCTL surface (dispatch on raw IoControlCode, DeviceType 0xC350):
//   0xC3502000  DEAD — hardwired STATUS_INVALID_HANDLE, do not send
//   0xC3502004  version stub (writes small global to caller)
//   0xC3502084  MSR-family write path      (unused here)
//   0xC3502088  MSR-family read path       (unused here)
//   0xC350214C  ← ARM — sets global magic (input buf DWORD 0 = magic)
//   0xC35060C8  I/O port read byte (in al,dx)
//   0xC35060CC  I/O port read byte alt
//   0xC35060D0  I/O port read word
//   0xC35060D4  I/O port read dword
//   0xC3506104  ← READ  phys memory (MmMapIoSpace + rep movs, 64-bit PA)
//   0xC3506144  READ  phys memory (cached mapping variant)
//   0xC350A108  I/O port write             (unused here)
//   0xC350A148  ← WRITE phys memory (unused here; ESP is read-only)
//   0xC350A0D8/DC/E0  port-write byte/word/dword
//
// IOCTL 0xC3506104 primitive (verified @ 0x1400013ac, secondary handler
// invoked by the DEVICE_CONTROL dispatcher at 0x140001100):
//   METHOD_BUFFERED. InputLength == 0x10, OutputLength >= unit_size*count.
//   Input struct:
//     +0x00  uint64 phys_addr        ← full 64-bit PA
//     +0x08  uint32 unit_size        ← MUST be 1, 2, or 4
//     +0x0C  uint32 count            ← number of units
//   Driver: MmMapIoSpace(PA, unit_size*count, MmNonCached) →
//     rep movsb/w/d from mapped region → output buffer →
//     MmUnmapIoSpace → IoStatus.Information = OutputBufferLength.
//   User side: DeviceIoControl returns TRUE with lpBytesReturned = size,
//   read data lives in the output buffer as-is. Standard contract, unlike
//   Corsair's "value comes back via lpBytesReturned" trick.
//
// Trade-offs vs. Corsair we shipped before:
//   + 64-bit PA (Corsair capped at 32-bit; forced CR3 scan under 4 GB
//     and legitimately missed high-PA kernel PT pages on 32 GB systems)
//   + Bulk reads: one IOCTL can fill an entire 4 KB page or larger
//     (Corsair needed 1024 DWORD IOCTLs per page). Cuts kernel round-trips
//     by ~1000× on cold-page fills — massive perf win on the CS2 cache
//     thread.
//   + No integrity-level gate on CREATE (Corsair required IL >= HIGH;
//     NTIOLib takes any admin who passes the device DACL)
//   - Requires one-shot ARM IOCTL (0xC350214C) after Open() before reads
//     work. Handled once in Open()'s probe.
//   - Device path \Device\NTIOLib_CC_COMM is a known IOC in AC/AV static
//     scanners. Mitigation: idle-mode reopen keeps the handle out of the
//     process handle table between scans; the .sys on disk is renamed to
//     a machine-stable hex; the SCM service name is likewise stable-hex.
// IOCTL codes verified against the MSI Center 2.0.35.0 v3.0.0.11 build of
// NTIOLib_X64.sys (SHA256 2A36D9A2...). Extracted from the driver's own
// dispatch tree in .text: 0xC3502000 is a DEAD CASE that unconditionally
// returns STATUS_INVALID_HANDLE — the actual arm handler (which reads
// SystemBuffer[0..3], compares to 0x2F405A34, and writes it into the
// driver-global arm word) is reached only when IoControlCode == 0xC350214C.
// Every read IOCTL (0xC3506104 + range) checks that arm-global-magic gate
// before dispatching MmMapIoSpace, so wrong ARM = every read fails with
// err=6 (STATUS_INVALID_HANDLE) — exactly what live-fire testing showed.
#define IOCTL_NTIO_ARM                  0xC350214Cu
#define IOCTL_NTIO_READ_PHYS            0xC3506104u
#define IOCTL_NTIO_WRITE_PHYS           0xC350A148u
#define NTIO_ARM_MAGIC                  0x2F405A34u

#pragma pack(push, 1)
struct NtioReadReq {
    uint64_t phys_addr;                // IN — full 64-bit physical address
    uint32_t unit_size;                // IN — 1, 2, or 4
    uint32_t count;                    // IN — number of units to read
};
static_assert(sizeof(NtioReadReq) == 0x10, "NTIOLib read req size");
#pragma pack(pop)

// Candidate on-wire request shapes tried by ReadScan when the standard
// 16-byte NtioReadReq is rejected by this driver build. Empirical — some
// NTIOLib patch levels shipped in MSI Center bundles use a 20-byte
// prefixed shape (a leading 4-byte "channel" or "unlock cookie"), and
// legacy MsIo64-style dispatchers use a 12-byte {pa32_lo, pa32_hi, size}
// packet. If none work, Open() reports FAILED with the enumerated log
// so we can extend the shape table with the actually-required layout.
enum class NtioReadShape : uint8_t {
    STD_16   = 0,   // {u64 pa, u32 unit, u32 count}                — canonical
    PADDED_20,      // {u32 pad, u64 pa, u32 unit, u32 count}       — MSI variant
    LEGACY_12,      // {u32 pa_lo, u32 pa_hi, u32 size_bytes}       — MsIo64 style
    SIZE_16,        // {u64 pa, u64 size_bytes}                     — byte-oriented
    kCount
};

// Fills `out` with the on-wire request bytes and returns the InputBufferLength
// to send. `out` must be at least 32 bytes; unused shapes return 0.
inline size_t BuildReadRequestBytes(NtioReadShape shape, uint64_t pa, uint32_t unit,
                                    uint32_t count, uint8_t out[32]) {
    memset(out, 0, 32);
    switch (shape) {
    case NtioReadShape::STD_16:
        *(uint64_t*)(out + 0) = pa;
        *(uint32_t*)(out + 8) = unit;
        *(uint32_t*)(out + 12) = count;
        return 16;
    case NtioReadShape::PADDED_20:
        *(uint32_t*)(out + 0)  = 0;
        *(uint64_t*)(out + 4)  = pa;
        *(uint32_t*)(out + 12) = unit;
        *(uint32_t*)(out + 16) = count;
        return 20;
    case NtioReadShape::LEGACY_12:
        *(uint32_t*)(out + 0) = (uint32_t)pa;
        *(uint32_t*)(out + 4) = (uint32_t)(pa >> 32);
        *(uint32_t*)(out + 8) = unit * count;
        return 12;
    case NtioReadShape::SIZE_16:
        *(uint64_t*)(out + 0) = pa;
        *(uint64_t*)(out + 8) = (uint64_t)unit * count;
        return 16;
    default: break;
    }
    return 0;
}

// NTIOLib IOCTL 0xC3506104 return-contract summary (from disassembly):
//
//   Path                                     IoStatus.Status       Information
//   Success (any unit_size*count read)       STATUS_SUCCESS  (0)   = size
//   MmMapIoSpace fail (bad PA / refused)     STATUS_UNSUCCESSFUL   0
//                                              (0xC0000001)
//   InputBufferLength != 0x10                STATUS_INVALID_       0
//                                              PARAMETER (0xC000000D)
//   OutputBufferLength < unit_size*count     same as above         0
//   Global magic not armed (call ARM first)  STATUS_UNSUCCESSFUL   0
//   PA upper 16 bits > 0xFEDC (sanity)       STATUS_UNSUCCESSFUL   0
//
// Win32 mapping seen at DeviceIoControl (ok=FALSE, err= these):
//   0xC0000001 UNSUCCESSFUL           → err = 31   (ERROR_GEN_FAILURE)
//   0xC000000D INVALID_PARAMETER      → err = 87
//   0xC0000023 INVALID_BUFFER_SIZE    → err = 24
//   0xC0000022 ACCESS_DENIED          → err = 5    (DACL rejects; not a runtime fail)
//   Handle broken                    → err = 6
//   Kernel low resources              → err = 1450
enum class SivFail : uint8_t {
    Ok            = 0,   // read succeeded
    BadArgs       = 1,   // caller violated preconditions (size or ptr)
    HandleFailed  = 2,   // idle-mode reopen returned INVALID_HANDLE_VALUE
    IoctlDenied   = 3,   // err = 5, DACL blocks
    IoctlRejected = 4,   // err = 87 / 24 / 1, driver refused params
    HandleStale   = 5,   // err = 6, handle went bad (session race)
    Transient     = 6,   // err = 1450, retryable
    PartialReturn = 7,   // ok but returned != size (never seen — defensive)
    UnknownError  = 8,   // any other Win32 err
};

class WinDrvReader {
public:

    static WinDrvReader& Get() {
        static WinDrvReader instance;
        return instance;
    }

    // NTIOLib hardcodes its \Device\NTIOLib_CC_COMM UNICODE_STRING at
    // DriverEntry (verified against .rdata @ 0x140001af0). The user-mode
    // path is fixed and cannot be renamed without patching the signed
    // driver and breaking the WHCP signature. What we CAN control:
    //   - The SCM service name (main.cpp GetSvcName — machine-stable hex)
    //   - The on-disk .sys filename (main.cpp GetDriverPath)
    //   - Handle visibility (idle-mode reopen keeps our process handle
    //     table clean of \Device\NTIOLib_CC_COMM between IOCTL bursts)
    // SetDevicePath is kept for API compatibility but is now a no-op —
    // the device path is a constant. Callers should stop invoking it.
    void SetDevicePath(const char* /*userModePath*/) {
        // no-op — device path is hardcoded in the signed driver.
    }
    const char* GetDevicePath() const {
        return "\\\\.\\NTIOLib_CC_COMM";
    }


    bool Open() {
        if (IsOpen()) return true;
        DBG_PRINT("[ntio] Opening device...\n");

        // RAII: suppresses NtioReadOnce's handle-close-on-HandleStale for
        // the entire probe flow. Without this, the first failed READ probe
        // closes m_hDevice, and every subsequent arm-scan / read-scan
        // variant runs against INVALID_HANDLE_VALUE — the log floods with
        // err=6 uniformly (because that's what DeviceIoControl returns for
        // a bad handle) and we lose the ability to distinguish real driver
        // rejection from our own self-inflicted handle close.
        struct ProbeGuard {
            std::atomic<bool>* flag;
            ProbeGuard(std::atomic<bool>* f) : flag(f) {
                flag->store(true, std::memory_order_release);
            }
            ~ProbeGuard() { flag->store(false, std::memory_order_release); }
        } _probeGuard(&m_openProbeInProgress);
        // Try each (path, access) pair. First success wins — but we now
        // track WHICH combo won so ARM failures can escalate by re-opening
        // with a stronger access mode. Prior behavior would silently pick
        // the fallback access=0 handle on strict DACLs, then get err=6
        // from the ARM IOCTL because the I/O manager still requires
        // FILE_ANY_ACCESS handles to at least have SYNCHRONIZE for some
        // driver builds' internal validation.
        //   - GENERIC_READ|WRITE:       normal admin access
        //   - GENERIC_READ:             device with read-only DACL
        //   - SYNCHRONIZE / 0:          fallback for FILE_ANY_ACCESS IOCTLs
        //   - GLOBALROOT / global path: session-isolation fallback
        // Retries ERROR_FILE_NOT_FOUND (symlink publish race) up to 10x.
        const char* base = GetDevicePath();
        const char* pathGlobal = "\\\\.\\GLOBALROOT\\Device\\NTIOLib_CC_COMM";

        struct Attempt { const char* path; DWORD access; };
        Attempt attempts[] = {
            { base,       GENERIC_READ | GENERIC_WRITE },
            { base,       GENERIC_READ                 },
            { base,       SYNCHRONIZE                  },
            { base,       0                            },
            { pathGlobal, GENERIC_READ | GENERIC_WRITE },
            { pathGlobal, 0                            },
        };
        constexpr int kNumAttempts = (int)(sizeof(attempts) / sizeof(attempts[0]));

        // Two-pass: first pick the strongest access that opens, then try
        // ARM. If ARM fails, escalate to the next weaker access variant —
        // NTIOLib on some patch levels ONLY accepts ARM from handles that
        // opened with a specific access mode combination.
        DWORD lastErr = 0;
        int   winIdx  = -1;
        for (int attempt = 0; attempt < 10 && m_hDevice == INVALID_HANDLE_VALUE; attempt++) {
            for (int i = 0; i < kNumAttempts; i++) {
                auto& a = attempts[i];
                m_hDevice = CreateFileA(a.path,
                                        a.access,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, nullptr);
                if (m_hDevice != INVALID_HANDLE_VALUE) { winIdx = i; break; }
                lastErr = GetLastError();
            }
            if (m_hDevice != INVALID_HANDLE_VALUE) break;
            if (lastErr != 2) break;   // only retry the not-found race
            Sleep(100);
        }
        if (m_hDevice == INVALID_HANDLE_VALUE) {
            DBG_PRINT("[ntio] Failed to open device: err=%lu\n", lastErr);
            if (lastErr == 2)      DBG_PRINT("[ntio]   (device not found -- driver not loaded or bad service name)\n");
            else if (lastErr == 5) DBG_PRINT("[ntio]   (access denied -- token DACL rejects; not elevated?)\n");
            return false;
        }
        DBG_PRINT("[ntio] Device opened: handle=0x%p access=0x%08X path=%s (attempt %d/%d)\n",
                  (void*)m_hDevice, attempts[winIdx].access, attempts[winIdx].path,
                  winIdx + 1, kNumAttempts);
        printf(skCrypt("[SysMonitor] NTIOLib device open (access=0x%X variant=%d/%d)\n"),
               attempts[winIdx].access, winIdx + 1, kNumAttempts);

        // Step 1: arm the driver, with escalation on err=6.
        // If ARM fails on the first-opened handle, walk the remaining
        // (path, access) variants — each one is a fresh CreateFile that
        // could produce a handle the driver considers ARM-capable. A
        // small sleep between attempts lets a transient dispatch state
        // (still-finalizing driver init, race with an MSI Center handle)
        // clear before we retry.
        int armStart = winIdx;
        bool armed = TryArmWithRetries(m_hDevice);
        if (!armed) {
            DWORD armErr = GetLastError();
            printf(skCrypt("[SysMonitor] NTIOLib ARM failed on variant %d (err=%lu) -- escalating\n"),
                   armStart + 1, armErr);
            // Walk remaining variants, each a fresh CreateFile + ARM.
            for (int i = 0; i < kNumAttempts && !armed; i++) {
                if (i == armStart) continue;
                auto& a = attempts[i];
                CloseHandle(m_hDevice);
                m_hDevice = INVALID_HANDLE_VALUE;
                Sleep(50);   // let the driver settle between opens
                HANDLE h = CreateFileA(a.path, a.access,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       nullptr, OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h == INVALID_HANDLE_VALUE) continue;
                m_hDevice = h;
                if (TryArmWithRetries(m_hDevice)) {
                    armed = true;
                    printf(skCrypt("[SysMonitor] NTIOLib ARM succeeded on variant %d (access=0x%X)\n"),
                           i + 1, a.access);
                    break;
                }
                printf(skCrypt("[SysMonitor] NTIOLib ARM variant %d also failed (err=%lu)\n"),
                       i + 1, GetLastError());
            }
        }
        if (!armed) {
            // Last-ditch: the driver's ARM state is DRIVER-GLOBAL, so if
            // MSI Center already ARMed it in its own session, our reads
            // will succeed WITHOUT us arming again. Re-open the base
            // path with the strongest access and try a physical read
            // directly. If it works, mark armed and proceed.
            if (m_hDevice != INVALID_HANDLE_VALUE) { CloseHandle(m_hDevice); m_hDevice = INVALID_HANDLE_VALUE; }
            Sleep(50);
            m_hDevice = CreateFileA(base, GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
            if (m_hDevice != INVALID_HANDLE_VALUE) {
                // Bypass NtioArm's m_armed short-circuit gate — pretend
                // we're armed just for the probe, revert if probe fails.
                m_armed.store(true, std::memory_order_release);
                uint32_t probe = 0;
                bool probeOk = NtioReadOnce(0x1000, 4, 1, &probe, sizeof(probe));
                if (probeOk) {
                    printf(skCrypt("[SysMonitor] NTIOLib pre-ARMed by another handle (MSI Center?) -- reads work, continuing\n"));
                    armed = true;   // treat as armed for the flow below
                } else {
                    m_armed.store(false, std::memory_order_release);
                    CloseHandle(m_hDevice);
                    m_hDevice = INVALID_HANDLE_VALUE;
                }
            }
        }
        if (!armed) {
            printf(skCrypt("[SysMonitor] NTIOLib ARM failed on all %d variants + pre-armed probe. "
                           "Try: (1) net stop MSI_CentralService then relaunch, or "
                           "(2) reboot to clear driver state.\n"),
                   kNumAttempts);
            if (m_hDevice != INVALID_HANDLE_VALUE) CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
            return false;
        }

        // Diagnostic: send VERSION IOCTL (0xC3502004) — no arm-gate check
        // in that handler, so if it succeeds while READ still fails with
        // err=6, the problem is arm-global bookkeeping (not handle/dispatch).
        {
            uint32_t versionVal = 0;
            NtioVersionProbe(m_hDevice, versionVal);
        }

        // Step 2: probe the bulk read primitive at PA=0x1000 with a 4-byte
        // dword read. Exercises the full path (input validation + activation
        // gate + MmMapIoSpace succeed + rep movs into output buffer).
        uint32_t probe = 0;
        bool ok = NtioReadOnce(0x1000, 4, 1, &probe, sizeof(probe));

        // Empirical read-shape fallback. ARM succeeded (ok=1) and VERSION
        // succeeded, but the driver rejected the standard 16-byte
        // NtioReadReq at 0xC3506104 with err=6. That means this build
        // either uses a different on-wire shape for the read struct
        // (PADDED_20, LEGACY_12, SIZE_16) or dispatches read through
        // 0xC3506144 (documented as the cached-mapping variant). ReadScan
        // enumerates the {IOCTL × shape} matrix; if any combo returns
        // ok=1 with 4 bytes, latch it into m_readIoctlIdx/m_readShapeIdx
        // so the hot path uses it and continue.
        if (!ok) {
            printf(skCrypt("[SysMonitor] standard read probe failed -- running read-shape scan\n"));
            if (ReadScan(m_hDevice)) {
                probe = 0;
                ok = NtioReadOnce(0x1000, 4, 1, &probe, sizeof(probe));
            }
        }

        // Read-shape scan matched no known combo -- either the wire
        // shape is stranger than our 4 candidates OR the read IOCTL
        // number itself is elsewhere in this build's dispatch table.
        // ReadIoctlSweep casts the wide net: probes 6xxx/Axxx/2xxx/60Cx
        // ranges with the standard 16-byte req and reports any code
        // whose response distinguishes a real handler (ok=1 / err=87 /
        // err=24) from a dead case (err=6) or an unmapped entry (err=1).
        if (!ok) {
            printf(skCrypt("[SysMonitor] read-shape scan failed -- running broad IOCTL sweep\n"));
            if (ReadIoctlSweep(m_hDevice)) {
                probe = 0;
                ok = NtioReadOnce(0x1000, 4, 1, &probe, sizeof(probe));
            }
        }

        // Arm-shape fallback: the 24-candidate ARM enumeration. Only
        // meaningful when the handle survives — ProbeGuard above ensures
        // it does. ArmScan reopens the handle itself as a defense in
        // depth if something else closed it in the meantime.
        if (!ok) {
            printf(skCrypt("[SysMonitor] read-sweep failed -- running empirical arm-scan\n"));
            if (ArmScan(m_hDevice)) {
                // ArmScan validated with the canonical shape internally,
                // so reset the hot path to it.
                m_readIoctlIdx.store(0, std::memory_order_release);
                m_readShapeIdx.store(0, std::memory_order_release);
                ok = true;
                probe = 0;
                NtioReadOnce(0x1000, 4, 1, &probe, sizeof(probe));
            }
        }

        if (!ok) {
            printf(skCrypt("[SysMonitor] NTIOLib probe FAILED (err=%lu) -- driver up + armed but IOCTL 0xC3506104 blocked\n"),
                   GetLastError());
            if (m_hDevice != INVALID_HANDLE_VALUE) CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
            return false;
        }
        {
            uint32_t override_code = m_readIoctlOverride.load(std::memory_order_acquire);
            uint32_t active = override_code ? override_code
                                            : kReadIoctls[m_readIoctlIdx.load(std::memory_order_acquire) & 1];
            printf(skCrypt("[SysMonitor] NTIOLib probe OK  PA=0x1000 dword -> 0x%08X  (ioctl=0x%08X shape=%u)\n"),
                   (unsigned)probe, (unsigned)active,
                   (unsigned)m_readShapeIdx.load(std::memory_order_acquire));
        }
        return true;
    }

    void FlushDriverTable() {
    }

    // Clear the "driver is broken" circuit breaker latched by SivReadPhys
    // after kIoFailStreakBreaker consecutive IOCTL failures. Call after
    // re-loading the driver service (e.g. after RecoverDriverDevice) so
    // subsequent reads are attempted again. Also resets the streak counter
    // and per-code log budgets so a fresh incident logs from scratch.
    void ResetIoBreaker() {
        m_ioBroken.store(false, std::memory_order_release);
        m_ioFailStreak.store(0, std::memory_order_release);
        m_armed.store(false, std::memory_order_release);
        m_readIoctlOverride.store(0, std::memory_order_release);
        m_readIoctlIdx.store(0, std::memory_order_release);
        m_readShapeIdx.store(0, std::memory_order_release);
        for (auto& c : m_failLogCounts) c.store(0, std::memory_order_release);
    }

    // True if the circuit breaker has latched. Callers that want to
    // proactively fall back (or surface the state in a diagnostic UI)
    // can poll this without stat-inspecting through a failing read.
    bool IsIoBroken() const {
        return m_ioBroken.load(std::memory_order_acquire);
    }

    // Idle mode: close the device handle when not reading, reopen per-IOCTL.
    // An open \\.\ handle is visible in the calling process's handle table;
    // closing it between scans removes that detection surface.
    //
    // Race safety: acquire m_physLock across the whole transition so a
    // concurrent NtioReadOnce mid-flight either (a) captured hUse under the
    // lock BEFORE we close and still holds a valid handle for DeviceIoControl,
    // or (b) captures hUse AFTER our close-and-null and takes the reopen
    // path. No window where a caller uses a dangling handle.
    void SetIdleMode(bool enable) {
        EnterCriticalSection(&m_physLock);
        m_idleMode = enable;
        if (enable && IsOpen()) {
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
        }
        LeaveCriticalSection(&m_physLock);
    }

    void Close() {
        if (IsOpen()) {
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
        }
    }

    bool IsOpen() const {
        return m_hDevice != INVALID_HANDLE_VALUE && m_hDevice != nullptr;
    }

    bool IsIdleMode() const { return m_idleMode; }

    void ClearPhysPageCache() {
        EnterCriticalSection(&m_physLock);
        memset(m_physPageCache, 0, sizeof(m_physPageCache));
        m_physPageHead = 0;
        LeaveCriticalSection(&m_physLock);
    }

    uint64_t GetKernelBase() const { return m_kernelBase; }
    uint64_t GetSystemCr3() const { return m_systemCr3; }
    bool     IsCr3Resolved() const { return m_cr3Resolved; }

    bool ResolveSystemCr3() {
        if (m_cr3Resolved) return true;

        m_kernelBase = GetNtoskrnlVa();
        if (!m_kernelBase) {
            printf(skCrypt("[SysMonitor] GetNtoskrnlVa failed\n"));
            return false;
        }
        printf(skCrypt("[SysMonitor] ntoskrnl VA: 0x%llX\n"), (unsigned long long)m_kernelBase);

        printf(skCrypt("[SysMonitor] CR3 scan starting (0-256MB)...\n"));
        uint64_t kernPA = 0;
        m_systemCr3 = BruteForceCr3(m_kernelBase, &kernPA);
        if (!m_systemCr3) {
            printf(skCrypt("[SysMonitor] CR3 scan failed — not found in 256MB\n"));
            return false;
        }

        m_kernelPA = kernPA;
        m_cr3Resolved = true;
        printf(skCrypt("[SysMonitor] system CR3: 0x%llX  kernelPA: 0x%llX\n"),
               (unsigned long long)m_systemCr3, (unsigned long long)kernPA);
        return true;
    }

    uint64_t GetProcessCr3(uint32_t pid) {
        if (!m_cr3Resolved) return 0;

        printf(skCrypt("[SysMonitor] finding PsInitialSystemProcess...\n"));
        uint64_t systemEprocess = FindPsInitialSystemProcess();
        if (!systemEprocess) {
            printf(skCrypt("[SysMonitor] PsInitialSystemProcess not found\n"));
            return 0;
        }
        m_systemEprocessVA = systemEprocess;
        printf(skCrypt("[SysMonitor] SystemEPROCESS: 0x%llX\n"), (unsigned long long)systemEprocess);

        printf(skCrypt("[SysMonitor] walking EPROCESS list for PID %u...\n"), (unsigned)pid);
        uint64_t targetEprocess = FindEprocessByPid(pid, systemEprocess);
        if (!targetEprocess) {
            printf(skCrypt("[SysMonitor] CS2 EPROCESS not found\n"));
            return 0;
        }
        printf(skCrypt("[SysMonitor] CS2 EPROCESS: 0x%llX\n"), (unsigned long long)targetEprocess);

        uint64_t cr3 = 0;
        if (!ReadKernelVA(targetEprocess + 0x28, &cr3, 8)) {
            printf(skCrypt("[SysMonitor] failed to read DirectoryTableBase\n"));
            return 0;
        }
        cr3 &= ~0xFFFULL;
        m_cs2EprocessVA = targetEprocess;
        printf(skCrypt("[SysMonitor] DirectoryTableBase CR3: 0x%llX\n"), (unsigned long long)cr3);

        // Prefer UserDirectoryTableBase (KPTI shadow CR3) when valid.
        {
            uint64_t userCr3 = 0;
            uint32_t udtbOff = Layout().UserDirectoryTableBase;
            if (ReadKernelVA(targetEprocess + udtbOff, &userCr3, 8) && userCr3) {
                userCr3 &= ~0xFFFULL;
                const uint64_t kMinCr3 = 0x100000ULL;
                if (userCr3 >= kMinCr3) {
                    uint64_t kernPml4Idx = (m_kernelBase >> 39) & 0x1FF;
                    uint64_t sysPml4e    = ReadPhys64(m_systemCr3 + kernPml4Idx * 8);
                    uint64_t candPml4e   = ReadPhys64(userCr3     + kernPml4Idx * 8);
                    bool pml4match = (sysPml4e & 1) && (candPml4e & 1) &&
                        ((sysPml4e & 0xFFFFFFFFFF000ULL) == (candPml4e & 0xFFFFFFFFFF000ULL));
                    if (pml4match) {
                        cr3 = userCr3;
                        printf(skCrypt("[SysMonitor] using KPTI shadow CR3: 0x%llX\n"), (unsigned long long)cr3);
                    } else {
                        printf(skCrypt("[SysMonitor] UDTB present but PML4 mismatch, using DTB\n"));
                    }
                }
            }
        }

        return cr3;
    }

    uint64_t GetCs2EprocessVA() const { return m_cs2EprocessVA; }

    // Non-mutating CR3 lookup — does not overwrite m_cs2EprocessVA.
    // Requires ResolveSystemCr3() + GetProcessCr3(cs2Pid) to have run first.
    uint64_t GetCr3ForProcess(uint32_t pid) {
        if (!m_cr3Resolved || !m_systemEprocessVA) return 0;
        uint64_t eprocess = FindEprocessByPid(pid, m_systemEprocessVA);
        if (!eprocess) return 0;
        uint64_t cr3 = 0;
        if (!ReadKernelVA(eprocess + 0x28, &cr3, 8)) return 0;
        return cr3 & ~0xFFFULL;
    }

    // Walk CS2's PEB via physical memory only — no NtQueryInformationProcess,
    // no NtQueryVirtualMemory, no ReadProcessMemory.
    //
    // Layout used (x64 Win11 26200):
    //   EPROCESS  +0x550 → Peb (user-mode VA)
    //   PEB       +0x18  → Ldr (_PEB_LDR_DATA*)
    //   Ldr       +0x20  → InMemoryOrderModuleList.Flink
    //   Entry           (flink – 0x10 = _LDR_DATA_TABLE_ENTRY base)
    //   Entry     +0x30  → DllBase
    //   Entry     +0x40  → SizeOfImage
    //   Entry     +0x48  → FullDllName.Length  (+0x50 Buffer)
    uint64_t FindModuleBasePhysical(uint64_t cs2Cr3, const wchar_t* moduleName,

        uint32_t* outSize = nullptr) {
        if (outSize) *outSize = 0;
        if (!m_cs2EprocessVA || !cs2Cr3) {
            DBG_PRINT("[PEB] m_cs2EprocessVA or cs2Cr3 is 0\n");
            return 0;
        }

        // 1. Read PEB
        uint64_t pebVA = 0;
        if (!ReadKernelVA(m_cs2EprocessVA + Layout().Peb, &pebVA, 8) || !pebVA) {
            DBG_PRINT("[PEB] Could not read EPROCESS.Peb\n");
            return 0;
        }
        DBG_PRINT("[PEB] Peb VA = 0x%llX\n", pebVA);

        // 2. Read Ldr (PEB.Ldr = +0x18)
        uint64_t ldrVA = 0;
        if (!ReadVirtual(cs2Cr3, pebVA + 0x18, &ldrVA, 8) || !ldrVA) {
            DBG_PRINT("[PEB] Could not read PEB.Ldr\n");
            return 0;
        }
        DBG_PRINT("[PEB] Ldr VA = 0x%llX\n", ldrVA);

        // 3. Walk InMemoryOrderModuleList (PEB_LDR_DATA.InMemoryOrderModuleList = +0x20)
        uint64_t listHead = ldrVA + 0x20;
        uint64_t flink = 0;
        if (!ReadVirtual(cs2Cr3, listHead, &flink, 8) || !flink || flink == listHead) {
            DBG_PRINT("[PEB] Could not read InMemoryOrderModuleList\n");
            return 0;
        }
        DBG_PRINT("[PEB] Flink = 0x%llX, ListHead = 0x%llX\n", flink, listHead);

        int count = 0;

        for (int i = 0; i < 512 && flink && flink != listHead; i++) {
            count++;
            // InMemoryOrderLinks is at +0x10 in _LDR_DATA_TABLE_ENTRY (x64)
            // entry base = flink - 0x10
            uint64_t entry = flink - 0x10;

            // DllBase at entry+0x30 (Ptr64)
            uint64_t dllBase = 0;
            if (!ReadVirtual(cs2Cr3, entry + 0x30, &dllBase, 8) || !dllBase) {
                if (!ReadVirtual(cs2Cr3, flink, &flink, 8)) break;
                continue;
            }

            // FullDllName (UNICODE_STRING): Length at entry+0x48, Buffer at entry+0x50
            uint16_t nameLen = 0;
            if (!ReadVirtual(cs2Cr3, entry + 0x48, &nameLen, 2) || !nameLen || nameLen > 512) {
                if (!ReadVirtual(cs2Cr3, flink, &flink, 8)) break;
                continue;
            }

            uint64_t nameBuf = 0;
            if (!ReadVirtual(cs2Cr3, entry + 0x50, &nameBuf, 8) || !nameBuf) {
                if (!ReadVirtual(cs2Cr3, flink, &flink, 8)) break;
                continue;
            }

            wchar_t wname[257] = {};
            uint16_t rlen = (nameLen < (uint16_t)(sizeof(wname) - 2)) ? nameLen : (uint16_t)(sizeof(wname) - 2);
            if (ReadVirtual(cs2Cr3, nameBuf, wname, rlen)) {
                if (count <= 9)
                    DBG_PRINT("[PEB] Module %d: %ls (Base: 0x%llX)\n", count, wname, dllBase);

                if (_wcsicmp(wname, moduleName) == 0) {
                    DBG_PRINT("[PEB] Found %ls at 0x%llX\n", moduleName, dllBase);
                    if (outSize) {
                        uint32_t sz = 0;
                        ReadVirtual(cs2Cr3, entry + 0x40, &sz, 4);
                        *outSize = sz;
                    }
                    return dllBase;
                }
            }

            if (!ReadVirtual(cs2Cr3, flink, &flink, 8)) break;
        }

        DBG_PRINT("[PEB] Scanned %d modules, did not find %ls\n", count, moduleName);
        return 0;
    }

    // Walk CS2's VAD tree physically and check every mapped region for a PE header
    // whose export-directory name matches the target.
    //
    // CS2 loads game DLLs (client.dll, engine2.dll) via a custom tier0 loader that
    // bypasses the Windows LDR, so they never appear in the PEB module list.
    // But every mapped region has a VAD node, and image sections start with an MZ header.
    //
    // _MMVAD structure offsets for Win11 24H2 / Build 26200:
    //   _RTL_BALANCED_NODE (embedded at +0x000):
    //     +0x000 Left  child ptr
    //     +0x008 Right child ptr
    //     +0x010 ParentValue / balance flags   ← NOT StartingVpn
    //   _MMVAD_SHORT:
    //     +0x018 StartingVpn (ULONG, low 32 bits of VPN)
    //     +0x01C EndingVpn   (ULONG)
    //     +0x020 StartingVpnHigh (UCHAR, bits [51:44] of VPN)
    //     +0x021 EndingVpnHigh   (UCHAR)
    //
    // EPROCESS.VadRoot — offset varies by Windows build, resolved at runtime.
    uint64_t FindModuleViaVAD(uint64_t cs2Cr3, uint64_t eprocess,
                               const wchar_t* targetName, uint32_t* outSize = nullptr,
                               uint64_t* outLargeCand = nullptr,
                               uint32_t* outLargeCandSize = nullptr) {
        uint64_t vadRootNode = 0;
        if (!ReadKernelVA(eprocess + Layout().VadRoot, &vadRootNode, 8)
            || !vadRootNode || vadRootNode < 0xFFFF000000000000ULL) {
            DBG_PRINT("[VAD] Could not read VadRoot from EPROCESS+VadRoot\n");
            return 0;
        }
        DBG_PRINT("[VAD] VadRoot = 0x%llX\n", (unsigned long long)vadRootNode);

        // Convert module name for export-directory comparison
        char targetChar[128] = {};
        WideCharToMultiByte(CP_ACP, 0, targetName, -1, targetChar, (int)sizeof(targetChar) - 1,
                            nullptr, nullptr);

        std::vector<uint64_t> stack;
        stack.reserve(4096);
        stack.push_back(vadRootNode);

        int checked = 0, peFound = 0;
        const int kMaxNodes = 10000;

        // FaceIT may zero PE headers or unlink VAD nodes for client.dll / engine2.dll.
        // Track the largest unidentified region in the CS2 VA range as a fallback candidate.
        uint64_t largeCandVA   = 0;  uint64_t largeCandSize = 0;

        while (!stack.empty() && checked < kMaxNodes) {
            uint64_t node = stack.back();
            stack.pop_back();
            if (!node || node < 0xFFFF000000000000ULL) continue;
            checked++;

            // Batch-read all needed VAD node fields (0x22 bytes) in one kernel VA access:
            // +0x00 Left, +0x08 Right, +0x18 StartingVpn(ULONG), +0x1C EndingVpn(ULONG),
            // +0x20 StartingVpnHigh(UCHAR), +0x21 EndingVpnHigh(UCHAR)
            uint8_t nb[0x22] = {};
            if (!ReadKernelVA(node, nb, sizeof(nb))) continue;

            uint64_t left  = *(uint64_t*)(nb + 0x00);
            uint64_t right = *(uint64_t*)(nb + 0x08);
            if (left  && left  > 0xFFFF000000000000ULL) stack.push_back(left);
            if (right && right > 0xFFFF000000000000ULL) stack.push_back(right);

            uint32_t startVpn32 = *(uint32_t*)(nb + 0x18);
            uint32_t endVpn32   = *(uint32_t*)(nb + 0x1C);
            uint8_t  startHigh  =  nb[0x20];
            uint8_t  endHigh    =  nb[0x21];

            uint64_t startVA  = ((uint64_t)startHigh << 44) | ((uint64_t)startVpn32 << 12);
            uint64_t endVA    = ((uint64_t)endHigh   << 44) | ((uint64_t)endVpn32   << 12) | 0xFFF;
            uint64_t regionSz = (endVA > startVA) ? (endVA - startVA + 1) : 0;

            // Only check user-mode addresses at 64KB alignment (PE image sections)
            if (startVA == 0 || startVA >= 0x0000800000000000ULL) continue;
            if (startVA & 0xFFFFULL) continue;

            // Check for MZ signature
            uint16_t magic = 0;
            if (!ReadVirtual(cs2Cr3, startVA, &magic, 2) || magic != 0x5A4D) {
                // Track large unidentified CS2-range regions as fallback candidates.
                // FaceIT may zero client.dll's MZ header while keeping the VAD node.
                if (startVA >= 0x7FF600000000ULL && startVA < 0x7FFE00000000ULL) {
                    if (regionSz > largeCandSize) {
                        largeCandVA   = startVA;
                        largeCandSize = regionSz;
                    }
                }
                continue;
            }

            // Validate PE signature
            uint32_t peOff = 0;
            if (!ReadVirtual(cs2Cr3, startVA + 0x3C, &peOff, 4)
                || peOff == 0 || peOff > 0x1000) continue;

            uint32_t peSig = 0;
            if (!ReadVirtual(cs2Cr3, startVA + peOff, &peSig, 4)
                || peSig != 0x00004550) continue;

            // Must be PE32+ (64-bit)
            uint16_t optMagic = 0;
            if (!ReadVirtual(cs2Cr3, startVA + peOff + 24, &optMagic, 2)
                || optMagic != 0x20B) continue;

            peFound++;

            // Export directory RVA is at optional-header+0x70
            // (optional header starts at peOff+4+20 = peOff+24)
            uint32_t exportRVA = 0;
            if (!ReadVirtual(cs2Cr3, startVA + peOff + 24 + 0x70, &exportRVA, 4)
                || !exportRVA || exportRVA > 0x10000000) continue;

            // Export directory Name field at +0x0C
            uint32_t nameRVA = 0;
            if (!ReadVirtual(cs2Cr3, startVA + exportRVA + 0x0C, &nameRVA, 4)
                || !nameRVA || nameRVA > 0x10000000) continue;

            char exportName[128] = {};
            if (!ReadVirtual(cs2Cr3, startVA + nameRVA, exportName,
                             (int)sizeof(exportName) - 1)) continue;
            exportName[127] = '\0';

            DBG_PRINT("[VAD] PE #%d at 0x%llX: %s\n",
                   peFound, (unsigned long long)startVA, exportName);

            if (_stricmp(exportName, targetChar) == 0) {
                DBG_PRINT("[VAD] Found %s at 0x%llX (node #%d)\n",
                       targetChar, (unsigned long long)startVA, checked);
                if (outSize) {
                    uint32_t sizeOfImage = 0;
                    // SizeOfImage at optional-header+0x38 = peOff+24+0x38 = peOff+0x50
                    if (ReadVirtual(cs2Cr3, startVA + peOff + 0x50, &sizeOfImage, 4))
                        *outSize = sizeOfImage;
                }
                return startVA;
            }
        }

        DBG_PRINT("[VAD] Scanned %d nodes (%d PEs checked), did not find %s\n",
               checked, peFound, targetChar);

        // Save large-candidate for caller — PT scan runs first.
        if (largeCandVA && outLargeCand) {
            DBG_PRINT("[VAD] Large-candidate:  0x%llX (~%uMB), deferring (PT scan runs first)\n",
                   (unsigned long long)largeCandVA, (uint32_t)(largeCandSize >> 20));
            *outLargeCand = largeCandVA;
            if (outLargeCandSize) *outLargeCandSize = (uint32_t)largeCandSize;
        }
        return 0;
    }
    // FindModuleViaBulkPTScan: walks PML4→PDPT→PD→PT using bulk 4KB PhysReads
    // (one read per table level) to scan the CS2 DLL VA range for a named PE.
    // Completely bypasses the VAD tree — used when FaceIT unlinks client.dll's
    // VAD node in competitive mode. Typical cost: ~80–150 ms one-time init.
    uint64_t FindModuleViaBulkPTScan(uint64_t cr3, const wchar_t* targetName,
                                     uint32_t* outSize) {
        char targetChar[128] = {};
        WideCharToMultiByte(CP_ACP, 0, targetName, -1, targetChar,
                            (int)sizeof(targetChar) - 1, nullptr, nullptr);
        DBG_PRINT("[Scan] Bulk PT scan for %s...\n", targetChar);

        // CS2 game DLLs can load anywhere in 0x7FF6_0000_0000 – 0x7FFE_0000_0000.
        // Address varies by session: 0x7FF9... in competitive, 0x7FFB... in casual.
        // All share PML4[0xFF]; only the PDPT range (indices ~0x1D8–0x1F7) changes.
        const uint64_t VA_LO   = 0x7FF600000000ULL;
        const uint64_t VA_HI   = 0x7FFE00000000ULL;
        const int      pml4Idx = (int)((VA_LO >> 39) & 0x1FF); // 0xFF

        // Step 1: read the relevant PML4 entry
        uint64_t pml4e = ReadPhys64(cr3 + (uint64_t)pml4Idx * 8);
        if (!(pml4e & 1)) { DBG_PRINT("[Scan] PML4[%d] not present\n", pml4Idx); return 0; }
        uint64_t pdptPA = pml4e & 0xFFFFFFFFFF000ULL;
        if (!IsSafeToMap(pdptPA)) return 0;

        // Step 2: entire PDPT page (4 KB = 512 × 8-byte entries)
        std::vector<uint64_t> pdpt(512, 0ULL);
        if (!PhysRead(pdptPA, pdpt.data(), 4096)) return 0;

        int pdptLo = (int)((VA_LO        >> 30) & 0x1FF);
        int pdptHi = (int)(((VA_HI - 1)  >> 30) & 0x1FF);

        for (int pdptIdx = pdptLo; pdptIdx <= pdptHi; pdptIdx++) {
            uint64_t pdpte = pdpt[(size_t)pdptIdx];
            if (!(pdpte & 1) || (pdpte & 0x80)) continue; // absent or 1 GB page

            uint64_t pdPA = pdpte & 0xFFFFFFFFFF000ULL;
            if (!IsSafeToMap(pdPA)) continue;

            // Base VA covered by this PDPT entry
            uint64_t pdptBaseVA = ((uint64_t)pml4Idx << 39) | ((uint64_t)pdptIdx << 30);

            // Step 3: entire PD page (512 × 2 MB entries)
            std::vector<uint64_t> pd(512, 0ULL);
            if (!PhysRead(pdPA, pd.data(), 4096)) continue;

            for (int pdIdx = 0; pdIdx < 512; pdIdx++) {
                uint64_t pde = pd[(size_t)pdIdx];
                if (!(pde & 1) || (pde & 0x80)) continue; // absent or 2 MB large page

                uint64_t regionVA = pdptBaseVA | ((uint64_t)pdIdx << 21);
                if (regionVA < VA_LO || regionVA >= VA_HI) continue;

                uint64_t ptPA = pde & 0xFFFFFFFFFF000ULL;
                if (!IsSafeToMap(ptPA)) continue;

                // Step 4: entire PT page (512 × 4 KB entries)
                std::vector<uint64_t> pt(512, 0ULL);
                if (!PhysRead(ptPA, pt.data(), 4096)) continue;

                // Step 5: check every 16th PTE (64 KB = DLL load alignment)
                for (int ptIdx = 0; ptIdx < 512; ptIdx += 16) {
                    uint64_t pte = pt[(size_t)ptIdx];
                    if (!(pte & 1)) continue;

                    uint64_t pagePA = pte & 0xFFFFFFFFFF000ULL;
                    if (!IsSafeToMap(pagePA)) continue;

                    uint64_t pageVA = regionVA | ((uint64_t)ptIdx << 12);

                    // Quick MZ check via physical address
                    uint16_t mz = 0;
                    if (!PhysRead(pagePA, &mz, 2) || mz != 0x5A4D) continue;

                    // e_lfanew
                    uint32_t peOff = 0;
                    if (!PhysRead(pagePA + 0x3C, &peOff, 4)
                        || peOff == 0 || peOff > 0x1000) continue;

                    // PE signature
                    uint32_t peSig = 0;
                    if (!PhysRead(pagePA + peOff, &peSig, 4)
                        || peSig != 0x00004550) continue;

                    // 64-bit PE (IMAGE_OPTIONAL_HEADER64.Magic = 0x20B)
                    uint16_t optMagic = 0;
                    if (!PhysRead(pagePA + peOff + 24, &optMagic, 2)
                        || optMagic != 0x20B) continue;

                    // Export directory — may cross pages so use virtual reads
                    uint32_t exportRVA = 0;
                    if (!ReadVirtual(cr3, pageVA + peOff + 24 + 0x70, &exportRVA, 4)
                        || !exportRVA || exportRVA > 0x10000000) continue;

                    uint32_t nameRVA = 0;
                    if (!ReadVirtual(cr3, pageVA + exportRVA + 0x0C, &nameRVA, 4)
                        || !nameRVA || nameRVA > 0x10000000) continue;

                    char expName[128] = {};
                    if (!ReadVirtual(cr3, pageVA + nameRVA, expName,
                                     (int)sizeof(expName) - 1)) continue;
                    expName[127] = '\0';

                    DBG_PRINT("[Scan] Found PE at 0x%llX: %s\n",
                           (unsigned long long)pageVA, expName);

                    if (_stricmp(expName, targetChar) == 0) {
                        DBG_PRINT("[Scan] Matched %s at 0x%llX via bulk PT scan!\n",
                               targetChar, (unsigned long long)pageVA);
                        if (outSize) {
                            uint32_t sz = 0;
                            ReadVirtual(cr3, pageVA + peOff + 0x50, &sz, 4);
                            *outSize = sz;
                        }
                        return pageVA;
                    }
                }
            }
        }

        DBG_PRINT("[Scan] Bulk PT scan: %s not found\n", targetChar);
        return 0;
    }

    uint64_t GetModuleBasePhysical(uint64_t cr3, const wchar_t* moduleName, uint32_t* outSize) {
        uint64_t result = 0;

        // Layer 1: PEB walk (fast, works for normal modules)
        result = FindModuleBasePhysical(cr3, moduleName, outSize);
        if (result) {
            printf(skCrypt("[SysMonitor] %ls found via PEB at 0x%llX\n"), moduleName, (unsigned long long)result);
            return result;
        }
        printf(skCrypt("[SysMonitor] %ls not in PEB, trying VAD...\n"), moduleName);

        // Layer 2: VAD walk (FaceIT hides modules here)
        uint64_t largeCand = 0;
        uint32_t largeCandSz = 0;
        result = FindModuleViaVAD(cr3, m_cs2EprocessVA, moduleName, outSize, &largeCand, &largeCandSz);
        if (result) {
            printf(skCrypt("[SysMonitor] %ls found via VAD at 0x%llX\n"), moduleName, (unsigned long long)result);
            return result;
        }
        printf(skCrypt("[SysMonitor] %ls not in VAD, trying PT scan...\n"), moduleName);

        // Layer 3: Bulk PT scan (FaceIT-proof — scans physical memory for PE headers)
        result = FindModuleViaBulkPTScan(cr3, moduleName, outSize);
        if (result) {
            printf(skCrypt("[SysMonitor] %ls found via PT scan at 0x%llX\n"), moduleName, (unsigned long long)result);
            return result;
        }
        printf(skCrypt("[SysMonitor] %ls not found via PT scan\n"), moduleName);

        // Layer 4: Large candidate fallback (last resort)
        if (largeCand) {
            printf(skCrypt("[SysMonitor] %ls using large-candidate fallback: 0x%llX (~%uMB)\n"),
                moduleName, (unsigned long long)largeCand, largeCandSz >> 20);
            if (outSize && !*outSize) *outSize = largeCandSz;
            return largeCand;
        }

        printf(skCrypt("[SysMonitor] %ls: all 4 layers failed\n"), moduleName);
        return 0;
    }
    // ReadVirtual with a caller-supplied VA→PA page cache.
    // First call for a VA page: does the 4-level walk (12 IOCTLs) and inserts into cache.
    // Subsequent calls for the same page: skips the walk (3 IOCTLs for PhysRead only).
    // cache[i].first = page-aligned VA, cache[i].second = physical page base.
    bool ReadVirtualCached(uint64_t cr3, uint64_t va, void* buffer, size_t size,
                           std::vector<std::pair<uint64_t,uint64_t>>& cache) {
        if (!cr3 || !size) return false;
        uint8_t* dst = (uint8_t*)buffer;
        size_t done = 0;
        while (done < size) {
            uint64_t pageBase = va & ~0xFFFULL;
            uint64_t offset   = va - pageBase;
            size_t   chunk    = (std::min)(size - done, (size_t)(0x1000 - offset));

            uint64_t pa = 0;
            for (auto& e : cache)
                if (e.first == pageBase) { pa = e.second; break; }
            if (!pa) {
                pa = VirtualToPhysical(cr3, pageBase);
                if (!pa) return false;
                cache.push_back({ pageBase, pa });
            }

            if (!PhysRead(pa + offset, dst + done, chunk)) return false;
            done += chunk;
            va = pageBase + 0x1000;
        }
        return true;
    }

    uint64_t VirtualToPhysical(uint64_t cr3, uint64_t va) {
        if (!IsSafeToMap(cr3)) return 0;

        // PML4 index
        uint64_t pml4e = ReadPhys64(cr3 + ((va >> 39) & 0x1FF) * 8);
        if (!(pml4e & 1)) return 0;
        uint64_t pdptPA = pml4e & 0xFFFFFFFFFF000ULL;
        if (!IsSafeToMap(pdptPA)) return 0;

        // PDPT index
        uint64_t pdpte = ReadPhys64(pdptPA + ((va >> 30) & 0x1FF) * 8);
        if (!(pdpte & 1)) return 0;
        if (pdpte & 0x80) { // 1GB page
            uint64_t pa = (pdpte & 0xFFFFFC0000000000ULL) | (va & 0x3FFFFFFFULL);
            return IsSafeToMap(pa) ? pa : 0;
        }
        uint64_t pdPA = pdpte & 0xFFFFFFFFFF000ULL;
        if (!IsSafeToMap(pdPA)) return 0;

        // PD index
        uint64_t pde = ReadPhys64(pdPA + ((va >> 21) & 0x1FF) * 8);
        if (!(pde & 1)) return 0;
        if (pde & 0x80) { // 2MB page
            uint64_t pa = (pde & 0xFFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
            return IsSafeToMap(pa) ? pa : 0;
        }
        uint64_t ptPA = pde & 0xFFFFFFFFFF000ULL;
        if (!IsSafeToMap(ptPA)) return 0;

        // PT index
        uint64_t pte = ReadPhys64(ptPA + ((va >> 12) & 0x1FF) * 8);
        if (!(pte & 1)) return 0;

        uint64_t pa = (pte & 0xFFFFFFFFFF000ULL) | (va & 0xFFFULL);
        return IsSafeToMap(pa) ? pa : 0;
    }

    bool ReadVirtual(uint64_t cr3, uint64_t va, void* buffer, size_t size) {
        if (!cr3 || !size) return false;

        uint8_t* dst = (uint8_t*)buffer;
        size_t done = 0;

        while (done < size) {
            uint64_t pageBase = va & ~0xFFFULL;
            uint64_t offset = va - pageBase;
            size_t chunk = (std::min)(size - done, (size_t)(0x1000 - offset));

            uint64_t pa = VirtualToPhysical(cr3, pageBase);
            if (!pa) return false;

            uint64_t readAddr = pa + offset;
            if (!PhysRead(readAddr, dst + done, chunk))
                return false;

            done += chunk;
            va = pageBase + 0x1000;
        }

        return true;
    }

    // Direct physical read — bypasses the page cache.
    // Under NTIOLib, SivReadPhys already picks the best unit_size/count
    // tuple internally, so this is a straight forward. Kept as a separate
    // entry point so PhysRead()'s small-read path can bypass the LRU slot
    // fill without special-casing the caller.
    bool ReadPhysDirect(uint64_t physAddr, void* buffer, size_t size) {
        return SivReadPhys(physAddr, buffer, size);
    }

    bool PhysRead(uint64_t physAddr, void* buffer, size_t size) {
        if (!size) return true;
        // Hard guard: reject any PA that could bugcheck the driver.
        if (!IsSafeToMap(physAddr) || !IsSafeToMap(physAddr + size - 1))
            return false;

        // Threshold: total requests ≤ this skip the page-cache slot fill and
        // just issue one IOCTL for the exact bytes needed. Under SIV, both
        // paths cost one IOCTL — the threshold is about page-cache economics,
        // not IOCTL count: 4 KB of RAM per slot is only worth spending on
        // pages likely to be re-read (repeated pointer chain walks, entity
        // struct re-touches, view-matrix reads). One-off small reads (single
        // fields, header probes) shouldn't evict a hot page slot for a
        // page that'll never be read again. 256 B stays a good middle.
        constexpr size_t kFastPathBytes = 256;

        uint8_t* dst = (uint8_t*)buffer;
        size_t done = 0;
        while (done < size) {
            uint64_t pagePA = (physAddr + done) & ~0xFFFULL;
            uint64_t offset = (physAddr + done) - pagePA;
            size_t   chunk  = (std::min)(size - done, (size_t)(0x1000 - offset));
            if (!IsSafeToMap(pagePA)) return false;

            // Cache probe first — a hit is a memcpy regardless of size.
            EnterCriticalSection(&m_physLock);
            bool hit = false;
            for (int i = 0; i < kPhysPageCacheN; i++) {
                if (m_physPageCache[i].pa == pagePA && pagePA != 0) {
                    memcpy(dst + done, m_physPageCache[i].data + offset, chunk);
                    hit = true;
                    break;
                }
            }
            LeaveCriticalSection(&m_physLock);

            if (!hit) {
                if (size <= kFastPathBytes) {
                    // Small read: one IOCTL for exactly `chunk` bytes.
                    // The page isn't slotted in the LRU afterwards — a
                    // one-off small read shouldn't evict a hot page.
                    if (!ReadPhysDirect(physAddr + done, dst + done, chunk))
                        return false;
                } else {
                    // Larger read: fill the whole page into cache. Subsequent
                    // reads of the same page (e.g. every frame) then hit
                    // the cache and skip IOCTLs entirely.
                    uint8_t page[4096];
                    if (!NalReadPage(pagePA, page)) return false;
                    EnterCriticalSection(&m_physLock);
                    int slot = m_physPageHead;
                    m_physPageHead = (m_physPageHead + 1) % kPhysPageCacheN;
                    m_physPageCache[slot].pa = pagePA;
                    memcpy(m_physPageCache[slot].data, page, 4096);
                    LeaveCriticalSection(&m_physLock);
                    memcpy(dst + done, page + offset, chunk);
                }
            }

            done += chunk;
        }
        return true;
    }

private:
    WinDrvReader() : m_hDevice(INVALID_HANDLE_VALUE), m_physPageHead(0) {
        InitializeCriticalSection(&m_physLock);
        InitializeCriticalSection(&m_ioctlLock);
        memset(m_physPageCache, 0, sizeof(m_physPageCache));
    }
    WinDrvReader(const WinDrvReader&) = delete;
    WinDrvReader& operator=(const WinDrvReader&) = delete;

    // Classify a DeviceIoControl failure into a SivFail code from the Win32
    // error and byte count. Keeps the retry decision and the log tagging
    // out of the hot happy path.
    static SivFail ClassifySivFail(BOOL ok, DWORD returned, DWORD requestedSize) {
        if (ok != FALSE) {
            if (returned == requestedSize) return SivFail::Ok;
            return SivFail::PartialReturn;
        }
        DWORD err = GetLastError();
        switch (err) {
            case 5:                              return SivFail::IoctlDenied;
            case 6:                              return SivFail::HandleStale;
            case 1:
            case 24:
            case 87:                             return SivFail::IoctlRejected;
            case 1450:                           return SivFail::Transient;
            default:                             return SivFail::UnknownError;
        }
    }

    // Only pipe-death signals count toward the circuit breaker — i.e. failures
    // where "the driver connection itself is broken" is a strictly better
    // hypothesis than "this particular PA is unmappable". A stale handle,
    // a refused reopen, or an access denial appearing mid-session means the
    // whole path is gone (anti-cheat teardown, unload, DACL change). Per-PA
    // rejections do NOT count — BruteForceCr3 and BulkPTScan legitimately hit
    // dozens or hundreds of driver-refused PAs during scanning; letting those
    // trip the breaker would masquerade "healthy driver, some reserved-memory
    // PAs" as "driver dead" and false-negative Engine::Init at CR3 resolution.
    static bool IsPipeDeath(SivFail cls) {
        return cls == SivFail::HandleStale
            || cls == SivFail::HandleFailed
            || cls == SivFail::IoctlDenied;
    }

    static const char* SivFailName(SivFail f) {
        switch (f) {
            case SivFail::Ok:            return "ok";
            case SivFail::BadArgs:       return "bad-args";
            case SivFail::HandleFailed:  return "handle-failed";
            case SivFail::IoctlDenied:   return "denied(err5)";
            case SivFail::IoctlRejected: return "rejected(err1/24/87)";
            case SivFail::HandleStale:   return "handle-stale(err6)";
            case SivFail::Transient:     return "transient(err1450)";
            case SivFail::PartialReturn: return "partial-return";
            case SivFail::UnknownError:  return "unknown";
        }
        return "?";
    }

    // Rate-limited failure logger. Each SivFail code prints at most
    // kIoFailLogCap times per run — a persistent problem stays visible in
    // the console without turning into a scroll of spam. The message
    // carries every bit the operator actually needs to root-cause: which
    // PA / size we asked for, which class of failure the driver returned,
    // and the raw Win32 err so it can be cross-referenced against MSDN.
    void NoteSivFail(SivFail cls, uint64_t pa, DWORD size, DWORD returned, DWORD err) {
        auto idx = static_cast<size_t>(cls);
        if (idx >= (size_t)kFailLogSlots) return;
        int n = m_failLogCounts[idx].fetch_add(1, std::memory_order_relaxed);
        if (n < kIoFailLogCap) {
            printf(skCrypt("[SysMonitor] NTIOLib IOCTL 0xC3506104 failed: %s  pa=0x%llX  bytes=%u  returned=%u  err=%lu\n"),
                   SivFailName(cls),
                   (unsigned long long)pa,
                   (unsigned)size,
                   (unsigned)returned,
                   (unsigned long)err);
        } else if (n == kIoFailLogCap) {
            printf(skCrypt("[SysMonitor] NTIOLib IOCTL 0xC3506104: further %s failures suppressed (cap=%d)\n"),
                   SivFailName(cls), kIoFailLogCap);
        }
    }

    // Arm the driver's activation gate. NTIOLib requires ONE call of
    // IOCTL_NTIO_ARM with the magic 0x2F405A34 word in the buffer before
    // any read/write IOCTL is dispatched. The gate is a DRIVER-GLOBAL
    // (persists across handle closes; only clears on driver unload), so
    // once we've armed it in this driver session further ARM calls are
    // redundant syscalls on the hot read path. m_armed tracks that state.
    // ResetIoBreaker (called on driver reload) also resets this so the
    // next Open re-arms cleanly.
    bool NtioArm(HANDLE h) {
        if (m_armed.load(std::memory_order_acquire)) return true;
        uint32_t buf = NTIO_ARM_MAGIC;
        DWORD    returned = 0;
        SetLastError(0);
        BOOL     ok = DeviceIoControl(h, IOCTL_NTIO_ARM,
                                      &buf, sizeof(buf),
                                      &buf, sizeof(buf),
                                      &returned, nullptr);
        DWORD    err = GetLastError();
        printf(skCrypt("[SysMonitor] ARM IOCTL 0x%08X sent (in=4 out=4 magic=0x%08X) -> ok=%d returned=%lu err=%lu buf_after=0x%08X\n"),
               (unsigned)IOCTL_NTIO_ARM, (unsigned)NTIO_ARM_MAGIC,
               (int)(ok != FALSE), returned, err, (unsigned)buf);
        if (ok != FALSE) m_armed.store(true, std::memory_order_release);
        SetLastError(err);
        return ok != FALSE;
    }

    // One-shot probe of IOCTL 0xC3502004 (VERSION). If dispatch works at all,
    // this returns a small dword to the caller. If it fails with err=6 like
    // ARM/READ do, the driver rejects this handle for ALL IOCTLs — deeper
    // than arm-global bookkeeping.
    bool NtioVersionProbe(HANDLE h, uint32_t& outVal) {
        uint32_t buf = 0;
        DWORD    returned = 0;
        SetLastError(0);
        BOOL ok = DeviceIoControl(h, 0xC3502004u,
                                  &buf, sizeof(buf),
                                  &buf, sizeof(buf),
                                  &returned, nullptr);
        DWORD err = GetLastError();
        outVal = buf;
        printf(skCrypt("[SysMonitor] VERSION IOCTL 0xC3502004 -> ok=%d returned=%lu err=%lu value=0x%08X\n"),
               (int)(ok != FALSE), returned, err, (unsigned)buf);
        return ok != FALSE;
    }

    // Try a candidate arm IOCTL + input pattern, then immediately probe with
    // a physical read. Returns true if the probe succeeds (i.e., driver is
    // now armed by whatever we just sent). This is empirical brute force —
    // static analysis of the driver says 0xC350214C with 4-byte magic should
    // arm, but it doesn't stick on dj's build. Try alternate encodings the
    // MSI codebase might expect.
    bool TryArmVariant(HANDLE h, uint32_t ioctlCode, const void* inBuf, size_t inSize,
                       size_t outSize, const char* tag)
    {
        // Send the candidate arm IOCTL
        uint8_t out[64] = {};
        DWORD returned = 0;
        SetLastError(0);
        BOOL ok = DeviceIoControl(h, ioctlCode,
                                  const_cast<void*>(inBuf), (DWORD)inSize,
                                  out, (DWORD)outSize,
                                  &returned, nullptr);
        DWORD armErr = GetLastError();

        // Probe: try reading 4 bytes from PA 0x1000 via READ_PHYS
        struct { uint64_t pa; uint32_t unit; uint32_t cnt; } req = { 0x1000, 4, 1 };
        uint32_t probe = 0;
        DWORD probeReturned = 0;
        SetLastError(0);
        BOOL probeOk = DeviceIoControl(h, IOCTL_NTIO_READ_PHYS,
                                       &req, sizeof(req),
                                       &probe, sizeof(probe),
                                       &probeReturned, nullptr);
        DWORD probeErr = GetLastError();

        printf(skCrypt("[SysMonitor] arm-scan [%s]: IOCTL 0x%08X in=%zu out=%zu -> ok=%d err=%lu ; "
                       "probe -> ok=%d err=%lu value=0x%08X\n"),
               tag, (unsigned)ioctlCode, inSize, outSize,
               (int)(ok != FALSE), armErr,
               (int)(probeOk != FALSE), probeErr, (unsigned)probe);

        return probeOk != FALSE;
    }

    // Empirical arm scan — cycle through candidate arm sequences until one
    // makes the READ probe succeed. Only called from Open() after the
    // static-analysis path fails. Brute-force expansion: 24 candidates
    // covering every reasonable input pattern the driver might expect.
    bool ArmScan(HANDLE h) {
        // Defense in depth: if the handle went invalid between Open()'s
        // ARM step and here, reopen so the arm-scan probes hit the driver
        // instead of ERROR_INVALID_HANDLE.
        if (h == INVALID_HANDLE_VALUE) {
            HANDLE nh = CreateFileA(GetDevicePath(),
                                    GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
            if (nh == INVALID_HANDLE_VALUE) {
                printf(skCrypt("[SysMonitor] arm-scan: could not reopen device (err=%lu)\n"),
                       GetLastError());
                return false;
            }
            m_hDevice = nh;
            h = nh;
            printf(skCrypt("[SysMonitor] arm-scan: reopened device handle=0x%p\n"), (void*)h);
        }
        printf(skCrypt("[SysMonitor] arm-scan: probing 24 arm candidates...\n"));
        m_armed.store(false, std::memory_order_release);

        struct Candidate {
            uint32_t code;
            uint32_t bufWords[8];   // up to 8 dwords of input
            size_t   inBytes;
            size_t   outSize;
            const char* tag;
        };
        const uint32_t M = NTIO_ARM_MAGIC;
        const uint32_t MI = ~NTIO_ARM_MAGIC;
        Candidate cands[] = {
            // Documented dispatch handler at 0x59E (my RE says this arms)
            { 0xC350214Cu, {M,0,0,0,0,0,0,0}, 4,  4,  "214C-4byte-in-out" },
            { 0xC350214Cu, {M,0,0,0,0,0,0,0}, 4,  0,  "214C-in4-out0" },
            { 0xC350214Cu, {M,M,0,0,0,0,0,0}, 8,  8,  "214C-8byte-both" },
            { 0xC350214Cu, {M,0,0,0,0,0,0,0}, 4,  16, "214C-in4-out16" },
            { 0xC350214Cu, {M,M,M,M,0,0,0,0}, 16, 16, "214C-16byte-magic" },
            { 0xC350214Cu, {M,0,0,0,0,0,0,0}, 4,  32, "214C-in4-out32" },
            { 0xC350214Cu, {M,MI,0,0,0,0,0,0}, 8, 8,  "214C-magic+inv" },
            { 0xC350214Cu, {0,M,0,0,0,0,0,0}, 8,  8,  "214C-magic-at-off4" },
            // MSR-family (some MSI builds route arm through these)
            { 0xC3502084u, {M,0,0,0,0,0,0,0}, 4,  4,  "2084-4byte" },
            { 0xC3502084u, {M,0,0,0,0,0,0,0}, 4,  16, "2084-in4-out16" },
            { 0xC3502084u, {M,M,0,0,0,0,0,0}, 8,  8,  "2084-8byte" },
            { 0xC3502088u, {M,0,0,0,0,0,0,0}, 4,  4,  "2088-4byte" },
            { 0xC3502088u, {M,M,0,0,0,0,0,0}, 8,  8,  "2088-8byte" },
            // Port-family (very unlikely but cheap)
            { 0xC35060C8u, {M,0,0,0,0,0,0,0}, 4,  4,  "60C8-port-r-4byte" },
            { 0xC350A0D8u, {M,0,0,0,0,0,0,0}, 4,  4,  "A0D8-port-w-4byte" },
            // VERSION and dead-case (control tests)
            { 0xC3502004u, {M,0,0,0,0,0,0,0}, 4,  4,  "2004-VERSION-4byte" },
            { 0xC3502000u, {M,0,0,0,0,0,0,0}, 4,  4,  "2000-DEAD-4byte" },
            // Empty / minimal buffers
            { 0xC350214Cu, {M,0,0,0,0,0,0,0}, 0,  0,  "214C-no-buffer" },
            { 0xC350214Cu, {0,0,0,0,0,0,0,0}, 4,  4,  "214C-zeros" },
            // High-func codes
            { 0xC350B941u, {M,0,0,0,0,0,0,0}, 4,  4,  "B941-4byte" },
            { 0xC3506144u, {M,0,0,0,0,0,0,0}, 4,  4,  "6144-4byte" },
            // Try 214C twice with a small delay (race the arm state)
            { 0xC350214Cu, {M,0,0,0,0,0,0,0}, 4,  4,  "214C-retry-1" },
            { 0xC350214Cu, {M,0,0,0,0,0,0,0}, 4,  4,  "214C-retry-2" },
            { 0xC350214Cu, {M,0,0,0,0,0,0,0}, 4,  4,  "214C-retry-3" },
        };
        for (auto& c : cands) {
            if (TryArmVariant(h, c.code, c.bufWords, c.inBytes, c.outSize, c.tag)) {
                m_armed.store(true, std::memory_order_release);
                printf(skCrypt("[SysMonitor] arm-scan WON with [%s]\n"), c.tag);
                return true;
            }
        }
        return false;
    }

    // Read-primitive scan. Walks the {IOCTL code × request shape} matrix
    // for a probe of PA 0x1000 dword-read. When the standard 16-byte
    // NtioReadReq at 0xC3506104 returns err=6 despite the driver being
    // armed (ARM ok, VERSION ok), the wire shape or the read IOCTL number
    // itself is what this build rejects — not the arm state. If any
    // combo wins, latch it into m_readIoctlIdx / m_readShapeIdx so the
    // hot path uses it, then return true. Caller must guarantee the
    // handle is valid.
    bool ReadScan(HANDLE h) {
        if (h == INVALID_HANDLE_VALUE) {
            printf(skCrypt("[SysMonitor] read-scan: handle invalid, skipping\n"));
            return false;
        }
        printf(skCrypt("[SysMonitor] read-scan: probing IOCTL/shape combos...\n"));
        const uint8_t nShapes = (uint8_t)NtioReadShape::kCount;
        const uint8_t nIoctls = (uint8_t)(sizeof(kReadIoctls) / sizeof(kReadIoctls[0]));
        for (uint8_t ci = 0; ci < nIoctls; ci++) {
            for (uint8_t si = 0; si < nShapes; si++) {
                uint8_t req[32] = {};
                size_t inBytes = BuildReadRequestBytes(
                    (NtioReadShape)si, 0x1000, 4, 1, req);
                if (!inBytes) continue;
                uint32_t out = 0;
                DWORD returned = 0;
                SetLastError(0);
                BOOL ok = DeviceIoControl(h, kReadIoctls[ci],
                                          req, (DWORD)inBytes,
                                          &out, sizeof(out),
                                          &returned, nullptr);
                DWORD err = GetLastError();
                printf(skCrypt("[SysMonitor] read-scan [ioctl=0x%08X shape=%u in=%zu]: "
                               "ok=%d returned=%lu err=%lu value=0x%08X\n"),
                       (unsigned)kReadIoctls[ci], (unsigned)si, inBytes,
                       (int)(ok != FALSE), returned, err, (unsigned)out);
                if (ok != FALSE && returned == sizeof(out)) {
                    m_readIoctlIdx.store(ci, std::memory_order_release);
                    m_readShapeIdx.store(si, std::memory_order_release);
                    printf(skCrypt("[SysMonitor] read-scan WON: ioctl=0x%08X shape=%u\n"),
                           (unsigned)kReadIoctls[ci], (unsigned)si);
                    return true;
                }
            }
        }
        return false;
    }

    // Confirms a candidate IOCTL is a real MmMapIoSpace-based read handler
    // and not a constant-returning stub like VERSION (0xC3502004 returns
    // 0x00000001 regardless of input, which happily passes an "ok=1
    // returned=4" check). The stub filter requests 8 bytes at PA 0x1000
    // (unit=4, count=2); a real read handler fills 8 bytes because it
    // sizes the copy from unit*count, while a stub keeps returning its
    // hardcoded 4-byte payload — the returned-count mismatch rejects it.
    bool ValidateReadCandidate(HANDLE h, uint32_t code) {
        struct { uint64_t pa; uint32_t unit; uint32_t count; } req = { 0x1000, 4, 2 };
        uint8_t buf[8] = {};
        DWORD ret = 0;
        SetLastError(0);
        BOOL ok = DeviceIoControl(h, code, &req, (DWORD)sizeof(req),
                                  buf, (DWORD)sizeof(buf), &ret, nullptr);
        if (ok == FALSE || ret != (DWORD)sizeof(buf)) return false;
        // Second probe: same PA, different unit shape. Real read returns
        // consistent bytes; a stub that ignores input and echoes memory
        // from its own buffer will differ.
        struct { uint64_t pa; uint32_t unit; uint32_t count; } req2 = { 0x1000, 2, 4 };
        uint8_t buf2[8] = {};
        DWORD ret2 = 0;
        SetLastError(0);
        BOOL ok2 = DeviceIoControl(h, code, &req2, (DWORD)sizeof(req2),
                                   buf2, (DWORD)sizeof(buf2), &ret2, nullptr);
        if (ok2 == FALSE || ret2 != (DWORD)sizeof(buf2)) return false;
        // The two probes read the same PA range in different unit sizes;
        // MmMapIoSpace + rep movs of unit*count bytes yields identical
        // byte patterns regardless of the movs granularity.
        return memcmp(buf, buf2, sizeof(buf)) == 0;
    }

    // Broad IOCTL-code sweep. Given ARM works on 0xC350214C, VERSION works
    // on 0xC3502004, but 0xC3506104 uniformly returns STATUS_INVALID_HANDLE
    // regardless of input shape, this build routes physical-memory read
    // through a code we haven't identified. Sweep the plausible ranges
    // with a standard 16-byte NtioReadReq at PA 0x1000 and classify:
    //   ok=1  returned=size   → CANDIDATE — validate with ValidateReadCandidate
    //   err=87 / err=24       → real handler, wrong request shape
    //   err=6                 → dead case OR arm-gated real handler
    //                            (both return STATUS_INVALID_HANDLE)
    //   err=1                 → not in dispatch table
    // Prints per-hit lines for the interesting classes plus a summary
    // count and the full err=6 candidate list — those are the codes
    // that need next-level attack (per-handle arm, image-name gate).
    bool ReadIoctlSweep(HANDLE h) {
        if (h == INVALID_HANDLE_VALUE) {
            printf(skCrypt("[SysMonitor] read-sweep: handle invalid, skipping\n"));
            return false;
        }

        // Refresh arm state on this handle before sweeping — some drivers
        // gate later reads on a per-handle arm token; the sweep needs
        // that token active for real handlers to accept our probes.
        {
            uint32_t magic = NTIO_ARM_MAGIC;
            DWORD ret = 0;
            SetLastError(0);
            DeviceIoControl(h, IOCTL_NTIO_ARM, &magic, sizeof(magic),
                            &magic, sizeof(magic), &ret, nullptr);
        }

        struct Range { uint32_t lo; uint32_t hi; const char* tag; };
        // Ranges chosen from the header's IOCTL surface table. The read
        // family is documented at 0xC35061xx, write at 0xC350A1xx, MSR at
        // 0xC35020xx. Sweep each family plus their neighbors — a build
        // that renamed 6104→ something in the same neighborhood will show.
        Range ranges[] = {
            { 0xC3506000u, 0xC3506FFFu, "6xxx-read-family" },
            { 0xC350A000u, 0xC350A2FFu, "Axxx-write-family" },
            { 0xC3502000u, 0xC35023FFu, "2xxx-msr-family" },
            { 0xC35060C0u, 0xC35060FFu, "60Cx-port-family" },
        };

        int  total  = 0;
        int  nErr1 = 0, nErr6 = 0, nErr87 = 0, nErr24 = 0, nOkStub = 0, nOther = 0;
        int  hitsPrinted = 0;
        uint32_t foundCode = 0;

        // Collect err=6 codes — these are candidates for the next attack
        // stage (per-handle arm state, image-name gating, secondary
        // unlock IOCTL). Cap at 64 to bound memory.
        constexpr int kMaxErr6 = 64;
        uint32_t err6Codes[kMaxErr6] = {};
        int      err6Count = 0;

        for (auto& r : ranges) {
            printf(skCrypt("[SysMonitor] read-sweep range [%s] 0x%08X..0x%08X (step 4)\n"),
                   r.tag, r.lo, r.hi);
            for (uint32_t code = r.lo; code <= r.hi; code += 4) {
                total++;
                uint8_t req[32] = {};
                size_t inBytes = BuildReadRequestBytes(
                    NtioReadShape::STD_16, 0x1000, 4, 1, req);
                uint32_t out = 0;
                DWORD returned = 0;
                SetLastError(0);
                BOOL ok = DeviceIoControl(h, code,
                                          req, (DWORD)inBytes,
                                          &out, sizeof(out),
                                          &returned, nullptr);
                DWORD err = GetLastError();

                if (ok != FALSE && returned == sizeof(out)) {
                    // Passed initial ok=1 returned=4 check — but VERSION
                    // and other constant-returning stubs also pass this.
                    // Validate with an 8-byte probe: real reads size the
                    // copy from unit*count, stubs keep echoing 4 bytes.
                    bool real = ValidateReadCandidate(h, code);
                    if (real) {
                        printf(skCrypt("[SysMonitor] read-sweep HIT: ioctl=0x%08X (validated as real read)  value=0x%08X\n"),
                               (unsigned)code, (unsigned)out);
                        if (!foundCode) foundCode = code;
                    } else {
                        nOkStub++;
                        printf(skCrypt("[SysMonitor] read-sweep [ioctl=0x%08X]: ok=1 but stub (constant/wrong size on 8B probe) — value=0x%08X\n"),
                               (unsigned)code, (unsigned)out);
                    }
                    continue;
                }
                switch (err) {
                case 1:  nErr1++;  break;
                case 6:
                    nErr6++;
                    if (err6Count < kMaxErr6) err6Codes[err6Count++] = code;
                    break;
                case 87:
                    nErr87++;
                    if (hitsPrinted < 16) {
                        printf(skCrypt("[SysMonitor] read-sweep [ioctl=0x%08X]: err=87 (real handler, wrong shape)\n"),
                               (unsigned)code);
                        hitsPrinted++;
                    }
                    break;
                case 24:
                    nErr24++;
                    if (hitsPrinted < 16) {
                        printf(skCrypt("[SysMonitor] read-sweep [ioctl=0x%08X]: err=24 (real handler, wrong buffer size)\n"),
                               (unsigned)code);
                        hitsPrinted++;
                    }
                    break;
                default:
                    nOther++;
                    if (hitsPrinted < 8) {
                        printf(skCrypt("[SysMonitor] read-sweep [ioctl=0x%08X]: err=%lu returned=%lu\n"),
                               (unsigned)code, err, returned);
                        hitsPrinted++;
                    }
                    break;
                }
            }
        }

        printf(skCrypt("[SysMonitor] read-sweep summary: probed=%d err1=%d err6=%d err87=%d err24=%d ok-stub=%d other=%d\n"),
               total, nErr1, nErr6, nErr87, nErr24, nOkStub, nOther);

        // Dump the full err=6 candidate list — these codes routed through
        // the driver's dispatch and hit a case that returned STATUS_INVALID_
        // HANDLE. Either dead cases OR real read/write handlers guarded by
        // an auth check we haven't defeated (per-handle arm, image-name
        // gate). Next stage: try each with alternate auth sequences.
        if (err6Count > 0) {
            printf(skCrypt("[SysMonitor] read-sweep err=6 codes (%d total):"), err6Count);
            for (int i = 0; i < err6Count; i++) {
                printf(" 0x%08X", (unsigned)err6Codes[i]);
                if ((i & 7) == 7 && i + 1 < err6Count) printf("\n                            ");
            }
            printf("\n");
        }

        if (foundCode) {
            m_readIoctlOverride.store(foundCode, std::memory_order_release);
            m_readShapeIdx.store((uint8_t)NtioReadShape::STD_16, std::memory_order_release);
            printf(skCrypt("[SysMonitor] read-sweep FOUND read primitive at 0x%08X — latching for hot path\n"),
                   (unsigned)foundCode);
            return true;
        }
        return false;
    }

    // Retry wrapper called from Open. Some NTIOLib builds initialize their
    // dispatch state a few ticks after DriverEntry returns; a rapid CreateFile
    // → ARM sequence right after service start can race that init and get
    // err=6 (STATUS_INVALID_HANDLE from the driver's own dispatch even
    // though the file handle itself is valid). On failure:
    //  - Small back-off and retry the same 4-byte ARM
    //  - Try the 8-byte {magic, 0} variant some patch levels use
    //  - Try METHOD-neither shape (odd trailing 0)
    // Returns true on the first successful attempt.
    bool TryArmWithRetries(HANDLE h) {
        // First: the canonical 4-byte ARM, up to 4 tries with growing sleep.
        for (int i = 0; i < 4; i++) {
            if (NtioArm(h)) return true;
            DWORD err = GetLastError();
            // err=6 means the driver rejected the handle/state — retrying
            // the same call on the same handle only helps if the driver
            // is still initializing; give it up to ~200 ms total.
            if (err != 6 && err != 1450 && err != 87) return false;
            Sleep(20 + i * 40);
            // Clear m_armed since NtioArm short-circuits on it — but we
            // never set it on failure, so this is just belt-and-braces.
            m_armed.store(false, std::memory_order_release);
        }
        // Second: 8-byte buffer variant. Some MSI patch levels moved the
        // magic to offset 0 of an 8-byte request (upper dword unused).
        // Same IOCTL code, larger in/out to satisfy their length check.
        {
            uint64_t buf8 = NTIO_ARM_MAGIC;    // magic at low dword, high dword = 0
            DWORD    returned = 0;
            BOOL     ok = DeviceIoControl(h, IOCTL_NTIO_ARM,
                                          &buf8, sizeof(buf8),
                                          &buf8, sizeof(buf8),
                                          &returned, nullptr);
            if (ok != FALSE) {
                m_armed.store(true, std::memory_order_release);
                return true;
            }
        }
        return false;
    }

    // Bulk physical read via NTIOLib IOCTL 0xC3506104. One IOCTL fills up
    // to unit_size*count bytes in the caller-supplied output buffer.
    // Contract (verified against dispatch handler @ 0x1400013ac):
    //   in  = NtioReadReq{phys_addr, unit_size ∈ {1,2,4}, count}
    //   out = unit_size*count raw bytes copied from the mapped PA range
    //   driver: MmMapIoSpace(PA, size, MmNonCached) → rep movs → unmap
    //
    // Failure discipline: same shape as before —
    //   - Transient (err=1450) → retry once
    //   - Pipe-death (err=5/6, handle-failed) → count toward breaker
    //   - Per-PA rejections (MmMapIoSpace refused a specific address) →
    //     reset streak; the driver is alive, this address just isn't mappable
    bool NtioReadOnce(uint64_t physAddr, uint32_t unit_size, uint32_t count,
                      void* out_data, size_t out_capacity) {
        if (unit_size != 1 && unit_size != 2 && unit_size != 4) return false;
        if (!count || !out_data)                                return false;
        size_t bytes = (size_t)unit_size * count;
        if (bytes > out_capacity)                               return false;

        if (m_ioBroken.load(std::memory_order_acquire)) return false;

        HANDLE hUse = INVALID_HANDLE_VALUE;
        bool   ownedOpen = false;
        EnterCriticalSection(&m_physLock);
        if (m_idleMode) {
            if (!IsOpen()) {
                m_hDevice = CreateFileA(GetDevicePath(),
                                        GENERIC_READ | GENERIC_WRITE,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, nullptr);
                if (m_hDevice != INVALID_HANDLE_VALUE) {
                    // Fresh handle in idle mode. NtioArm short-circuits via
                    // m_armed after the first successful Open()-time ARM in
                    // this driver session, so this is a load+branch (no
                    // syscall) on every idle reopen from cache read #1 on.
                    NtioArm(m_hDevice);
                }
                ownedOpen = (m_hDevice != INVALID_HANDLE_VALUE);
            }
        }
        hUse = m_hDevice;
        LeaveCriticalSection(&m_physLock);
        if (hUse == INVALID_HANDLE_VALUE) {
            NoteSivFail(SivFail::HandleFailed, physAddr, (DWORD)bytes, 0, GetLastError());
            return false;
        }

        uint8_t reqBuf[32] = {};
        uint8_t shapeIdx = m_readShapeIdx.load(std::memory_order_acquire);
        uint8_t ioctlIdx = m_readIoctlIdx.load(std::memory_order_acquire);
        if (shapeIdx >= (uint8_t)NtioReadShape::kCount) shapeIdx = 0;
        if (ioctlIdx >= 2) ioctlIdx = 0;
        size_t inBytes = BuildReadRequestBytes(
            (NtioReadShape)shapeIdx, physAddr, unit_size, count, reqBuf);
        uint32_t codeOverride = m_readIoctlOverride.load(std::memory_order_acquire);
        uint32_t code = codeOverride ? codeOverride : kReadIoctls[ioctlIdx];

        DWORD returned = 0;
        BOOL  ok = DeviceIoControl(hUse, code,
                                   reqBuf, (DWORD)inBytes,
                                   out_data, (DWORD)bytes,
                                   &returned, nullptr);

        SivFail cls;
        if (ok != FALSE && returned == (DWORD)bytes) {
            cls = SivFail::Ok;
        } else if (ok != FALSE) {
            cls = SivFail::PartialReturn;
        } else {
            DWORD err = GetLastError();
            switch (err) {
                case 5:                                cls = SivFail::IoctlDenied;   break;
                case 6:                                cls = SivFail::HandleStale;   break;
                case 1: case 24: case 87: case 8: case 31:
                                                       cls = SivFail::IoctlRejected; break;
                case 1450:                             cls = SivFail::Transient;     break;
                default:                               cls = SivFail::UnknownError;  break;
            }
        }

        if (cls == SivFail::Transient) {
            Sleep(0);
            returned = 0;
            ok = DeviceIoControl(hUse, code,
                                 reqBuf, (DWORD)inBytes,
                                 out_data, (DWORD)bytes,
                                 &returned, nullptr);
            if (ok != FALSE && returned == (DWORD)bytes) cls = SivFail::Ok;
        }

        // HandleStale (err=6) means the driver was reloaded out from under
        // us (MSI Center restarting its service, an admin poking
        // sc.exe stop/start, or our own self-heal after a Vanguard bump).
        // Two side-effects that need clearing so the NEXT read recovers:
        //   1. Close the handle so the idle-mode reopen builds a fresh one.
        //   2. Clear m_armed — the driver's activation global was zeroed on
        //      unload, so the reopen must re-ARM. Without this, m_armed
        //      stays true, NtioArm short-circuits, and every subsequent
        //      read fails permanently until the user restarts the cheat.
        //
        // Exception: during Open()'s probe path (m_openProbeInProgress),
        // an err=6 from an unknown-shape probe doesn't mean the handle
        // died — it means the driver rejected THIS shape. Closing the
        // handle here would blind the shape-scan and arm-scan that follow.
        if (cls == SivFail::HandleStale
            && !m_openProbeInProgress.load(std::memory_order_acquire)) {
            EnterCriticalSection(&m_physLock);
            if (m_hDevice != INVALID_HANDLE_VALUE) {
                CloseHandle(m_hDevice);
                m_hDevice = INVALID_HANDLE_VALUE;
            }
            LeaveCriticalSection(&m_physLock);
            m_armed.store(false, std::memory_order_release);
            ownedOpen = false;   // handle already gone
        }

        if (ownedOpen) {
            EnterCriticalSection(&m_physLock);
            if (m_hDevice != INVALID_HANDLE_VALUE) {
                CloseHandle(m_hDevice); m_hDevice = INVALID_HANDLE_VALUE;
            }
            LeaveCriticalSection(&m_physLock);
        }

        if (cls == SivFail::Ok) {
            m_ioFailStreak.store(0, std::memory_order_release);
            return true;
        }

        NoteSivFail(cls, physAddr, (DWORD)bytes, returned, GetLastError());
        if (IsPipeDeath(cls)) {
            int streak = m_ioFailStreak.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (streak >= kIoFailStreakBreaker) {
                if (!m_ioBroken.exchange(true, std::memory_order_acq_rel)) {
                    printf(skCrypt("[SysMonitor] NTIOLib pipe dead (%d consecutive %s failures) — fast-failing further reads. Reset via WinDrvReader::Get().ResetIoBreaker() after re-loading.\n"),
                           streak, SivFailName(cls));
                }
            }
        } else {
            m_ioFailStreak.store(0, std::memory_order_release);
        }
        return false;
    }

    // Arbitrary-size physical read via NTIOLib's bulk primitive.
    // One IOCTL fills the whole request in a single kernel round-trip
    // (verified against the read handler @ 0x1400013ac which uses
    // rep movsb/w/d inside kernel to copy from the mapped range).
    // 64-bit PA supported — no 4 GB ceiling like the Corsair era.
    bool SivReadPhys(uint64_t physAddr, void* out, size_t size) {
        if (!out || size == 0) {
            NoteSivFail(SivFail::BadArgs, physAddr, (DWORD)size, 0, 0);
            return false;
        }
        // NTIOLib's PA sanity check rejects addresses whose top 16 bits
        // exceed 0xFEDC (verified @ 0x1400013f7). That leaves ~255 TB of
        // usable PA space — plenty of headroom for anything short of a
        // kernel-VA-shaped garbage value.
        if (((physAddr + size - 1) >> 48) > 0xFEDCULL) {
            NoteSivFail(SivFail::BadArgs, physAddr, (DWORD)size, 0, 0);
            return false;
        }

        // Pick the largest unit_size that both PA and size align to. This
        // keeps `rep movs` in the kernel handler on its fast dword path.
        uint32_t unit;
        uint32_t count;
        if ((physAddr & 3ULL) == 0 && (size & 3ULL) == 0) {
            unit = 4; count = (uint32_t)(size / 4);
        } else if ((physAddr & 1ULL) == 0 && (size & 1ULL) == 0) {
            unit = 2; count = (uint32_t)(size / 2);
        } else {
            unit = 1; count = (uint32_t)size;
        }
        return NtioReadOnce(physAddr, unit, count, out, size);
    }

    // Fills a 4 KB physical page. NTIOLib supports the whole page in one
    // IOCTL — massive improvement over Corsair's 1024-DWORD cost per page.
    bool SivReadPage(uint64_t pagePA, uint8_t out[4096]) {
        pagePA &= ~0xFFFULL;
        if (!out || reinterpret_cast<uintptr_t>(out) < 0x10000ULL) return false;

        // Same PA-sanity gate as the driver (top 16 bits ≤ 0xFEDC).
        if (((pagePA + 0xFFFULL) >> 48) > 0xFEDCULL) return false;

        // PA blacklist: skip pages that have failed before. Miss once, skip forever.
        for (int i = 0; i < kBadPaCount; i++)
            if (m_badPAs[i] && m_badPAs[i] == pagePA) return false;

        // Serialise so one thread's IOCTL isn't interleaved with another's.
        // Not strictly required for correctness (each IOCTL is self-contained)
        // but keeps driver-side MmMapIoSpace locality clean.
        EnterCriticalSection(&m_ioctlLock);
        bool ok = NtioReadOnce(pagePA, 4, 1024, out, 4096);
        if (!ok) {
            static bool s_logged = false;
            if (!s_logged) {
                s_logged = true;
                printf(skCrypt("[SysMonitor] NTIOLib page read failed: err=%lu (PA=0x%llX)\n"),
                       GetLastError(), (unsigned long long)pagePA);
            }
            m_badPAs[m_badPaHead] = pagePA;
            m_badPaHead = (m_badPaHead + 1) % kBadPaCount;
        }
        LeaveCriticalSection(&m_ioctlLock);
        return ok;
    }

    // Compatibility shim — callers still use the old NalReadPage name.
    bool NalReadPage(uint64_t pagePA, uint8_t out[4096]) {
        return SivReadPage(pagePA, out);
    }

    uint64_t ReadPhys64(uint64_t physAddr) {
        uint64_t val = 0;
        if (!PhysRead(physAddr, &val, sizeof(val)))
            return 0;
        return val;
    }

    uint64_t GetNtoskrnlVa() {
        // Method 1: EnumDeviceDrivers — ntoskrnl is always drivers[0] on admin processes
        LPVOID drivers[1024] = {};
        DWORD needed = 0;
        auto pEnumDeviceDrivers = reinterpret_cast<BOOL(WINAPI*)(LPVOID*, DWORD, LPDWORD)>(
            AntiDebug::ResolveExport(AntiDebug::Fnv1a("EnumDeviceDrivers")));
        if (pEnumDeviceDrivers && pEnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed >= sizeof(PVOID)) {
            uint64_t base = (uint64_t)drivers[0];
            if (base >= 0xFFFF800000000000ULL) return base;
        }

        // Method 2: NtQuerySystemInformation(11) = SystemModuleInformation
        // RTL_PROCESS_MODULES layout on x64:
        //   +0x00  NumberOfModules (ULONG, 4B)
        //   +0x04  padding (4B)
        //   +0x08  Module[0] (RTL_PROCESS_MODULE_INFORMATION):
        //     +0x00  Section   (HANDLE, 8B)
        //     +0x08  MappedBase (PVOID, 8B)
        //     +0x10  ImageBase  (PVOID, 8B)  ← ntoskrnl VA at buf+0x18
        {
            typedef LONG(NTAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
            auto NtQSI = (NtQSI_t)li::detail::resolve(0x7A43974Au);
            if (NtQSI) {
                ULONG bufSize = 0;
                NtQSI(11, nullptr, 0, &bufSize);
                if (bufSize) {
                    bufSize += 0x1000;
                    BYTE* buf = (BYTE*)malloc(bufSize);
                    if (buf) {
                        if (NtQSI(11, buf, bufSize, nullptr) == 0 && bufSize >= 0x20) {
                            uint64_t base = *(uint64_t*)(buf + 0x18);
                            free(buf);
                            if (base >= 0xFFFF800000000000ULL) return base;
                        } else {
                            free(buf);
                        }
                    }
                }
            }
        }

        return 0;  // Both methods failed — ResolveSystemCr3 will log and return false
    }

    uint64_t BruteForceCr3(uint64_t kernVA, uint64_t* outKernPA) {
        const uint64_t pml4Idx = (kernVA >> 39) & 0x1FF;
        const uint64_t pml4Off = pml4Idx * 8;

        // Was 256 MB. Modern Win11 (24H2 / 25H2) on boxes with ≥ 16 GB RAM
        // allocates the kernel's page-table pool well above the low-RAM
        // window — CR3 is routinely observed in the 1-4 GB physical range,
        // occasionally higher. Bumped to 4 GB and instrumented so a scan
        // that still comes up empty gives operator data to reason with
        // (how many candidates hit PML4, how many made it through the full
        // walk, and where the driver refused MmMapIoSpace).
        const uint64_t limit = 0x100000000ULL;   // 4 GB
        const uint64_t progressStep = 0x20000000; // 512 MB

        uint64_t pml4Hits    = 0;
        uint64_t walkAttempts = 0;
        uint64_t translated   = 0;   // walks that produced a non-zero PA
        uint64_t peChecked    = 0;   // PAs where HasPeHeader was queried
        uint64_t nextProgress = progressStep;

        for (uint64_t candidate = 0x1000; candidate < limit; candidate += 0x1000) {
            if (candidate >= nextProgress) {
                printf(skCrypt("[SysMonitor] CR3 scan progress: %llu MB done, %llu PML4 hits so far, %llu translated\n"),
                       (unsigned long long)(candidate >> 20),
                       (unsigned long long)pml4Hits,
                       (unsigned long long)translated);
                nextProgress += progressStep;
            }
            if (!IsSafeToMap(candidate)) continue;

            uint64_t pml4e = ReadPhys64(candidate + pml4Off);
            if (!(pml4e & 1)) continue;
            pml4Hits++;

            walkAttempts++;
            uint64_t pa = TranslateWithCr3(candidate, kernVA);
            if (!pa) continue;
            translated++;

            peChecked++;
            if (HasPeHeader(pa)) {
                printf(skCrypt("[SysMonitor] CR3 found at 0x%llX after %llu PML4 hits / %llu walks / %llu translated / %llu PE-checked\n"),
                       (unsigned long long)candidate,
                       (unsigned long long)pml4Hits,
                       (unsigned long long)walkAttempts,
                       (unsigned long long)translated,
                       (unsigned long long)peChecked);
                *outKernPA = pa;
                return candidate;
            }
        }

        printf(skCrypt("[SysMonitor] CR3 scan exhausted %llu MB: %llu PML4 hits, %llu walks, %llu translated, %llu PE-checked, no valid CR3\n"),
               (unsigned long long)(limit >> 20),
               (unsigned long long)pml4Hits,
               (unsigned long long)walkAttempts,
               (unsigned long long)translated,
               (unsigned long long)peChecked);
        return 0;
    }

    uint64_t TranslateWithCr3(uint64_t cr3, uint64_t va) {
        // Fast ceiling: rejects clearly-garbage PTEs before touching IsSafeToMap
        static const uint64_t PA_MAX = 0x10000000000ULL; // 1 TB

        uint64_t pml4e = ReadPhys64(cr3 + ((va >> 39) & 0x1FF) * 8);
        if (!(pml4e & 1)) return 0;
        uint64_t pdptPA = pml4e & 0xFFFFFFFFFF000;
        if (pdptPA >= PA_MAX || !IsSafeToMap(pdptPA)) return 0;

        uint64_t pdpte = ReadPhys64(pdptPA + ((va >> 30) & 0x1FF) * 8);
        if (!(pdpte & 1)) return 0;
        if (pdpte & 0x80)
            return (pdpte & 0x000FFFFFC0000000) | (va & 0x3FFFFFFF);
        uint64_t pdPA = pdpte & 0xFFFFFFFFFF000;
        if (pdPA >= PA_MAX || !IsSafeToMap(pdPA)) return 0;

        uint64_t pde = ReadPhys64(pdPA + ((va >> 21) & 0x1FF) * 8);
        if (!(pde & 1)) return 0;
        if (pde & 0x80)
            return (pde & 0xFFFFFFFE00000) | (va & 0x1FFFFF);
        uint64_t ptPA = pde & 0xFFFFFFFFFF000;
        if (ptPA >= PA_MAX || !IsSafeToMap(ptPA)) return 0;

        uint64_t pte = ReadPhys64(ptPA + ((va >> 12) & 0x1FF) * 8);
        if (!(pte & 1)) return 0;

        uint64_t result = (pte & 0xFFFFFFFFFF000) | (va & 0xFFF);
        if (result >= PA_MAX || !IsSafeToMap(result)) return 0;
        return result;
    }

    static bool IsSafeToMap(uint64_t pa) {
        if (pa < 0x1000) return false;
        if (pa >= 0xA0000    && pa <  0x100000)  return false;  // VGA/BIOS ROM (ISA hole)
        if (pa >= 0xC0000000 && pa <= 0xFFFFFFFF) return false;  // PCI BARs / LAPIC / HPET
        static const uint64_t kPhysCeil = [] {
            MEMORYSTATUSEX ms = { sizeof(ms) };
            uint64_t base = GlobalMemoryStatusEx(&ms)
                            ? ms.ullTotalPhys : 0x800000000ULL;
            return base + 0x100000000ULL;
        }();
        if (pa >= kPhysCeil) return false;
        return true;
    }

    bool HasPeHeader(uint64_t physAddr) {
        // Read first 0x40 bytes to safely access e_lfanew at offset 0x3C
        uint8_t hdr[0x40] = {};
        if (!PhysRead(physAddr, hdr, sizeof(hdr))) return false;

        if (*(uint16_t*)(hdr + 0) != 0x5A4D) return false;  // MZ

        uint32_t peOff = *(uint32_t*)(hdr + 0x3C);
        // Sanity: ntoskrnl PE header is always within the first 4 KB
        if (peOff < 0x40 || peOff > 0xF00u) return false;

        // Read from peOff to cover the full Optional Header up to SizeOfImage.
        // SizeOfImage is at PE header + 0x50; we need peOff..peOff+0x58 to be valid.
        uint8_t pe[0x60] = {};
        if (!PhysRead(physAddr + peOff, pe, sizeof(pe))) return false;

        if (*(uint32_t*)(pe + 0) != 0x00004550) return false;  // "PE\0\0"
        if (*(uint16_t*)(pe + 4) != 0x8664)     return false;  // AMD64
        if (*(uint16_t*)(pe + 0x18) != 0x020B)  return false;  // PE32+

        // SizeOfImage: ntoskrnl is always > 4 MB; filter out tiny stubs
        uint32_t sizeOfImage = *(uint32_t*)(pe + 0x50);
        if (sizeOfImage < 0x400000 || sizeOfImage > 0x10000000) return false;

        return true;
    }

    bool ReadKernelVA(uint64_t va, void* buffer, size_t size) {
        return ReadVirtual(m_systemCr3, va, buffer, size);
    }

    uint64_t FindPsInitialSystemProcess() {
        uint8_t hdr[0x1000] = {};
        if (!ReadKernelVA(m_kernelBase, hdr, sizeof(hdr)))
            return 0;

        uint32_t peOff = *(uint32_t*)(hdr + 0x3C);
        if (peOff + 0x90u > sizeof(hdr)) return 0;

        // IMAGE_NT_HEADERS64 layout (from peOff):
        //   +0x00  Signature (4)
        //   +0x04  FileHeader (20)
        //   +0x18  OptionalHeader (PE32+):
        //            +0x70 DataDirectory[0] = Export  <- peOff+0x88
        //            +0x74 DataDirectory[0].Size       <- peOff+0x8C
        uint32_t exportRva  = *(uint32_t*)(hdr + peOff + 0x88);
        uint32_t exportSize = *(uint32_t*)(hdr + peOff + 0x8C);
        if (!exportRva || !exportSize || exportSize > 0x400000u)
            return 0;

        // Load the entire export section in one read to avoid per-symbol IOCTLs.
        // The section includes the IMAGE_EXPORT_DIRECTORY + all name/ordinal/RVA tables
        // + name strings, so a single bulk read suffices.
        std::vector<uint8_t> exportBuf(exportSize);
        if (!ReadKernelVA(m_kernelBase + exportRva, exportBuf.data(), exportSize))
            return 0;
        if (exportBuf.size() < 40) return 0;

        uint32_t numNames    = *(uint32_t*)(exportBuf.data() + 24);
        uint32_t addrOfFuncs = *(uint32_t*)(exportBuf.data() + 28);
        uint32_t addrOfNames = *(uint32_t*)(exportBuf.data() + 32);
        uint32_t addrOfOrd   = *(uint32_t*)(exportBuf.data() + 36);

        // Convert image RVAs to offsets within our buffer
        if (addrOfNames < exportRva || addrOfOrd < exportRva || addrOfFuncs < exportRva)
            return 0;
        uint32_t namesOff = addrOfNames - exportRva;
        uint32_t ordOff   = addrOfOrd   - exportRva;
        uint32_t funcsOff = addrOfFuncs - exportRva;
        if (namesOff + numNames * 4u > exportSize) return 0;

        for (uint32_t i = 0; i < numNames; i++) {
            uint32_t nameRva = *(uint32_t*)(exportBuf.data() + namesOff + i * 4);
            uint32_t nameOff = nameRva - exportRva;
            if (nameOff >= exportSize) continue;

            const char* name = (const char*)(exportBuf.data() + nameOff);
            if (strcmp(name, skCrypt("PsInitialSystemProcess")) != 0) continue;

            uint16_t ord = *(uint16_t*)(exportBuf.data() + ordOff + i * 2);
            if (funcsOff + (uint32_t)(ord + 1) * 4u > exportSize) continue;
            uint32_t funcRva = *(uint32_t*)(exportBuf.data() + funcsOff + ord * 4);

            // PsInitialSystemProcess is a pointer variable; read the 8-byte VA it holds
            uint64_t eprocessVa = 0;
            if (!ReadKernelVA(m_kernelBase + funcRva, &eprocessVa, 8))
                continue;

            DBG_PRINT("[WinDrv] PsInitialSystemProcess VA: 0x%llX\n",
                   (unsigned long long)eprocessVa);
            return eprocessVa;
        }

        return 0;
    }

    uint64_t FindEprocessByPid(uint32_t targetPid, uint64_t systemEprocessVA) {
        const uint32_t offLinks = Layout().ActiveProcessLinks;
        const uint32_t offPid   = Layout().UniqueProcessId;

        uint64_t flink = 0;
        if (!ReadKernelVA(systemEprocessVA + offLinks, &flink, 8))
            return 0;

        uint64_t headLink = systemEprocessVA + offLinks;
        uint64_t current = flink;

        for (int i = 0; i < 1024; i++) {
            if (!current || current == headLink)
                break;

            uint64_t eprocess = current - offLinks;

            uint32_t pid = 0;
            if (!ReadKernelVA(eprocess + offPid, &pid, 4))
                break;

            if (pid == targetPid)
                return eprocess;

            // Advance to next Flink
            if (!ReadKernelVA(current, &current, 8))
                break;
        }

        return 0;
    }

    struct EprocessLayout {
        uint32_t UniqueProcessId;
        uint32_t ActiveProcessLinks;
        uint32_t Peb;
        uint32_t UserDirectoryTableBase;
        uint32_t VadRoot;
    };

    // Verified builds: 19041–19045 (Win10 20H1–22H2), 22000–22631 (Win11 21H2–23H2), 26100+ (Win11 24H2+)
    static const EprocessLayout& Layout() {
        static const EprocessLayout s = [] {
            using RtlGV_t = LONG(NTAPI*)(RTL_OSVERSIONINFOW*);
            auto pRtlGetVersion = (RtlGV_t)AntiDebug::ResolveExport(AntiDebug::Fnv1a("RtlGetVersion"));
            RTL_OSVERSIONINFOW vi = { sizeof(vi) };
            DWORD build = (pRtlGetVersion && pRtlGetVersion(&vi) == 0) ? vi.dwBuildNumber : 0;

            if (build == 0) {
                // RtlGetVersion resolution failed. Default to the newest
                // known layout — target box is Win11 24H2/25H2, wrong
                // Win10 offsets there would silently misread every EPROCESS
                // field and cause a cascade of module-discovery failures.
                printf("[SysMonitor] WARNING: RtlGetVersion failed — assuming Win11 24H2+ EPROCESS layout\n");
                build = 26100;
            } else if (build < 19041) {
                printf("[SysMonitor] WARNING: untested Windows build %lu — EPROCESS offsets may be wrong\n", (unsigned long)build);
            }

            EprocessLayout l = {};
            if (build >= 26100) {
                // Windows 11 24H2+ (build 26100, 26200, ...)
                // Verified against Vergilius Project _KPROCESS / _EPROCESS for 26200:
                //   _KPROCESS.DirectoryTableBase     = +0x028 (EPROCESS+0x028)
                //   _KPROCESS.UserDirectoryTableBase = +0x158 (EPROCESS+0x158)
                //   _EPROCESS.UniqueProcessId        = 0x1D0
                //   _EPROCESS.ActiveProcessLinks     = 0x1D8
                //   _EPROCESS.Peb                    = 0x2E0
                //   _EPROCESS.VadRoot                = 0x558
                l.UniqueProcessId        = 0x1D0;
                l.ActiveProcessLinks     = 0x1D8;
                l.Peb                    = 0x2E0;
                l.UserDirectoryTableBase = 0x158; // KPROCESS+0x158; was wrong (0x388 = DefaultHardErrorProcessing)
                l.VadRoot                = 0x558;
            } else {
                // Windows 10 / Windows 11 21H2–23H2
                l.UniqueProcessId        = 0x440;
                l.ActiveProcessLinks     = 0x448;
                l.Peb                    = 0x550;
                l.UserDirectoryTableBase = 0x388;
                l.VadRoot                = 0x7D8;
            }
            return l;
        }();
        return s;
    }

    // 256 × 4 KB = 1 MB of cached physical pages. Sized for the 5700x /
    // 32 GB target: the Zen3 shared L3 is 32 MB, so 1 MB is comfortable
    // headroom. NTIOLib fills a page in a single IOCTL (was 1024 under
    // Corsair), and every avoided cold-miss saves one kernel round-trip
    // on the cache-thread hot path. Doubling the cache from the Corsair
    // era's 128 slots captures more of the entity working set on rounds
    // where the player count is high (up to 10 controllers × ~5 hot pages
    // each + a dozen weapon/globals pages) with room for VM/EPROCESS
    // page reuse. Steady-state cost: +512 KB heap.
    static constexpr int kPhysPageCacheN = 256;
    struct PhysPageEntry { uint64_t pa; uint8_t data[4096]; };

    bool            m_idleMode         = false;
    HANDLE          m_hDevice          = INVALID_HANDLE_VALUE;
    // (Device path is hardcoded — see GetDevicePath. m_devicePath removed.)
    uint64_t        m_kernelBase       = 0;
    uint64_t        m_kernelPA         = 0;
    uint64_t        m_systemCr3        = 0;
    uint64_t        m_systemEprocessVA = 0;
    uint64_t        m_cs2EprocessVA    = 0;
    bool            m_cr3Resolved      = false;
    PhysPageEntry    m_physPageCache[kPhysPageCacheN];
    int              m_physPageHead     = 0;
    CRITICAL_SECTION m_physLock;
    // Serialises the full map/memcpy/unmap sequence so concurrent threads
    // never have overlapping mappings active in the driver. Prevents a
    // whole class of kernel-side races that can bugcheck 0x3B.
    CRITICAL_SECTION m_ioctlLock;
    // Small ring of PAs the driver has failed on. Later attempts to read
    // these are refused up-front. Prevents the same PA re-hammering the
    // driver after it just faulted on it.
    static constexpr int kBadPaCount = 64;
    uint64_t             m_badPAs[kBadPaCount] = {};
    int                  m_badPaHead = 0;

    // Circuit-breaker + rate-limited-log state for SivReadPhys.
    //   kIoFailStreakBreaker: consecutive pipe-death failures (HandleStale
    //     / HandleFailed / IoctlDenied per IsPipeDeath()) before we latch
    //     broken and start fast-failing subsequent reads. Per-PA rejections
    //     never accumulate here — they reset the streak — so CR3 brute-
    //     force and PT scans that legitimately hit driver-refused reserved-
    //     memory PAs cannot false-trip the breaker. 32 is generous slack for
    //     a genuine anti-cheat teardown or driver unload without hiding a
    //     real death for long.
    //   kIoFailLogCap: max prints per SivFail code per run. Chosen so
    //     first-time diagnostics show up clearly (10 lines is enough to
    //     see PA patterns) but a repeat problem doesn't drown the console.
    //   kFailLogSlots: covers every current SivFail enumerator; increase
    //     alongside the enum if new codes are added.
    static constexpr int  kIoFailStreakBreaker = 32;
    static constexpr int  kIoFailLogCap        = 40;
    static constexpr int  kFailLogSlots        = 9;
    std::atomic<int>      m_ioFailStreak       {0};
    std::atomic<bool>     m_ioBroken           {false};
    // NTIOLib activation-gate cache. Set true after the first successful
    // IOCTL_NTIO_ARM in this driver session; cleared by ResetIoBreaker
    // (which is called on Engine::Init after driver reload). Skips the
    // redundant ARM syscall on every idle-mode reopen.
    std::atomic<bool>     m_armed              {false};
    std::atomic<int>      m_failLogCounts[kFailLogSlots] {};

    // Set while Open()'s probe path is running. Suppresses NtioReadOnce's
    // handle-close-on-HandleStale side-effect so ArmScan/ReadScan still
    // see a live handle after the first probe returns err=6. Without this
    // guard the first failed probe closes m_hDevice, every subsequent
    // arm-scan variant runs against INVALID_HANDLE_VALUE, and the log
    // shows err=6 uniformly across 24 candidates — masking whatever the
    // driver actually thinks about them.
    std::atomic<bool>     m_openProbeInProgress {false};

    // Active read-primitive shape. ReadScan populates these when the
    // default (ioctl=0xC3506104, standard 16-byte request) is rejected
    // by this driver build. Rest of the hot path reads them per-call.
    static constexpr uint32_t kReadIoctls[2] = { 0xC3506104u, 0xC3506144u };
    std::atomic<uint8_t>  m_readIoctlIdx       {0};
    std::atomic<uint8_t>  m_readShapeIdx       {0};

    // Set by ReadIoctlSweep when it finds an IOCTL code that returns
    // ok=1 with the expected byte count for a physical-read probe. Non-
    // zero overrides kReadIoctls[m_readIoctlIdx] on the hot path so the
    // actual code the sweep discovered gets used for real reads. The
    // header's static-analysis-derived kReadIoctls table was for a
    // different build; live-fire on this MSI Center 2.0.35.0 image
    // shows 0xC3506104 returns STATUS_INVALID_HANDLE uniformly.
    std::atomic<uint32_t> m_readIoctlOverride  {0};
};
