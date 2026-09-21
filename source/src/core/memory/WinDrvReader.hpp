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

// CorsairLLAccess64.sys (Corsair Memory, Inc., v1.0.24.0, WHCP-signed).
// SHA256: 01E024D3C76FB1B71851AB7761AFBEE23159D6E8CBF7F5F1D5052EFCA2F7756D
// Signer: Corsair Components, Inc. via Microsoft Windows Third Party
//         Component CA 2014 → Microsoft Windows Hardware Compatibility
//         Publisher. WHQL Authenticode chain, timestamp cert good through
//         2029. Loads on stock Windows 11 with Secure Boot.
// Not on Microsoft's HVCI vulnerable-driver blocklist. Low profile — one
// public writeup from 2022, no LOLDrivers "commonly-abused" listing.
//
// Device path: dynamically built from the SERVICE name at DriverEntry —
// the driver reads its own DriverObject.DriverName (which starts with
// "\Driver\<ServiceName>") and constructs "\Device\<ServiceName>" +
// "\DosDevices\<ServiceName>". We register the service under our
// machine-stable hex name (see GetSvcName in main.cpp), so the user-mode
// path becomes "\\.\<hwkey>". Set at runtime via the shared helper.
//
// IRP_MJ_CREATE gate (verified against CREATE handler @ 0x1400010d0):
//   SeQueryInformationToken( TokenIntegrityLevel, ... ) →
//     token IntegrityLevel must be ≥ 0x3000 (SECURITY_MANDATORY_HIGH_RID)
//   otherwise STATUS_ACCESS_DENIED (0xC0000022). An elevated admin token
//   passes; standard user or non-elevated admin is denied. Our main()'s
//   IsElevated() check already enforces this upstream, so open just works.
//
// IOCTL surface (dispatch on raw IoControlCode, DeviceType 0x22):
//   0x225348  read op                        (unused here)
//   0x225358  I/O port read                  (unused here)
//   0x225374  MDL-based phys → user-VA map   (unused here, future opt)
//   0x22537C  version stub → 0x01000018      (unused here)
//   0x225388  MSR / thermal read op          (unused here)
//   0x22934C  ← WRITE phys memory (byte/word/dword, 32-bit PA)
//   0x229350  ← READ  phys memory (byte/word/dword, 32-bit PA)
//   0x229354  I/O port write                 (unused here)
//   0x229378  another read op                (unused here)
//   0x229380  PCI config write via HalSet    (unused here)
//   0x229384  another op                     (unused here)
//
// IOCTL 0x229350 primitive (verified @ 0x14000185c, dl = is_write flag = 0):
//   METHOD_BUFFERED. InputLength ≥ 0xC, OutputLength ≥ 0xA.
//   Input struct layout:
//     +0x00  uint32 phys_addr_low    ← 32-bit PA (upper bits forced to 0)
//     +0x04  uint32 phys_addr_high   ← ignored on read
//     +0x08  uint16 size             ← MUST be 1, 2, or 4
//     +0x0A  uint16 pad
//   Driver: MmMapIoSpace(PA, size, MmNonCached) → typed load (byte/word/dword)
//     → writes value to *IoStatus.Information (a pointer to IRP+0x38).
//   User side: DeviceIoControl returns TRUE and the read value comes back
//   via lpBytesReturned. Yes, "bytes returned" IS the data — unusual but
//   deliberate. IoStatus.Status = STATUS_SUCCESS on the happy path.
//
// Trade-offs vs. SIV / bsitf we tried:
//   + Simpler descriptor, no scatter/gather, no state-based reads
//   + Kernel-managed PT pages ARE mappable here (SIV refused them on 25H2)
//   + No SeSinglePrivilegeCheck gate (SIV's was the SeLoadDriverPrivilege
//     block that stopped us on 25H2 until we enabled the priv)
//   + No SMBIOS vendor gate (bsitf demanded ASUS motherboard, blocked MSI)
//   - 32-bit PA cap: fine for kernel PT pages on any typical Win11 box
//     (ntoskrnl PA seen at ~470 MB); the CR3 scan stays under 4 GB
//   - Read granularity 1/2/4 bytes: a 4 KB page fill costs 1024 IOCTLs
//     (same as the WDTKernel era before we found SIV's bulk mode)
#define IOCTL_CLL_READ_PHYS             0x229350u
#define IOCTL_CLL_WRITE_PHYS            0x22934Cu

// Minimum sizes required by the driver's dispatch (0x14000187b: cmp r8d,0xA;
// jb error). We always send 12 bytes to satisfy both InputLength ≥ 0xC and
// OutputLength ≥ 0xA. Individual read primitives never exceed 4 bytes so
// there is no ceiling to worry about beyond the size-{1,2,4} rule.
#define CLL_BUF_SIZE                    12u

#pragma pack(push, 1)
struct CllReadReq {
    uint32_t phys_lo;                  // IN — low 32 bits of physical address
    uint32_t phys_hi;                  // IN — must be 0 (driver ignores it on read)
    uint16_t size;                     // IN — must be 1, 2, or 4
    uint16_t pad;                      // IN — zero
};
static_assert(sizeof(CllReadReq) == 0x0C, "CLL read req size");
#pragma pack(pop)

// Corsair IOCTL 0x229350 return-contract summary (from disassembly):
//
//   Path                                     IoStatus.Status       Information
//   Success (byte/word/dword read)           STATUS_SUCCESS  (0)   = read value
//   MmMapIoSpace fail                        STATUS_INSUFFICIENT_  0
//                                              RESOURCES (0xC0000017)
//   size not in {1,2,4}                      STATUS_INVALID_       (unchanged)
//                                              PARAMETER (0xC000000D)
//   OutputLength < 10                        STATUS_INVALID_       0
//                                              BUFFER_SIZE (0xC0000023)
//   InputLength < size (read)                same as above         0
//   IRP_MJ_CREATE integrity < HIGH           STATUS_ACCESS_DENIED  (n/a: refused earlier)
//
// Win32 mapping seen at DeviceIoControl (ok=FALSE, err= these):
//   0xC0000017 INSUFFICIENT_RESOURCES → err = 8   (ERROR_NOT_ENOUGH_MEMORY)
//   0xC000000D INVALID_PARAMETER      → err = 87
//   0xC0000023 INVALID_BUFFER_SIZE    → err = 24  (ERROR_BAD_LENGTH)
//   0xC0000022 ACCESS_DENIED          → err = 5   (integrity or DACL)
//   Handle broken                    → err = 6   (INVALID_HANDLE)
//   Kernel low resources              → err = 1450 (NO_SYSTEM_RESOURCES)
//
// On success DeviceIoControl also puts the read value in `lpBytesReturned`.
// We ignore the `out` buffer contents and take the value from there.
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

    // Set the device path before Open(). Corsair's driver builds its
    // \Device\<name> at runtime from the service name (see the header
    // comment above), and our service name is machine-stable (see
    // main.cpp's GetSvcName()), so main.cpp computes both once and hands
    // them to us. Length-limited to keep the fallback GLOBALROOT and \?
    // variants short and stack-buildable.
    void SetDevicePath(const char* userModePath) {
        if (!userModePath) return;
        size_t n = strnlen(userModePath, sizeof(m_devicePath) - 1);
        memcpy(m_devicePath, userModePath, n);
        m_devicePath[n] = '\0';
    }
    const char* GetDevicePath() const {
        return m_devicePath[0] ? m_devicePath : "\\\\.\\CorsairLLAccess";
    }


    bool Open() {
        if (IsOpen()) return true;
        DBG_PRINT("[cll] Opening device...\n");
        // Try each (path, access) pair. First success wins.
        //   - GENERIC_READ|WRITE:       normal admin access
        //   - GENERIC_READ:             device with read-only DACL
        //   - SYNCHRONIZE / 0:          fallback for FILE_ANY_ACCESS IOCTLs
        //   - GLOBALROOT / global path: session-isolation fallback
        // Retries ERROR_FILE_NOT_FOUND (symlink publish race) up to 10x.
        const char* base = GetDevicePath();

        // Derive the two alternate spellings without heap allocation.
        // Base looks like "\\.\<name>"; extract <name> after "\\.\".
        const char* leaf = base;
        if (strncmp(base, "\\\\.\\", 4) == 0) leaf = base + 4;

        char pathGlobal[128] = {};
        snprintf(pathGlobal, sizeof(pathGlobal),
                 "\\\\.\\GLOBALROOT\\Device\\%s", leaf);

        struct Attempt { const char* path; DWORD access; };
        Attempt attempts[] = {
            { base,       GENERIC_READ | GENERIC_WRITE },
            { base,       GENERIC_READ                 },
            { base,       SYNCHRONIZE                  },
            { base,       0                            },
            { pathGlobal, GENERIC_READ | GENERIC_WRITE },
            { pathGlobal, 0                            },
        };
        DWORD lastErr = 0;
        for (int attempt = 0; attempt < 10 && m_hDevice == INVALID_HANDLE_VALUE; attempt++) {
            for (auto& a : attempts) {
                m_hDevice = CreateFileA(a.path,
                                        a.access,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, nullptr);
                if (m_hDevice != INVALID_HANDLE_VALUE) break;
                lastErr = GetLastError();
            }
            if (m_hDevice != INVALID_HANDLE_VALUE) break;
            if (lastErr != 2) break;   // only retry the not-found race
            Sleep(100);
        }
        if (m_hDevice == INVALID_HANDLE_VALUE) {
            DBG_PRINT("[cll] Failed to open device: err=%lu\n", lastErr);
            if (lastErr == 2)      DBG_PRINT("[cll]   (device not found -- driver not loaded or bad service name)\n");
            else if (lastErr == 5) DBG_PRINT("[cll]   (access denied -- token integrity < HIGH, or DACL blocks)\n");
            return false;
        }
        DBG_PRINT("[cll] Device opened: handle=0x%p\n", (void*)m_hDevice);

        // Probe IOCTL 0x229350 at PA=0x1000 with a 4-byte read. Corsair's
        // primitive is byte/word/dword only, so we use size=4 to prove
        // dispatch works end-to-end (input validation + MmMapIoSpace succeed
        // + read value comes back via lpBytesReturned).
        uint32_t probe = 0;
        bool ok = CllReadOnce(0x1000, 4, probe);

        if (!ok) {
            printf(skCrypt("[SysMonitor] CLL probe FAILED (err=%lu) -- driver up but IOCTL 0x229350 blocked\n"),
                   GetLastError());
            // Fail Open() so Engine::Init doesn't proceed with a broken
            // read path. Downstream cascade through CR3 resolution / module
            // discovery gives no clear diagnostic; failing here does.
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
            return false;
        }
        printf(skCrypt("[SysMonitor] CLL probe OK  PA=0x1000 dword -> 0x%08X\n"),
               (unsigned)probe);
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
    void SetIdleMode(bool enable) {
        m_idleMode = enable;
        if (enable && IsOpen()) {
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
        }
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
    // Under Corsair, SivReadPhys already handles size-1/2/4 chunking + PA
    // alignment internally, so this is just a straight forward. Kept as a
    // separate entry point so PhysRead()'s small-read path can bypass the
    // LRU slot fill without special-casing the caller.
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
            printf(skCrypt("[SysMonitor] SIV IOCTL 0x10 failed: %s  pa=0x%llX  size=%u  returned=%u  err=%lu\n"),
                   SivFailName(cls),
                   (unsigned long long)pa,
                   (unsigned)size,
                   (unsigned)returned,
                   (unsigned long)err);
        } else if (n == kIoFailLogCap) {
            printf(skCrypt("[SysMonitor] SIV IOCTL 0x10: further %s failures suppressed (cap=%d)\n"),
                   SivFailName(cls), kIoFailLogCap);
        }
    }

    // Single 1/2/4-byte physical read via Corsair IOCTL 0x229350.
    // Driver contract (verified @ 0x14000185c):
    //   - Input: CllReadReq (12 bytes) — phys_lo, phys_hi=0, size ∈ {1,2,4}
    //   - Output: DeviceIoControl's `lpBytesReturned` holds the read value
    //     (IoStatus.Information IS the payload — the OutputBuffer is used
    //     only to satisfy the OutputLength ≥ 10 gate; its contents are
    //     undefined on success).
    //
    // We synthesise 8/16/N-byte reads in SivReadPhys by chaining DWORD
    // IOCTLs. Idle mode still reopens the handle per call to keep the
    // process handle table clean between scans.
    //
    // Failure discipline (same shape as before):
    //   - Transient (err=1450) → retry once
    //   - Pipe-death (err=5/6, handle-failed) → count toward breaker
    //   - Per-PA rejections (MmMapIoSpace refused a specific address) →
    //     reset streak; the driver is alive, this address just isn't mappable
    bool CllReadOnce(uint64_t physAddr, uint16_t size, uint32_t& out_val) {
        if (size != 1 && size != 2 && size != 4) return false;
        if ((physAddr >> 32) != 0)               return false;  // driver drops upper bits

        if (m_ioBroken.load(std::memory_order_acquire)) return false;

        HANDLE hUse = INVALID_HANDLE_VALUE;
        bool   ownedOpen = false;
        if (m_idleMode) {
            EnterCriticalSection(&m_physLock);
            if (!IsOpen()) {
                m_hDevice = CreateFileA(GetDevicePath(),
                                        GENERIC_READ | GENERIC_WRITE,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, nullptr);
                ownedOpen = (m_hDevice != INVALID_HANDLE_VALUE);
            }
            hUse = m_hDevice;
            LeaveCriticalSection(&m_physLock);
            if (hUse == INVALID_HANDLE_VALUE) {
                NoteSivFail(SivFail::HandleFailed, physAddr, size, 0, GetLastError());
                return false;
            }
        } else {
            hUse = m_hDevice;
        }

        CllReadReq req{};
        req.phys_lo = (uint32_t)physAddr;
        req.phys_hi = 0;
        req.size    = size;
        req.pad     = 0;

        // OutputLength ≥ 10 gate. The driver never writes into OutputBuffer
        // for reads — the value comes back via IoStatus.Information — but
        // we still need to satisfy the size check. A stack DWORD would be
        // too small; use a small local sized to CLL_BUF_SIZE.
        uint8_t out_scratch[CLL_BUF_SIZE] = {};

        DWORD returned = 0;
        BOOL  ok = DeviceIoControl(hUse, IOCTL_CLL_READ_PHYS,
                                   &req, sizeof(req),
                                   out_scratch, sizeof(out_scratch),
                                   &returned, nullptr);

        // Corsair's Ok criterion: DeviceIoControl returned TRUE. `returned`
        // is the read value itself, not a byte count — so the SIV-style
        // `returned == size` gate does not apply here.
        SivFail cls;
        if (ok != FALSE) {
            cls = SivFail::Ok;
        } else {
            DWORD err = GetLastError();
            switch (err) {
                case 5:                                cls = SivFail::IoctlDenied;   break;
                case 6:                                cls = SivFail::HandleStale;   break;
                case 1: case 24: case 87: case 8:      cls = SivFail::IoctlRejected; break;
                case 1450:                             cls = SivFail::Transient;     break;
                default:                               cls = SivFail::UnknownError;  break;
            }
        }

        if (cls == SivFail::Transient) {
            Sleep(0);
            returned = 0;
            ok = DeviceIoControl(hUse, IOCTL_CLL_READ_PHYS,
                                 &req, sizeof(req),
                                 out_scratch, sizeof(out_scratch),
                                 &returned, nullptr);
            if (ok != FALSE) cls = SivFail::Ok;
        }

        if (ownedOpen) {
            EnterCriticalSection(&m_physLock);
            CloseHandle(m_hDevice); m_hDevice = INVALID_HANDLE_VALUE;
            LeaveCriticalSection(&m_physLock);
        }

        if (cls == SivFail::Ok) {
            out_val = returned;
            m_ioFailStreak.store(0, std::memory_order_release);
            return true;
        }

        NoteSivFail(cls, physAddr, size, returned, GetLastError());
        if (IsPipeDeath(cls)) {
            int streak = m_ioFailStreak.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (streak >= kIoFailStreakBreaker) {
                if (!m_ioBroken.exchange(true, std::memory_order_acq_rel)) {
                    printf(skCrypt("[SysMonitor] Corsair driver pipe dead (%d consecutive %s failures) — fast-failing further reads. Reset via WinDrvReader::Get().ResetIoBreaker() after re-loading.\n"),
                           streak, SivFailName(cls));
                }
            }
        } else {
            m_ioFailStreak.store(0, std::memory_order_release);
        }
        return false;
    }

    // Arbitrary-size physical read layered on top of CllReadOnce.
    // The driver only supports 1/2/4-byte primitives, so we chain DWORDs
    // and use size-2 / size-1 fills for the trailing 1..3 bytes. Keeps
    // the caller-visible signature identical to the SIV era.
    bool SivReadPhys(uint64_t physAddr, void* out, size_t size) {
        if (!out || size == 0) {
            NoteSivFail(SivFail::BadArgs, physAddr, (DWORD)size, 0, 0);
            return false;
        }
        if ((physAddr + size - 1) >> 32) {
            // Corsair's IOCTL 0x229350 caps PAs at 32 bits. On the ESP hot
            // path CR3 candidates and kernel PT pages sit well under 4 GB,
            // so this only triggers on genuinely out-of-range requests.
            NoteSivFail(SivFail::BadArgs, physAddr, (DWORD)size, 0, 0);
            return false;
        }

        uint8_t* dst = reinterpret_cast<uint8_t*>(out);
        size_t   done = 0;
        while (done < size) {
            size_t   remain = size - done;
            uint64_t pa     = physAddr + done;
            uint32_t val    = 0;

            if (remain >= 4 && (pa & 3ULL) == 0) {
                if (!CllReadOnce(pa, 4, val)) return false;
                memcpy(dst + done, &val, 4);
                done += 4;
            } else if (remain >= 2 && (pa & 1ULL) == 0) {
                if (!CllReadOnce(pa, 2, val)) return false;
                uint16_t v16 = (uint16_t)val;
                memcpy(dst + done, &v16, 2);
                done += 2;
            } else {
                if (!CllReadOnce(pa, 1, val)) return false;
                dst[done] = (uint8_t)val;
                done += 1;
            }
        }
        return true;
    }

    // Fills a 4KB physical page. Corsair's primitive caps at 4-byte reads,
    // so this costs 1024 DWORD IOCTLs per page (same order as the WDTKernel
    // era). CS2's hot working set is largely served by the 128-slot LRU in
    // PhysRead(), so the per-page cost only bites on cold misses.
    bool SivReadPage(uint64_t pagePA, uint8_t out[4096]) {
        pagePA &= ~0xFFFULL;
        if (!out || reinterpret_cast<uintptr_t>(out) < 0x10000ULL) return false;

        // Corsair's IOCTL 0x229350 caps PAs at 32 bits — reject page-aligned
        // PAs beyond 4 GB up front to avoid 1024 wasted IOCTLs.
        if (pagePA + 0xFFFULL >> 32) return false;

        // PA blacklist: skip pages that have failed before. Miss once, skip forever.
        for (int i = 0; i < kBadPaCount; i++)
            if (m_badPAs[i] && m_badPAs[i] == pagePA) return false;

        // Serialise so one thread's DWORD stream isn't interleaved with
        // another's. Not strictly required for correctness (each IOCTL is
        // self-contained) but keeps driver-side mapping-cache locality clean.
        EnterCriticalSection(&m_ioctlLock);
        bool ok = true;
        for (uint32_t off = 0; off < 4096; off += 4) {
            uint32_t val = 0;
            if (!CllReadOnce(pagePA + off, 4, val)) { ok = false; break; }
            memcpy(out + off, &val, 4);
        }
        if (!ok) {
            static bool s_logged = false;
            if (!s_logged) {
                s_logged = true;
                printf(skCrypt("[SysMonitor] CLL page read failed: err=%lu (PA=0x%llX)\n"),
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

    // 128 × 4KB = 512 KB of cached physical pages. WDTKernel needed 512 slots
    // because a cold page fill cost 512+ IOCTLs — thrash on eviction was
    // catastrophic. SIV fills a page in ONE IOCTL, so the driver-side
    // mapping cache and this LRU together already dominate the WDT-era 512
    // configuration; 128 fits comfortably in a Zen3 L2 (5700x has 512 KB
    // per core) with room to spare and cuts steady-state RAM by 1.5 MB.
    static constexpr int kPhysPageCacheN = 128;
    struct PhysPageEntry { uint64_t pa; uint8_t data[4096]; };

    bool            m_idleMode         = false;
    HANDLE          m_hDevice          = INVALID_HANDLE_VALUE;
    // Device path — set by main.cpp via SetDevicePath() before Open() so
    // the runtime can match whatever service name we registered. Corsair
    // builds \Device\<svcname> at load, so keeping this in sync is what
    // makes the driver openable at all.
    char            m_devicePath[64]   = {};
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
    std::atomic<int>      m_failLogCounts[kFailLogSlots] {};
};
