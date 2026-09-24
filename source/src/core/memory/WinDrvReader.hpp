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
#include <chrono>
#include <thread>
#include <mutex>
#include <skCrypter/skCrypter.hpp>
#include "../../../payload/payload_shared.h"

// WinDrvReader — user-mode client for the manual-mapped kernel payload.
//
// The payload lives in kernel memory (mapped by kdmapper via iqvw64e.sys
// exploit) and exposes a single named shared section:
//     Global\Xh7Km2p9Qr4tZ8
//
// This client opens that section and drives it via a spin-poll wire
// protocol (see payload_shared.h). All reads/writes against CS2 go
// through KeStackAttachProcess + RtlCopyMemory inside the payload; no
// physical memory, no MmMapIoSpace, no \Device\PhysicalMemory. The
// launcher never holds a handle to cs2.exe — only the payload does
// (via PEPROCESS obtained from PsLookupProcessByProcessId).
//
// Compat surface: preserves every method the rest of the codebase calls
// (Memory.cpp, Engine.cpp, Cache.cpp, main.cpp) so no downstream changes
// are needed. Methods that were physical-memory-specific (CR3 resolve,
// VirtualToPhysical, PhysRead) become identity/pass-through stubs because
// the payload does VA translation kernel-side.

// Failure classification kept for the log-cap machinery downstream.
enum class SivFail : uint8_t {
    Ok            = 0,
    BadArgs       = 1,
    HandleFailed  = 2,
    IoctlDenied   = 3,
    IoctlRejected = 4,
    HandleStale   = 5,
    Transient     = 6,
    PartialReturn = 7,
    UnknownError  = 8,
};

class WinDrvReader {
public:
    static WinDrvReader& Get() {
        static WinDrvReader instance;
        return instance;
    }

    // === Lifecycle ===

    // Open the shared section produced by the payload. Assumes the payload
    // is already mapped — main.cpp is responsible for invoking the mapper
    // before calling this, and for retry loops around initial section
    // availability.
    bool Open() {
        if (IsOpen()) return true;
        HANDLE h = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, PAYLOAD_SECTION_NAME);
        if (!h) {
            DWORD err = GetLastError();
            printf(skCrypt("[SysMonitor] payload section not found (err=%lu) -- mapper didn't run or payload crashed\n"),
                   (unsigned long)err);
            return false;
        }
        void* view = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, PAYLOAD_SECTION_SIZE);
        if (!view) {
            DWORD err = GetLastError();
            printf(skCrypt("[SysMonitor] MapViewOfFile failed err=%lu\n"), (unsigned long)err);
            CloseHandle(h);
            return false;
        }
        m_section = h;
        m_shared  = (payload_shared_t*)view;

        // Verify the payload initialized the section (magic set in DriverEntry).
        if (m_shared->magic != PAYLOAD_MAGIC) {
            printf(skCrypt("[SysMonitor] payload section present but magic wrong (0x%08X) -- payload not initialized\n"),
                   (unsigned)m_shared->magic);
            Close();
            return false;
        }
        printf(skCrypt("[SysMonitor] payload section opened, magic OK\n"));

        // Ping to confirm the reader thread is alive.
        if (!ping()) {
            printf(skCrypt("[SysMonitor] payload ping timeout -- reader thread dead?\n"));
            Close();
            return false;
        }
        printf(skCrypt("[SysMonitor] payload ping OK\n"));
        return true;
    }

    void Close() {
        if (m_shared) {
            UnmapViewOfFile(m_shared);
            m_shared = nullptr;
        }
        if (m_section) {
            CloseHandle(m_section);
            m_section = nullptr;
        }
        m_attached_pid = 0;
        m_cachedPebVA  = 0;
    }

    bool IsOpen() const {
        return m_shared != nullptr && m_section != nullptr;
    }

    bool IsIdleMode() const { return false; }
    void SetIdleMode(bool /*enable*/) { /* no-op — section is invisible enough */ }

    void FlushDriverTable() {}
    void ClearPhysPageCache() {}

    void ResetIoBreaker() {
        m_ioBroken.store(false, std::memory_order_release);
    }

    bool IsIoBroken() const {
        return m_ioBroken.load(std::memory_order_acquire);
    }

    // === Target attach ===

    // Point the payload's cached PEPROCESS at CS2. Subsequent reads go
    // against this process's VA space.
    bool AttachProcess(uint32_t pid) {
        if (!IsOpen()) return false;
        if (m_attached_pid == pid) return true;
        if (!submit(PAYLOAD_OP_ATTACH_PID, /*va*/ 0, /*size*/ 0, pid)) return false;
        m_attached_pid = pid;
        m_cachedPebVA  = 0;   // invalidate on target change
        return true;
    }

    // === Read primitives ===

    // The "cr3" parameter is a legacy from the physical-memory backend.
    // With the payload backend, it's ignored — kernel does the translation.
    bool ReadVirtual(uint64_t /*cr3*/, uint64_t va, void* buffer, size_t size) {
        if (!IsOpen() || !buffer || size == 0) return false;
        uint8_t* dst = (uint8_t*)buffer;
        size_t   done = 0;
        while (done < size) {
            size_t chunk = std::min<size_t>(size - done, PAYLOAD_DATA_MAX);
            if (!submit(PAYLOAD_OP_READ_VIRTUAL, va + done, (uint32_t)chunk, 0))
                return false;
            memcpy(dst + done, (void*)m_shared->data, chunk);
            done += chunk;
        }
        return true;
    }

    // Cache passthrough — with this backend cross-page cache tracking of
    // VA→PA mappings is pointless (kernel does the translation for us).
    // Just forward to ReadVirtual and ignore the cache vector.
    bool ReadVirtualCached(uint64_t cr3, uint64_t va, void* buffer, size_t size,
                            std::vector<std::pair<uint64_t,uint64_t>>& /*cache*/) {
        return ReadVirtual(cr3, va, buffer, size);
    }

    // "Physical" reads under this backend just forward to ReadVirtual; the
    // page cache in Memory.cpp calls PhysRead(pa,...) after VirtualToPhysical
    // returned the VA identity. Keeping the compat lets that code work
    // unmodified.
    bool PhysRead(uint64_t addr, void* buffer, size_t size) {
        return ReadVirtual(/*cr3*/ 0, addr, buffer, size);
    }

    bool ReadPhysDirect(uint64_t addr, void* buffer, size_t size) {
        return ReadVirtual(/*cr3*/ 0, addr, buffer, size);
    }

    // Identity: caller passes a VA, we hand the VA back so subsequent
    // PhysRead(pa, ...) calls hit the same VA via ReadVirtual.
    uint64_t VirtualToPhysical(uint64_t /*cr3*/, uint64_t va) { return va; }

    // === Legacy CR3/EPROCESS surface (stubs) ===

    uint64_t GetKernelBase() const { return 0; }
    uint64_t GetSystemCr3()  const { return 1; }
    bool     IsCr3Resolved() const { return m_attached_pid != 0; }
    bool     ResolveSystemCr3() { return true; }

    uint64_t GetProcessCr3(uint32_t pid) {
        return AttachProcess(pid) ? 1 : 0;
    }
    uint64_t GetCr3ForProcess(uint32_t pid) {
        return AttachProcess(pid) ? 1 : 0;
    }
    uint64_t GetCs2EprocessVA() const { return 1; }

    // === Module discovery via PEB walk ===

    // Walks CS2's PEB InMemoryOrderModuleList looking for `moduleName`.
    // Under this backend the "physical" return is really the module's VA
    // in CS2's address space — the Memory.cpp callers treat it opaquely
    // as a base pointer and pass it back for reads, which works because
    // ReadVirtual is VA-based now.
    uint64_t GetModuleBasePhysical(uint64_t /*cr3*/, const wchar_t* moduleName,
                                    uint32_t* outSize) {
        if (outSize) *outSize = 0;
        if (!IsOpen() || !m_attached_pid) return 0;

        uint64_t peb = get_peb_cached();
        if (!peb) return 0;

        // PEB.Ldr at +0x18
        uint64_t ldr = 0;
        if (!ReadVirtual(0, peb + 0x18, &ldr, 8) || !ldr) return 0;

        // PEB_LDR_DATA.InMemoryOrderModuleList at +0x20
        uint64_t list_head = ldr + 0x20;
        uint64_t flink = 0;
        if (!ReadVirtual(0, list_head, &flink, 8) || !flink || flink == list_head) return 0;

        for (int i = 0; i < 512 && flink && flink != list_head; i++) {
            // InMemoryOrderLinks is at +0x10 in LDR_DATA_TABLE_ENTRY
            uint64_t entry = flink - 0x10;

            uint64_t dll_base = 0;
            if (!ReadVirtual(0, entry + 0x30, &dll_base, 8) || !dll_base) {
                if (!ReadVirtual(0, flink, &flink, 8)) break;
                continue;
            }

            uint16_t name_len = 0;
            uint64_t name_buf = 0;
            ReadVirtual(0, entry + 0x48, &name_len, 2);
            ReadVirtual(0, entry + 0x50, &name_buf, 8);
            if (!name_len || !name_buf || name_len > 512) {
                if (!ReadVirtual(0, flink, &flink, 8)) break;
                continue;
            }

            wchar_t name[257] = {};
            uint16_t rlen = (name_len < (uint16_t)(sizeof(name) - 2))
                          ? name_len : (uint16_t)(sizeof(name) - 2);
            if (ReadVirtual(0, name_buf, name, rlen)) {
                // Compare basename only.
                const wchar_t* base = wcsrchr(name, L'\\');
                base = base ? base + 1 : name;
                if (_wcsicmp(base, moduleName) == 0) {
                    if (outSize) {
                        uint32_t sz = 0;
                        ReadVirtual(0, entry + 0x40, &sz, 4);   // SizeOfImage
                        *outSize = sz;
                    }
                    return dll_base;
                }
            }

            if (!ReadVirtual(0, flink, &flink, 8)) break;
        }
        return 0;
    }

    // Legacy names — some code paths call these directly.
    uint64_t FindModuleBasePhysical(uint64_t cr3, const wchar_t* moduleName,
                                     uint32_t* outSize = nullptr) {
        return GetModuleBasePhysical(cr3, moduleName, outSize);
    }
    uint64_t FindModuleViaVAD(uint64_t cr3, uint64_t /*eprocess*/,
                               const wchar_t* moduleName,
                               uint32_t* outSize = nullptr,
                               uint64_t* /*outLargeCand*/ = nullptr,
                               uint32_t* /*outLargeCandSize*/ = nullptr) {
        return GetModuleBasePhysical(cr3, moduleName, outSize);
    }
    uint64_t FindModuleViaBulkPTScan(uint64_t cr3, const wchar_t* moduleName,
                                      uint32_t* outSize) {
        return GetModuleBasePhysical(cr3, moduleName, outSize);
    }

    // === Device path stubs (kept for source compat) ===
    void SetDevicePath(const char* /*userModePath*/) {}
    const char* GetDevicePath() const { return "\\\\.\\payload"; }

private:
    WinDrvReader() {
        InitializeCriticalSection(&m_lock);
    }
    ~WinDrvReader() {
        Close();
        DeleteCriticalSection(&m_lock);
    }
    WinDrvReader(const WinDrvReader&) = delete;
    WinDrvReader& operator=(const WinDrvReader&) = delete;

    bool ping() {
        return submit(PAYLOAD_OP_PING, 0, 0, 0);
    }

    uint64_t get_peb_cached() {
        if (m_cachedPebVA) return m_cachedPebVA;
        if (!submit(PAYLOAD_OP_GET_PEB, 0, 0, 0)) return 0;
        uint64_t peb = *(const uint64_t*)m_shared->data;
        m_cachedPebVA = peb;
        return peb;
    }

    // Send a request and spin-wait for completion. Uses the class's
    // critical section for user-side serialization so multi-threaded
    // callers (cache thread + ESP thread + trigger thread) don't
    // interleave requests on the single shared slot.
    bool submit(uint32_t op, uint64_t va, uint32_t size, uint32_t pid) {
        if (!IsOpen()) return false;
        EnterCriticalSection(&m_lock);

        m_shared->op         = op;
        m_shared->target_va  = va;
        m_shared->size       = size;
        m_shared->target_pid = pid;
        m_shared->status     = 0;

        // Signal REQUEST.
        InterlockedExchange(&m_shared->state, PAYLOAD_STATE_REQUEST);

        // Spin-wait for DONE. Bounded so a dead payload doesn't hang us
        // forever.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        LONG s;
        while ((s = InterlockedCompareExchange(&m_shared->state, 0, 0)) != PAYLOAD_STATE_DONE) {
            if (std::chrono::steady_clock::now() > deadline) {
                LeaveCriticalSection(&m_lock);
                m_ioBroken.store(true, std::memory_order_release);
                printf(skCrypt("[SysMonitor] payload request timeout (op=%u, state=%d)\n"),
                       (unsigned)op, (int)s);
                return false;
            }
            YieldProcessor();
        }

        int32_t status = m_shared->status;
        // Clear back to IDLE for the next round.
        InterlockedExchange(&m_shared->state, PAYLOAD_STATE_IDLE);
        LeaveCriticalSection(&m_lock);
        return status >= 0;   // NT_SUCCESS(status)
    }

    HANDLE            m_section      = nullptr;
    payload_shared_t* m_shared       = nullptr;
    CRITICAL_SECTION  m_lock         = {};
    uint32_t          m_attached_pid = 0;
    uint64_t          m_cachedPebVA  = 0;
    std::atomic<bool> m_ioBroken     {false};
};
