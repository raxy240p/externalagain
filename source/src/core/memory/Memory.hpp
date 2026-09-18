#ifndef _PPROCESS_HPP_
#define _PPROCESS_HPP_
#include "core/debug.hpp"

#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <memory>
#include <algorithm>
#include <atomic>
#include <thread>
#include "WinDrvReader.hpp"

struct ProcessModule {
    uintptr_t base, size;
};

class pProcess {
public:
    DWORD    pid_    = 0;
    HANDLE   handle_ = nullptr;
    HWND     hwnd_   = nullptr;
    ProcessModule base_client_{};

    ~pProcess() { Close(); }

    bool AttachProcess(const char* process_name);
    bool AttachWindow(const char* window_name);
    bool UpdateHWND();
    void Close();

    HWND      GetWindowHandleFromProcessId(DWORD ProcessId);
    LPVOID    Allocate(size_t size_in_bytes);
    uintptr_t FindCodeCave(uint32_t length_in_bytes);

    uintptr_t FindSignature(std::vector<uint8_t> signature);
    uintptr_t FindSignature(ProcessModule target_module, std::vector<uint8_t> signature);

    template<class T>
    uintptr_t ReadOffsetFromSignature(std::vector<uint8_t> signature, uint8_t offset) {
        uintptr_t pattern_address = this->FindSignature(signature);
        if (!pattern_address) return 0x0;
        T offset_value = this->read<T>(pattern_address + offset);
        return pattern_address + offset_value + offset + sizeof(T);
    }

    // Physical read — uncached, use for one-off reads (startup, signature scans).
    bool read_raw(uintptr_t address, void* buffer, size_t size);

    // Physical read with VA→PA page cache.
    // First access to a page: 4-level walk (12 IOCTLs) + PhysRead (3 IOCTLs) = 15.
    // All subsequent accesses to the same page: PhysRead only (3 IOCTLs).
    // Use for hot runtime reads (pawn, controller, bones, view matrix).
    bool read_raw_cached(uintptr_t address, void* buffer, size_t size);

    // Like read_raw_cached but stops at the first unreadable page and returns
    // the number of bytes successfully read. Use when later pages of a struct
    // may be unmapped (e.g. some pawn VA alignments put the 3rd physical page
    // of a 0x1D00-byte read spans an unreadable physical page).
    size_t read_raw_partial(uintptr_t address, void* buffer, size_t size);

    // Invalidate the PA cache (e.g. on game restart / CR3 change).
    void ClearPaCache() {
        m_paCacheCount.store(0, std::memory_order_release);
        m_vmCachedPagePA = 0;
    }

    // Remove specific pages from the cache so the next access re-walks the page table.
    // Use when reads succeed physically but return garbage (stale PA after pawn remap).
    void InvalidatePaCacheRange(uint64_t va, size_t size) {
        int n = m_paCacheCount.load(std::memory_order_acquire);
        if (n > kPaCacheSize) n = kPaCacheSize;
        uint64_t first = va & ~0xFFFULL;
        uint64_t last  = (va + size - 1) & ~0xFFFULL;
        for (int i = 0; i < n; i++) {
            uint64_t e = m_paCache[i].va;
            if (e >= first && e <= last) {
                m_paCache[i].va = 0;
                m_paCache[i].pa = 0;
            }
        }
    }

    // Single-page fast read with its own cached PA (for the view matrix page).
    bool read_page_fast(uintptr_t va, void* out, size_t size);

    void PrintPaCacheStats() const {
        int n = m_paCacheCount.load(std::memory_order_acquire);
        if (n > kPaCacheSize) n = kPaCacheSize;
        int valid = 0, blocked = 0, retryable = 0;
        for (int i = 0; i < n; i++) {
            uint64_t pa = m_paCache[i].pa;
            if (pa == ~0ULL)  blocked++;
            else if (pa == 0) retryable++;
            else              valid++;
        }
        DBG_PRINT("[PACache] %d/%d used  valid=%d  retryable=%d  blocked(~0)=%d\n",
               n, kPaCacheSize, valid, retryable, blocked);
    }

    template<class T>
    T read(uintptr_t address) {
        T buffer{};
        read_raw(address, &buffer, sizeof(T));
        return buffer;
    }

    uintptr_t read_multi_address(uintptr_t ptr, std::vector<uintptr_t> offsets) {
        uintptr_t buffer = ptr;
        for (size_t i = 0; i < offsets.size(); i++)
            buffer = this->read<uintptr_t>(buffer + offsets[i]);
        return buffer;
    }

    template <typename T>
    T read_multi(uintptr_t base, std::vector<uintptr_t> offsets) {
        uintptr_t buffer = base;
        for (size_t i = 0; i < offsets.size() - 1; i++)
            buffer = this->read<uintptr_t>(buffer + offsets[i]);
        return this->read<T>(buffer + offsets.back());
    }

    uint64_t m_cachedCr3 = 0;

private:
    // VA→PA page cache — add-only, lock-free on x86/x64 (stores finalized before count bumped).
    static const int kPaCacheSize = 512;
    struct PaEntry { uint64_t va; uint64_t pa; };
    PaEntry              m_paCache[kPaCacheSize]{};
    std::atomic<int>     m_paCacheCount{0};

    uint64_t m_vmCachedPagePA = 0;

    uint32_t FindProcessIdByProcessName(const char* process_name);
    uint32_t FindProcessIdByWindowName(const char* window_name);
};

#endif
