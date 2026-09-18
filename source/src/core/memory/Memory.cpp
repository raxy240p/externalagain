#include "Memory.hpp"
#include <tlhelp32.h>
#include <lazy_importer/lazy_importer.hpp>
#include "core/anti_debug/AntiDebug.hpp"

uint32_t pProcess::FindProcessIdByProcessName(const char* ProcessName) {
    std::wstring wideName(ProcessName, ProcessName + strlen(ProcessName));
    using PFN_Snap  = HANDLE(WINAPI*)(DWORD, DWORD);
    using PFN_ProcW = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
    static auto pfSnap  = (PFN_Snap) li::detail::resolve(0x185776B5u);
    static auto pfFirst = (PFN_ProcW)li::detail::resolve(0x0E81B808u);
    static auto pfNext  = (PFN_ProcW)li::detail::resolve(0xABE5123Fu);
    HANDLE snapshot = pfSnap(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    DWORD pid = 0;
    if (pfFirst(snapshot, &pe)) {
        do {
            if (wideName == pe.szExeFile) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (pfNext(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return pid;
}

uint32_t pProcess::FindProcessIdByWindowName(const char* WindowName) {
    DWORD pid = 0;
    using FFWA = HWND(WINAPI*)(LPCSTR, LPCSTR);
    using FGWTPID = DWORD(WINAPI*)(HWND, LPDWORD);
    auto pFindWindowA = reinterpret_cast<FFWA>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("FindWindowA")));
    auto pGetWindowThreadProcessId = reinterpret_cast<FGWTPID>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("GetWindowThreadProcessId")));
    HWND hwnd = pFindWindowA(nullptr, WindowName);
    if (hwnd) pGetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

HWND pProcess::GetWindowHandleFromProcessId(DWORD ProcessId) {
    using FFWE = HWND(WINAPI*)(HWND, HWND, LPCSTR, LPCSTR);
    using FGWTPID = DWORD(WINAPI*)(HWND, LPDWORD);
    auto pFindWindowEx = reinterpret_cast<FFWE>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("FindWindowEx")));
    auto pGetWindowThreadProcessId = reinterpret_cast<FGWTPID>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("GetWindowThreadProcessId")));
    HWND hwnd = nullptr;
    do {
        hwnd = pFindWindowEx(nullptr, hwnd, nullptr, nullptr);
        DWORD pid = 0;
        pGetWindowThreadProcessId(hwnd, &pid);
        if (pid == ProcessId) {
            TCHAR title[MAX_PATH];
            GetWindowText(hwnd, title, MAX_PATH);
            if (IsWindowVisible(hwnd) && title[0]) return hwnd;
        }
    } while (hwnd);
    return nullptr;
}

bool pProcess::AttachProcess(const char* ProcessName) {
    pid_ = FindProcessIdByProcessName(ProcessName);
    if (!pid_) return false;
    handle_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid_);
    hwnd_ = GetWindowHandleFromProcessId(pid_);
    return true;
}

bool pProcess::AttachWindow(const char* WindowName) {
    pid_ = FindProcessIdByWindowName(WindowName);
    if (!pid_) return false;
    hwnd_ = GetWindowHandleFromProcessId(pid_);
    return true;
}

bool pProcess::UpdateHWND() {
    hwnd_ = GetWindowHandleFromProcessId(pid_);
    return hwnd_ != nullptr;
}


LPVOID pProcess::Allocate(size_t size_in_bytes) {
    if (!pid_) return nullptr;
    using FVAE = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    auto pVirtualAllocEx = reinterpret_cast<FVAE>(AntiDebug::ResolveExport(AntiDebug::Fnv1a("VirtualAllocEx")));
    if (!pVirtualAllocEx) return nullptr;
    if (handle_) {
        LPVOID r = pVirtualAllocEx(handle_, nullptr, size_in_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (r) return r;
    }
    HANDLE tmp = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid_);
    if (!tmp) return nullptr;
    LPVOID r = pVirtualAllocEx(tmp, nullptr, size_in_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CloseHandle(tmp);
    return r;
}

uintptr_t pProcess::FindSignature(std::vector<uint8_t> signature) {
    if (!base_client_.base || !base_client_.size) return 0;
    constexpr size_t kPage = 0x1000;
    auto data = std::make_unique<uint8_t[]>(base_client_.size);
    memset(data.get(), 0, base_client_.size);
    for (size_t off = 0; off < base_client_.size; off += kPage)
        read_raw(base_client_.base + off, data.get() + off, std::min(kPage, base_client_.size - off));
    if (signature.size() > base_client_.size) return 0;
    for (uintptr_t i = 0; i < base_client_.size - signature.size(); i++) {
        bool found = true;
        for (size_t j = 0; j < signature.size(); j++) {
            if (signature[j] != 0x00 && signature[j] != data[i + j]) {
                found = false;
                break;
            }
        }
        if (found) return base_client_.base + i;
    }
    return 0;
}

uintptr_t pProcess::FindSignature(ProcessModule target_module, std::vector<uint8_t> signature) {
    if (!target_module.base || !target_module.size) return 0;
    constexpr size_t kPage = 0x1000;
    auto data = std::make_unique<uint8_t[]>(target_module.size);
    memset(data.get(), 0, target_module.size);
    for (size_t off = 0; off < target_module.size; off += kPage)
        read_raw(target_module.base + off, data.get() + off, std::min(kPage, target_module.size - off));
    if (signature.size() > target_module.size) return 0;
    for (uintptr_t i = 0; i < target_module.size - signature.size(); i++) {
        bool found = true;
        for (size_t j = 0; j < signature.size(); j++) {
            if (signature[j] != 0x00 && signature[j] != data[i + j]) {
                found = false;
                break;
            }
        }
        if (found) return target_module.base + i;
    }
    return 0;
}

uintptr_t pProcess::FindCodeCave(uint32_t length_in_bytes) {
    std::vector<uint8_t> cave_pattern(length_in_bytes, 0x00);
    return FindSignature(cave_pattern);
}

void pProcess::Close() {
    if (handle_) CloseHandle(handle_);
    handle_ = nullptr;
}


bool pProcess::read_raw(uintptr_t address, void* buffer, size_t size) {
    auto& drv = WinDrvReader::Get();
    if (!m_cachedCr3) return false;
    if (!drv.IsOpen() && !drv.IsIdleMode()) return false;
    return drv.ReadVirtual(m_cachedCr3, address, buffer, size);
}

bool pProcess::read_raw_cached(uintptr_t address, void* buffer, size_t size) {
    auto& drv = WinDrvReader::Get();
    if (!m_cachedCr3) return false;
    if (!drv.IsOpen() && !drv.IsIdleMode()) return false;

    uint8_t* dst  = (uint8_t*)buffer;
    size_t   done = 0;
    uint64_t va   = address;

    while (done < size) {
        uint64_t pageBase = va & ~0xFFFULL;
        uint64_t offset   = va - pageBase;
        size_t   chunk    = (std::min)(size - done, (size_t)(0x1000 - offset));

        uint64_t pa = 0;
        int cache_idx = -1;
        int n = m_paCacheCount.load(std::memory_order_acquire);
        if (n > kPaCacheSize) n = kPaCacheSize;
        for (int i = 0; i < n; i++) {
            if (m_paCache[i].va == pageBase) {
                pa = m_paCache[i].pa;
                cache_idx = i;
                break;
            }
        }

        if (pa == ~0ULL) return false;

        if (!pa) {
            pa = drv.VirtualToPhysical(m_cachedCr3, pageBase);
            if (!pa) return false;
            if (cache_idx >= 0) {
                m_paCache[cache_idx].pa = pa;
            } else {
                // Prefer reusing a slot vacated by InvalidatePaCacheRange (va==0)
                // over always appending — prevents the cache from filling permanently.
                int slot = -1;
                {
                    int n_now = m_paCacheCount.load(std::memory_order_acquire);
                    if (n_now > kPaCacheSize) n_now = kPaCacheSize;
                    for (int i = 0; i < n_now; i++) {
                        if (m_paCache[i].va == 0) { slot = i; break; }
                    }
                }
                if (slot < 0) {
                    int appended = m_paCacheCount.fetch_add(1, std::memory_order_relaxed);
                    if (appended < kPaCacheSize) slot = appended;
                }
                if (slot >= 0) {
                    m_paCache[slot].va = pageBase;
                    m_paCache[slot].pa = pa;
                    cache_idx = slot;
                }
            }
            std::atomic_thread_fence(std::memory_order_release);
        }

        if (!drv.PhysRead(pa + offset, dst + done, chunk)) {
            if (cache_idx >= 0)
                m_paCache[cache_idx].pa = 0;
            else {
                int n2 = m_paCacheCount.load(std::memory_order_acquire);
                if (n2 > kPaCacheSize) n2 = kPaCacheSize;
                for (int i = 0; i < n2; i++)
                    if (m_paCache[i].va == pageBase) { m_paCache[i].pa = 0; break; }
            }
            return false;
        }
        done += chunk;
        va = pageBase + 0x1000;
    }
    return true;
}

size_t pProcess::read_raw_partial(uintptr_t address, void* buffer, size_t size) {
    auto& drv = WinDrvReader::Get();
    if (!m_cachedCr3) return 0;
    if (!drv.IsOpen() && !drv.IsIdleMode()) return 0;

    uint8_t* dst  = (uint8_t*)buffer;
    size_t   done = 0;
    uint64_t va   = address;

    while (done < size) {
        uint64_t pageBase = va & ~0xFFFULL;
        uint64_t offset   = va - pageBase;
        size_t   chunk    = (std::min)(size - done, (size_t)(0x1000 - offset));

        uint64_t pa = 0;
        int cache_idx = -1;
        int n = m_paCacheCount.load(std::memory_order_acquire);
        if (n > kPaCacheSize) n = kPaCacheSize;
        for (int i = 0; i < n; i++) {
            if (m_paCache[i].va == pageBase) {
                pa = m_paCache[i].pa;
                cache_idx = i;
                break;
            }
        }

        if (pa == ~0ULL) break;

        if (!pa) {
            pa = drv.VirtualToPhysical(m_cachedCr3, pageBase);
            if (!pa) break;
            if (cache_idx >= 0) {
                m_paCache[cache_idx].pa = pa;
            } else {
                int slot = -1;
                {
                    int n_now = m_paCacheCount.load(std::memory_order_acquire);
                    if (n_now > kPaCacheSize) n_now = kPaCacheSize;
                    for (int i = 0; i < n_now; i++) {
                        if (m_paCache[i].va == 0) { slot = i; break; }
                    }
                }
                if (slot < 0) {
                    int appended = m_paCacheCount.fetch_add(1, std::memory_order_relaxed);
                    if (appended < kPaCacheSize) slot = appended;
                }
                if (slot >= 0) {
                    m_paCache[slot].va = pageBase;
                    m_paCache[slot].pa = pa;
                    cache_idx = slot;
                }
            }
            std::atomic_thread_fence(std::memory_order_release);
        }

        if (!drv.PhysRead(pa + offset, dst + done, chunk)) {
            if (cache_idx >= 0)
                m_paCache[cache_idx].pa = 0;
            else {
                int n2 = m_paCacheCount.load(std::memory_order_acquire);
                if (n2 > kPaCacheSize) n2 = kPaCacheSize;
                for (int i = 0; i < n2; i++)
                    if (m_paCache[i].va == pageBase) { m_paCache[i].pa = 0; break; }
            }
            break;
        }
        done += chunk;
        va = pageBase + 0x1000;
    }
    return done;
}

bool pProcess::read_page_fast(uintptr_t va, void* out, size_t size) {
    auto& drv = WinDrvReader::Get();
    if (!m_cachedCr3) return false;
    if (!drv.IsOpen() && !drv.IsIdleMode()) return false;
    if (!m_vmCachedPagePA) {
        m_vmCachedPagePA = drv.VirtualToPhysical(m_cachedCr3, va & ~0xFFFULL);
        if (!m_vmCachedPagePA) return false;
    }
    return drv.PhysRead(m_vmCachedPagePA + (va & 0xFFF), out, size);
}
