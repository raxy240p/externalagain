#pragma once
// PEB-walking import resolver — resolves Win32 exports at runtime by FNV-1a hash.
// No GetProcAddress call. No import table entry for resolved functions.
// Handles Win10/11 kernel32 → kernelbase forwarders by searching all loaded modules.
// Usage:  LI_FN(CreateFileA)(path, GENERIC_READ, ...)
//         LI_FN(DeviceIoControl)(hDev, code, ...)

#include <windows.h>
#include <intrin.h>
#include <cstdint>

namespace li {

// FNV-1a hash — case-sensitive (export names are case-sensitive)
constexpr uint32_t fnv1a(const char* s, uint32_t h = 0x811c9dc5u) noexcept {
    return *s ? fnv1a(s + 1, (h ^ static_cast<uint8_t>(*s)) * 0x01000193u) : h;
}

namespace detail {

// Walk all loaded modules in the PEB and find the first real (non-forwarder)
// export whose name hashes to fn_hash.
// By searching all modules we naturally resolve kernel32→kernelbase forwarders:
// kernelbase.dll always contains the real export, so we find it when we reach it.
inline void* resolve(uint32_t fn_hash) noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    auto* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
#else
    auto* peb = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
#endif
    auto* ldr  = *reinterpret_cast<uint8_t**>(peb + 0x18);
    auto* head = reinterpret_cast<LIST_ENTRY*>(ldr + 0x20);

    for (auto* e = head->Flink; e != head; e = e->Flink) {
        // InMemoryOrderLinks is at offset 0x10 inside LDR_DATA_TABLE_ENTRY (64-bit)
        auto* dll = *reinterpret_cast<uint8_t**>(reinterpret_cast<uint8_t*>(e) - 0x10 + 0x30);
        if (!dll) continue;

        auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(dll);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;

        auto* nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(dll + dos->e_lfanew);
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dir.VirtualAddress) continue;

        auto* exp   = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(dll + dir.VirtualAddress);
        auto* names = reinterpret_cast<DWORD*>(dll + exp->AddressOfNames);
        auto* ords  = reinterpret_cast<WORD* >(dll + exp->AddressOfNameOrdinals);
        auto* funcs = reinterpret_cast<DWORD*>(dll + exp->AddressOfFunctions);

        for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
            auto* fname = reinterpret_cast<const char*>(dll + names[i]);

            // Hash the export name
            uint32_t fh = 0x811c9dc5u;
            for (const char* p = fname; *p; ++p)
                fh = (fh ^ static_cast<uint8_t>(*p)) * 0x01000193u;

            if (fh != fn_hash) continue;

            DWORD rva = funcs[ords[i]];
            // Skip forwarders (RVA points into the export directory itself)
            if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size)
                continue;

            return dll + rva;
        }
    }
    return nullptr;
}

} // namespace detail

template<typename Fn, uint32_t FnHash>
struct LazyFn {
    __forceinline operator Fn() const noexcept {
        static void* cached = nullptr;
        if (!cached) cached = detail::resolve(FnHash);
        return reinterpret_cast<Fn>(cached);
    }
    template<typename... Args>
    __forceinline auto operator()(Args&&... args) const {
        return (operator Fn())(static_cast<Args&&>(args)...);
    }
};

} // namespace li

// The function name is hashed at compile time — only an integer constant appears in the binary.
// No GetProcAddress call, no import table entry, no string literal for the function name.
#define LI_FN(fn) (::li::LazyFn<decltype(&fn), ::li::fnv1a(#fn)>{})
