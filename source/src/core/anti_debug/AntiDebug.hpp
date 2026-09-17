#pragma once
#include <VMProtect/VMProtectSDK.h>
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <lazy_importer/lazy_importer.hpp>
#include <skCrypter/skCrypter.hpp>
#include "Opaque.hpp"
#include "Crash.hpp"

using NtQIP_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtQSI_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtSIP_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtQIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

namespace AntiDebug {

// ── FNV-1a compile-time hash ──────────────────────────────────────────────────
static constexpr uint32_t Fnv1a(const char* s, uint32_t h = 2166136261u) {
    return *s ? Fnv1a(s + 1, (h ^ (uint8_t)*s) * 16777619u) : h;
}

__forceinline static void* ResolveExport(uint32_t hash) {
    auto peb  = (PPEB)__readgsqword(0x60);
    auto head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto cur = head->Flink; cur != head; cur = cur->Flink) {
        auto base = *(PBYTE*)((PBYTE)cur + 0x20);
        if (!base) continue;
        auto dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        auto nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        auto& ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!ed.VirtualAddress) continue;
        auto exp   = (PIMAGE_EXPORT_DIRECTORY)(base + ed.VirtualAddress);
        auto names = (DWORD*)(base + exp->AddressOfNames);
        auto funcs = (DWORD*)(base + exp->AddressOfFunctions);
        auto ords  = (WORD*) (base + exp->AddressOfNameOrdinals);
        for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
            const char* name = (const char*)(base + names[i]);
            uint32_t h = 2166136261u;
            for (const char* p = name; *p; ++p) h = (h ^ (uint8_t)*p) * 16777619u;
            if (h != hash) continue;
            DWORD funcRva = funcs[ords[i]];
            // On Windows 8+, many kernel32 exports (CreateFileA, GetFileAttributesA, etc.)
            // are forwarded to KERNELBASE.dll. A forwarded export is detected by its RVA
            // falling *inside* the export directory itself — the bytes at that address are
            // the ASCII forwarding string "TARGETDLL.ExportName", not executable code.
            // Calling that address crashes (DEP: .rdata is non-executable). Follow the
            // forward into the target module instead.
            if (funcRva >= ed.VirtualAddress && funcRva < ed.VirtualAddress + ed.Size) {
                const char* fwdStr = (const char*)(base + funcRva);
                // Split "DLLNAME.FunctionName" at the dot
                const char* dot = fwdStr;
                while (*dot && *dot != '.') ++dot;
                if (!*dot) return nullptr;
                // Hash the target function name
                uint32_t tHash = 2166136261u;
                for (const char* p = dot + 1; *p; ++p) tHash = (tHash ^ (uint8_t)*p) * 16777619u;
                // Case-insensitive prefix match against PEB module BaseDllName
                // (forward string has no .dll suffix; BaseDllName does, so prefix match is correct)
                size_t pfxLen = (size_t)(dot - fwdStr);
                for (auto c2 = head->Flink; c2 != head; c2 = c2->Flink) {
                    auto b2 = *(PBYTE*)((PBYTE)c2 + 0x20);
                    if (!b2 || b2 == base) continue;
                    // LDR_DATA_TABLE_ENTRY offsets (x64):
                    // c2 -> InMemoryOrderLinks (+0x10 in entry).
                    // BaseDllName UNICODE_STRING: entry+0x58 = c2+0x48
                    //   .Length (USHORT)  at c2+0x48
                    //   .Buffer (PWSTR)   at c2+0x50
                    USHORT bLen = *(USHORT*)((PBYTE)c2 + 0x48);
                    PWSTR  bBuf = *(PWSTR*) ((PBYTE)c2 + 0x50);
                    if (!bBuf || (size_t)(bLen >> 1) < pfxLen) continue;
                    bool ok = true;
                    for (size_t k = 0; k < pfxLen && ok; ++k)
                        ok = ((fwdStr[k] | 0x20) == (char)(bBuf[k] | 0x20));
                    if (!ok) continue;
                    // Found target module — resolve the export name within it
                    auto dos2 = (PIMAGE_DOS_HEADER)b2;
                    if (dos2->e_magic != IMAGE_DOS_SIGNATURE) continue;
                    auto nt2  = (PIMAGE_NT_HEADERS)(b2 + dos2->e_lfanew);
                    auto& e2  = nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                    if (!e2.VirtualAddress) continue;
                    auto exp2 = (PIMAGE_EXPORT_DIRECTORY)(b2 + e2.VirtualAddress);
                    auto nms2 = (DWORD*)(b2 + exp2->AddressOfNames);
                    auto fns2 = (DWORD*)(b2 + exp2->AddressOfFunctions);
                    auto ord2 = (WORD*) (b2 + exp2->AddressOfNameOrdinals);
                    for (DWORD j = 0; j < exp2->NumberOfNames; ++j) {
                        const char* n2 = (const char*)(b2 + nms2[j]);
                        uint32_t h2 = 2166136261u;
                        for (const char* p = n2; *p; ++p) h2 = (h2 ^ (uint8_t)*p) * 16777619u;
                        if (h2 == tHash) return b2 + fns2[ord2[j]];
                    }
                    return nullptr; // target module found but export not in it
                }
                return nullptr; // target module not loaded
            }
            return base + funcRva;
        }
    }
    return nullptr;
}

#define AD_API(name, type) \
    reinterpret_cast<type>(AntiDebug::ResolveExport( \
        []() -> uint32_t { constexpr uint32_t h = AntiDebug::Fnv1a(#name); return h; }()))

// ── Junk calls (hash-resolved, no import entries) ──────────────────────────────
#define AD_JUNK() do { \
    SYSTEM_INFO _si{}; \
    ((void(WINAPI*)(LPSYSTEM_INFO))ResolveExport(Fnv1a("GetSystemInfo")))(&_si); \
    LARGE_INTEGER _qpc{}; \
    ((void(WINAPI*)(LARGE_INTEGER*))ResolveExport(Fnv1a("QueryPerformanceCounter")))(&_qpc); \
    volatile DWORD _chk = _si.dwPageSize ^ (DWORD)_qpc.LowPart; \
    if (_chk == 0xF00DC0FEUL) CRASH(); \
} while(0)

// ── CRC-32 (Castagnoli) ───────────────────────────────────────────────────────
__forceinline static uint32_t ComputeCrc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    while (len--) {
        crc ^= *data++;
        for (int k = 8; k--; )
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

// ── Hide thread from debugger ─────────────────────────────────────────────────
__forceinline static void HideThread() {
    auto fn = AD_API(NtSetInformationThread, NtSIT_t);
    if (!fn) return;
    auto pGetCurrentThread = AD_API(GetCurrentThread, HANDLE(WINAPI*)());
    fn(pGetCurrentThread(), 17, nullptr, 0);
}

// ── PEB checks ────────────────────────────────────────────────────────────────
__forceinline bool PebCheck() {
    auto peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged) return true;
    if (*(DWORD*)((PBYTE)peb + 0xBC) & 0x70) return true;
    return false;
}

// ── NtQueryInformationProcess — DebugPort + DebugFlags ───────────────────────
__forceinline bool NtipCheck() {
    auto fn = AD_API(NtQueryInformationProcess, NtQIP_t);
    if (!fn) return false;
    auto pGetCurrentProcess = AD_API(GetCurrentProcess, HANDLE(WINAPI*)());
    HANDLE hProc = pGetCurrentProcess();
    HANDLE port = nullptr;
    if (NT_SUCCESS(fn(hProc, 7, &port, sizeof(port), nullptr)) && port)
        return true;
    DWORD flags = 1;
    if (NT_SUCCESS(fn(hProc, 0x1F, &flags, sizeof(flags), nullptr)) && flags == 0)
        return true;
    return false;
}

// ── Kernel debugger present ───────────────────────────────────────────────────
__forceinline bool KernelDbgCheck() {
    auto fn = AD_API(NtQuerySystemInformation, NtQSI_t);
    if (!fn) return false;
    struct { BOOLEAN Enabled; BOOLEAN NotPresent; } kdi{ 0, 1 };
    if (NT_SUCCESS(fn(0x23, &kdi, sizeof(kdi), nullptr)))
        return kdi.Enabled && !kdi.NotPresent;
    return false;
}

// ── NtClose invalid-handle anti-debug ─────────────────────────────────────────
// Passing a deliberately invalid handle to NtClose raises STATUS_INVALID_HANDLE
// exception. A debugger catches it (first-chance) while a normal process silently
// returns STATUS_INVALID_HANDLE. Exception == debugger present.
__forceinline bool NtCloseCheck() {
    auto ntClose = (NTSTATUS(NTAPI*)(HANDLE))ResolveExport(Fnv1a("NtClose"));
    if (!ntClose) return false;
    // 0xDEAD is a deliberately invalid handle — if SEH fires, debugger is present
    __try { ntClose((HANDLE)0xDEAD); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return true; }
    return false;
}

// ── Kernel module enumeration WITHOUT EnumDeviceDrivers ──────────────────────
// K32EnumDeviceDrivers is a hooked API. Uses NtQuerySystemInformation instead,
// resolved at runtime via FNV-1a hash — no sensitive API string in the binary.
struct KernelModuleInfo {
    uint64_t base;
    uint64_t size;
    char     name[260];
};

static int EnumerateModulesPml4(KernelModuleInfo* out, int maxCount) {
    // Called after engine init. Uses NtQuerySystemInformation(SystemModuleInformation)
    // resolved at runtime via FNV-1a hash — no hooked API string in the binary.
    auto fn = AD_API(NtQuerySystemInformation, NtQSI_t);
    if (!fn) return 0;
    ULONG size = 0;
    fn(11, nullptr, 0, &size); // SystemModuleInformation
    if (!size) return 0;
    std::vector<uint8_t> buf(size);
    if (!NT_SUCCESS(fn(11, buf.data(), size, &size))) return 0;
    struct RTL_PROCESS_MODULES { ULONG Count; struct { void* Section; void* MappedBase; void* ImageBase; ULONG ImageSize; ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT ModuleNameOffset; CHAR FullPathName[256]; } Modules[1]; };
    auto* mods = (RTL_PROCESS_MODULES*)buf.data();
    int count = 0;
    for (ULONG i = 0; i < mods->Count && count < maxCount; i++) {
        out[count].base = (uint64_t)mods->Modules[i].ImageBase;
        out[count].size = mods->Modules[i].ImageSize;
        const char* fn = mods->Modules[i].FullPathName;
        const char* slash = strrchr(fn, '\\');
        strncpy_s(out[count].name, slash ? slash + 1 : fn, _TRUNCATE);
        count++;
    }
    return count;
}

// Check if any loaded kernel module matches the blacklist
// (bypasses the K32EnumDeviceDrivers API which ACs hook)
__forceinline bool KernelModuleBlacklistCheck() {
    KernelModuleInfo kmi[64];
    int count = EnumerateModulesPml4(kmi, 64);
    for (int i = 0; i < count; i++) {
        // Hash the module name — no string comparison needed
        uint32_t h = 0x811C9DC5u;
        for (const char* p = kmi[i].name; *p; ++p)
            h = (h ^ (uint8_t)(*p >= 'a' ? *p - 0x20 : *p)) * 0x01000193u;
        // Known AC/sandbox driver hashes
        switch (h) {
        case Fnv1a("easyanticheat.sys"):
        case Fnv1a("EasyAntiCheat.sys"):
        case Fnv1a("EAC.sys"):
        case Fnv1a("BEDaisy.sys"):
        case Fnv1a("beds.sys"):
        // faceit.sys intentionally excluded — this tool targets FaceIT
        case Fnv1a("vmci.sys"):
        case Fnv1a("vmmouse.sys"):
        case Fnv1a("vm3dmp.sys"):
        case Fnv1a("vmx_svga.sys"):
        case Fnv1a("VBoxGuest.sys"):
        case Fnv1a("VBoxMouse.sys"):
        case Fnv1a("VBoxSF.sys"):
        case Fnv1a("VBoxVideo.sys"):
            return true; // AC or VM driver detected
        }
    }
    return false;
}

// ── Hardware breakpoints (≥2 to avoid AC false-positives) ────────────────────
__forceinline bool HardwareBreakpointCheck() {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    auto pGetThreadContext = AD_API(GetThreadContext, BOOL(WINAPI*)(HANDLE, LPCONTEXT));
    auto pGetCurrentThread = AD_API(GetCurrentThread, HANDLE(WINAPI*)());
    pGetThreadContext(pGetCurrentThread(), &ctx);
    return ((ctx.Dr0 != 0) + (ctx.Dr1 != 0) + (ctx.Dr2 != 0) + (ctx.Dr3 != 0)) >= 2;
}

// ── Anti-hook: ntdll syscall stubs must start with MOV R10,RCX (4C 8B D1) ───
__forceinline bool AntiHookCheck() {
    static const uint32_t targets[] = {
        Fnv1a("NtQueryInformationProcess"),
        Fnv1a("NtSetInformationThread"),
        Fnv1a("NtQuerySystemInformation"),
        Fnv1a("NtCreateThreadEx"),
        0
    };
    for (int i = 0; targets[i]; ++i) {
        auto fn = (PBYTE)ResolveExport(targets[i]);
        if (!fn) continue;
        // Windows 11 24H2+ with CET: stubs begin with ENDBR64 (F3 0F 1E FA)
        if (fn[0] == 0xF3 && fn[1] == 0x0F && fn[2] == 0x1E && fn[3] == 0xFA)
            fn += 4;
        // Unhooked syscall stub: 4C 8B D1 (mov r10, rcx)
        // Hooked:  E9 xx xx xx xx  (jmp rel32) or FF 25 (jmp [mem])
        if (fn[0] == 0xE9 || (fn[0] == 0xFF && fn[1] == 0x25))
            return true;
        if (fn[0] != 0x4C && fn[0] != 0xB8)
            return true; // unexpected prologue
    }
    return false;
}

// ── Thread suspend: exit if our thread has been externally suspended ──────────
__forceinline bool ThreadSuspendCheck() {
    auto fn = AD_API(NtQueryInformationThread, NtQIT_t);
    if (!fn) return false;
    auto pGetCurrentThread = AD_API(GetCurrentThread, HANDLE(WINAPI*)());
    ULONG count = 0;
    if (NT_SUCCESS(fn(pGetCurrentThread(), 35, &count, sizeof(count), nullptr)))
        return count > 0;
    return false;
}

// ── RDTSC timing ──────────────────────────────────────────────────────────────
__forceinline bool TimingCheck() {
    unsigned long long t1 = __rdtsc();
    volatile DWORD x = 0;
    for (int i = 0; i < 1000; i++) x ^= (DWORD)(i * 0x1337U);
    (void)x;
    return (__rdtsc() - t1) > 5000000000ULL;
}

// ── VM detection ──────────────────────────────────────────────────────────────
__forceinline bool VMCheck() {
    int cpui[4]{};
    __cpuid(cpui, 1);
    if (cpui[2] & (1 << 31)) {
        __cpuid(cpui, 0x40000000);
        char v[13]{};
        memcpy(v,   &cpui[1], 4);
        memcpy(v+4, &cpui[2], 4);
        memcpy(v+8, &cpui[3], 4);
        if (strstr(v, skCrypt("VMwareVMware")) || strstr(v, skCrypt("VBoxVBoxVBox")) || strstr(v, skCrypt("KVMKVMKVM")))
            return true;
    }
    HKEY hk;
    auto pRegOpenKeyExA = AD_API(RegOpenKeyExA, LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY));
    auto pRegCloseKey   = AD_API(RegCloseKey,   LSTATUS(WINAPI*)(HKEY));
    if (pRegOpenKeyExA(HKEY_LOCAL_MACHINE, skCrypt("SOFTWARE\\VMware, Inc.\\VMware Tools"),
                       0, KEY_READ, &hk) == ERROR_SUCCESS)
        { pRegCloseKey(hk); return true; }
    if (pRegOpenKeyExA(HKEY_LOCAL_MACHINE, skCrypt("SOFTWARE\\Oracle\\VirtualBox Guest Additions"),
                       0, KEY_READ, &hk) == ERROR_SUCCESS)
        { pRegCloseKey(hk); return true; }
    return false;
}

// ── Process blacklist ─────────────────────────────────────────────────────────
__forceinline bool BlacklistCheck() {
    auto _b0  = skCrypt("x64dbg.exe");
    auto _b1  = skCrypt("x32dbg.exe");
    auto _b2  = skCrypt("ollydbg.exe");
    auto _b3  = skCrypt("ida.exe");
    auto _b4  = skCrypt("ida64.exe");
    auto _b5  = skCrypt("idaq.exe");
    auto _b6  = skCrypt("idaq64.exe");
    auto _b7  = skCrypt("ghidra.exe");
    auto _b8  = skCrypt("ghidrarun.exe");
    auto _b9  = skCrypt("radare2.exe");
    auto _b10 = skCrypt("r2.exe");
    auto _b11 = skCrypt("cutter.exe");
    auto _b12 = skCrypt("windbg.exe");
    auto _b13 = skCrypt("cdb.exe");
    auto _b14 = skCrypt("ntsd.exe");
    auto _b15 = skCrypt("cheatengine-x86_64.exe");
    auto _b16 = skCrypt("cheat engine.exe");
    auto _b17 = skCrypt("processhacker.exe");
    auto _b18 = skCrypt("systeminformer.exe");
    auto _b19 = skCrypt("wireshark.exe");
    auto _b20 = skCrypt("fiddler.exe");
    auto _b21 = skCrypt("httpdebuggerui.exe");
    auto _b22 = skCrypt("scylladump.exe");
    auto _b23 = skCrypt("pe-sieve64.exe");
    auto _b24 = skCrypt("hollows_hunter64.exe");
    auto _b25 = skCrypt("apimonitor-x64.exe");
    auto _b26 = skCrypt("pestudio.exe");
    const char* bad[] = {
        (const char*)_b0,  (const char*)_b1,  (const char*)_b2,
        (const char*)_b3,  (const char*)_b4,  (const char*)_b5,
        (const char*)_b6,  (const char*)_b7,  (const char*)_b8,
        (const char*)_b9,  (const char*)_b10, (const char*)_b11,
        (const char*)_b12, (const char*)_b13, (const char*)_b14,
        (const char*)_b15, (const char*)_b16, (const char*)_b17,
        (const char*)_b18, (const char*)_b19, (const char*)_b20,
        (const char*)_b21, (const char*)_b22, (const char*)_b23,
        (const char*)_b24, (const char*)_b25, (const char*)_b26,
        nullptr
    };
    auto pCreateToolhelp32Snapshot = AD_API(CreateToolhelp32Snapshot, HANDLE(WINAPI*)(DWORD, DWORD));
    auto pProcess32First           = AD_API(Process32First,           BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32));
    auto pProcess32Next            = AD_API(Process32Next,            BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32));
    auto pCloseHandle              = AD_API(CloseHandle,              BOOL(WINAPI*)(HANDLE));
    HANDLE snap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe{ sizeof(pe) };
    bool found = false;
    if (pProcess32First(snap, &pe))
        do {
            for (int i = 0; bad[i]; ++i)
                if (_stricmp(pe.szExeFile, bad[i]) == 0) { found = true; break; }
        } while (!found && pProcess32Next(snap, &pe));
    pCloseHandle(snap);
    return found;
}

// ── Spoof PEB process name and command line ───────────────────────────────────
inline void SpoofProcessName() {
    auto peb    = (PPEB)__readgsqword(0x60);
    auto params = *(PBYTE*)((PBYTE)peb + 0x20); // ProcessParameters
    if (!params) return;

    // UNICODE_STRING layout (x64): USHORT Length (+0), USHORT MaxLen (+2), PWSTR Buffer (+8)
    // Built from narrow skCrypt literals at first call so no wide string in .rdata
    static wchar_t sPath[64] = {};
    static wchar_t sCmd[32]  = {};
    static bool    sReady    = false;
    if (!sReady) {
        auto _p = skCrypt("C:\\Windows\\System32\\svchost.exe");
        auto _c = skCrypt("svchost.exe -k netsvcs");
        MultiByteToWideChar(CP_UTF8, 0, (const char*)_p, -1, sPath, 64);
        MultiByteToWideChar(CP_UTF8, 0, (const char*)_c, -1, sCmd,  32);
        sReady = true;
    }

    auto setUStr = [](PBYTE base, wchar_t* buf) {
        auto len = (USHORT)(wcslen(buf) * 2);
        *(USHORT*)(base + 0) = len;
        *(USHORT*)(base + 2) = (USHORT)(len + 2);
        *(PWSTR*) (base + 8) = buf;
    };
    setUStr(params + 0x60, sPath); // ImagePathName
    setUStr(params + 0x70, sCmd);  // CommandLine
}

// ── PE header erasure (call after StartWatchdog snapshots the CRC) ────────────
// Zeros DOS stub + PE signature only — NOT the full 0x1000 page.
// Zeroing the optional header's data directories breaks x64 SEH: when the
// overlay window is activated, Windows walks the exception directory to register
// unwind tables. If that pointer is zero, any subsequent exception terminates
// the process with no handler. Keeping NT headers intact preserves SEH while
// still defeating "MZ"/"PE\0\0" signature scans.
inline void ErasePeHeaders() {
    auto pGetModuleHandleW = AD_API(GetModuleHandleW, HMODULE(WINAPI*)(LPCWSTR));
    auto pVirtualProtect   = AD_API(VirtualProtect,   BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD));
    PBYTE base = (PBYTE)pGetModuleHandleW(nullptr);
    auto  dos  = (PIMAGE_DOS_HEADER)base;
    DWORD ntOff = dos->e_lfanew;
    if (!ntOff || ntOff > 0x400) return;

    DWORD eraseLen = ntOff + 4;
    DWORD old;
    if (pVirtualProtect(base, eraseLen, PAGE_READWRITE, &old)) {
        SecureZeroMemory(base, eraseLen);
        pVirtualProtect(base, eraseLen, old, &old);
    }
}

// ── PEB module-list sanitisation ─────────────────────────────────────────────
// Unlinks the D3D/DWM DLLs used by the overlay from all 3 PEB LDR lists so
// that process-module enumerations don't reveal an OpenGL/D3D overlay process.
// Called once after the renderer is up. Only touches render-specific imports;
// the host process entry is left intact (unlink order matters for SEH).
inline void SanitizePebModuleList() {
    auto peb = (PPEB)__readgsqword(0x60);
    auto ldr = peb->Ldr;

    // Targets: d3d11.dll, dxgi.dll, d3dcompiler_47.dll, dwmapi.dll
    // Hash them at compile-time so no wide string literal appears.
    static const uint32_t kTargets[] = {
        Fnv1a("d3d11.dll"), Fnv1a("dxgi.dll"),
        Fnv1a("d3dcompiler_47.dll"), Fnv1a("dwmapi.dll"),
        0
    };

    // LDR_DATA_TABLE_ENTRY (x64) list heads relative to Ldr:
    //   InLoadOrderModuleList   = Ldr+0x10
    //   InMemoryOrderModuleList = Ldr+0x20
    //   InInitializationOrderModuleList = Ldr+0x30
    PLIST_ENTRY heads[3] = {
        (PLIST_ENTRY)((PBYTE)ldr + 0x10),
        (PLIST_ENTRY)((PBYTE)ldr + 0x20),
        (PLIST_ENTRY)((PBYTE)ldr + 0x30),
    };

    for (auto link = heads[0]->Flink; link != heads[0]; ) {
        // BaseDllName UNICODE_STRING at entry+0x58 (InLoadOrderLinks is at entry+0x00)
        USHORT bLen  = *(USHORT*)((PBYTE)link + 0x58);
        PWSTR  bBuf  = *(PWSTR*) ((PBYTE)link + 0x60);
        PLIST_ENTRY next = link->Flink;

        if (bBuf && bLen > 0 && bLen <= 512) {
            // Convert BaseDllName to lowercase ASCII for Fnv1a comparison
            char name[256] = {};
            for (int i = 0; i < (int)(bLen / 2) && i < 255; i++) {
                wchar_t c = bBuf[i];
                name[i] = (c >= L'A' && c <= L'Z') ? (char)(c + 0x20) : (char)c;
            }
            uint32_t h = Fnv1a(name);
            for (int t = 0; kTargets[t]; t++) {
                if (h == kTargets[t]) {
                    // Unlink from all 3 lists:
                    // InLoadOrder   @ link+0x00
                    // InMemoryOrder @ link+0x10
                    // InInitOrder   @ link+0x20
                    for (int li = 0; li < 3; li++) {
                        PLIST_ENTRY e = (PLIST_ENTRY)((PBYTE)link + li * 0x10);
                        e->Blink->Flink = e->Flink;
                        e->Flink->Blink = e->Blink;
                        e->Flink = e->Blink = e;
                    }
                    break;
                }
            }
        }
        link = next;
    }
}

// ── ETW suppression — patch EtwEventWrite to xor eax,eax / ret ──────────────
// Prevents user-mode ETW providers (AV inline hooks on ntdll) from logging
// process events. VirtualProtect on ntdll is user-mode only; unaffected by HVCI.
inline void BlindEtw() {
    auto pVP = AD_API(VirtualProtect, BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD));
    if (!pVP) return;
    auto fn = (PBYTE)ResolveExport(Fnv1a("EtwEventWrite"));
    if (!fn) return;
    DWORD old = 0;
    if (pVP(fn, 16, PAGE_EXECUTE_READWRITE, &old)) {
        fn[0] = 0x33; fn[1] = 0xC0; fn[2] = 0xC3;  // xor eax,eax; ret
        pVP(fn, 16, old, &old);
    }
}

// ── Make process critical — kill triggers BSOD ────────────────────────────────
inline void MakeProcessCritical() {
    auto fn = AD_API(NtSetInformationProcess, NtSIP_t);
    if (!fn) return;
    ULONG val = 1;
    auto pGetCurrentProcess = AD_API(GetCurrentProcess, HANDLE(WINAPI*)());
    fn(pGetCurrentProcess(), 29, &val, sizeof(val));
}

// Optional secondary CRC over an arbitrary function body (pass via validateFnPtr).
static PBYTE   s_valBase = nullptr;
static uint32_t s_valCrc  = 0;

// Optional periodic re-validation callback
using RevalidateFn = bool(*)();
static RevalidateFn s_revalidate = nullptr;

// ── CRC watchdog thread ───────────────────────────────────────────────────────
static DWORD WINAPI WatchdogProc(LPVOID) {
    HideThread();
    {
        auto pSetThreadPriority = AD_API(SetThreadPriority, BOOL(WINAPI*)(HANDLE, int));
        auto pGetCurrentThread  = AD_API(GetCurrentThread,  HANDLE(WINAPI*)());
        pSetThreadPriority(pGetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    }
    auto pSleep = AD_API(Sleep, void(WINAPI*)(DWORD));
    DWORD tick = 0;
    int   revalFails = 0;

    while (true) {
        pSleep(3000);
        ++tick;

        // Optional function integrity CRC — detects short-circuit patches like mov-al-1/ret.
        // Covers 512 bytes so prologue patches can't hide at the tail.
        // NOTE: whole-module .code CRC omitted — packed binaries patch their own IAT/
        // relocations post-startup, causing false mismatches every time.
        if (s_valBase) {
            if (ComputeCrc32(s_valBase, 512) != s_valCrc)
                CRASH();
        }

        // Periodic re-validation every 30 minutes (600 ticks × 3 s = 1800 s)
        if (s_revalidate && tick % 600 == 0) {
            if (!s_revalidate()) {
                if (++revalFails >= 3)   // allow 2 transient network failures
                    CRASH();
            } else {
                revalFails = 0;
            }
        }

        // PebCheck/NtipCheck omitted: FaceIT may set these flags legitimately in-game
    }
    return 0;
}

// Call BEFORE LateHarden — optionally snapshots a function CRC and spawns the watchdog thread.
// revalidateFn : called every 30 min, pass a callback that returns true on success.
// validateFnPtr: pointer to a function whose first 512 bytes are CRC'd for patch detection.
inline void StartWatchdog(RevalidateFn revalidateFn = nullptr, void* validateFnPtr = nullptr) {
    s_revalidate = revalidateFn;

    // Snapshot 512 bytes of the supplied function for patch detection (optional).
    if (validateFnPtr) {
        s_valBase = (PBYTE)validateFnPtr;
        s_valCrc  = ComputeCrc32(s_valBase, 512);
    }

    auto pCreateThread = AD_API(CreateThread, HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD));
    auto pCloseHandle  = AD_API(CloseHandle,  BOOL(WINAPI*)(HANDLE));
    HANDLE h = pCreateThread(nullptr, 0, WatchdogProc, nullptr, 0, nullptr);
    if (h) pCloseHandle(h);
}

// ── Full startup check (obfuscated with opaque predicates) ───────────────────
#ifdef __clang__
[[clang::noinline, clang::optnone]]
#else
__declspec(noinline)
#endif
inline void Assert() {
    VMProtectBeginMutation("anti_dbg");
    HideThread();
    AD_JUNK();

    // Each check is gated behind an opaque true predicate so the decompiler
    // sees multiple conditionally-executed code paths. All are always taken.
    bool caught = false;

    if (OP_TRUE()) {
        if (OP_TRUE()) caught = caught || PebCheck();
        if (OP_TRUE()) caught = caught || NtipCheck();
        if (OP_TRUE()) caught = caught || KernelDbgCheck();
        AD_JUNK();
        if (OP_TRUE()) caught = caught || NtCloseCheck();
        if (OP_TRUE()) caught = caught || HardwareBreakpointCheck();
    } else {
        // Opaque fork: identical checks that decompiler can't statically merge
        caught = PebCheck() || NtipCheck() || KernelDbgCheck();
    }

    if (OP_TRUE()) {
        // AntiHookCheck() removed: AV inline hooks in ntdll stubs survive "disable
        // real-time protection" — hooks are installed by the AV kernel driver at boot
        // and only removed on full driver unload/reboot. This caused false-positive
        // CRASH() on any system with AV installed, even with protection disabled.
        // VMProtect virtualization covers the same attack surface without the FP.
        caught = caught || TimingCheck();
        caught = caught || VMCheck();
        caught = caught || BlacklistCheck();
    }

    AD_JUNK();

    // Kernel module check via NtQuerySystemInformation (not EnumDeviceDrivers)
    if (OP_TRUE()) {
        if (KernelModuleBlacklistCheck()) CRASH();
    }

    if (caught) CRASH();
}

// ── Late hardening — call after engine+renderer are up ───────────────────────
// ErasePeHeaders removed: VirtualProtect on the module header region is
// intercepted by FaceIT's kernel driver and triggers process termination.
// PE header erasure is intentionally skipped here — see comment above.
inline void LateHarden() {
    BlindEtw();
    MakeProcessCritical();
}

// ── Periodic check (cache loop) ───────────────────────────────────────────────
__forceinline void Tick() {
    if (PebCheck() || HardwareBreakpointCheck() || NtipCheck())
        CRASH();
}

#undef AD_API

} // namespace AntiDebug
