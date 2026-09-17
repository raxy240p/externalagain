#include <windows.h>
#include <intrin.h>
#include "AntiDebug.hpp"
#include "Opaque.hpp"
#include "Crash.hpp"

#pragma comment(linker, "/INCLUDE:_tls_used")
__declspec(thread) volatile char _tls_anchor = 0;

static VOID NTAPI TlsCb(PVOID, DWORD reason, PVOID) {
    if (reason != DLL_PROCESS_ATTACH) return;

    // Hide the main thread from debugger thread lists before any user code runs.
    AntiDebug::HideThread();

    // Check PEB BeingDebugged + NtGlobalFlag — crash early if a debugger is attached.
    if (AntiDebug::PebCheck())
        CRASH();

    // Overwrite PEB image name so the process appears under a different name in
    // debugger process lists and tools that read the PEB path.
    AntiDebug::SpoofProcessName();
}

extern "C" {
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK _tls_cb_ptr = TlsCb;
#pragma data_seg()
}
