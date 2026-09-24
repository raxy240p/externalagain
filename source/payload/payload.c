// payload.c — minimal manual-mapped kernel payload.
//
// Runs after kdmapper (or equivalent) copies this PE into NonPagedPool,
// fixes imports, and calls DriverEntry(NULL, NULL). No DriverObject, no
// IoCreateDevice, no IOCTL dispatch. Communicates with the user-mode
// cheat via a single named section — see payload_shared.h.
//
// Reads happen via KeStackAttachProcess(target) + RtlCopyMemory inside
// __try/__except. Simple, works on every Win7-through-Win11 build, and
// has no MmMapIoSpace / \Device\PhysicalMemory footprint for AC to
// signature-scan.
//
// Lifecycle: DriverEntry creates the section, spawns one reader system
// thread, returns STATUS_SUCCESS. The thread lives until the user writes
// PAYLOAD_STATE_SHUTDOWN into state.

#include <ntifs.h>
#include "payload_shared.h"

// --- state --------------------------------------------------------------

static HANDLE            g_section_handle = NULL;
static payload_shared_t* g_shared         = NULL;
static PVOID             g_section_view   = NULL;
static PEPROCESS         g_target         = NULL;
static ULONG             g_target_pid     = 0;
static HANDLE            g_thread_handle  = NULL;
static volatile LONG     g_shutdown       = 0;

// --- shared-section setup ----------------------------------------------

static NTSTATUS payload_create_section(void)
{
    UNICODE_STRING    name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER     max_size;
    SIZE_T            view_size = PAYLOAD_SECTION_SIZE;
    NTSTATUS          s;

    RtlInitUnicodeString(&name, PAYLOAD_SECTION_NT);
    InitializeObjectAttributes(&attr,
                               &name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
                               NULL, NULL);
    max_size.QuadPart = PAYLOAD_SECTION_SIZE;

    s = ZwCreateSection(&g_section_handle,
                        SECTION_ALL_ACCESS,
                        &attr,
                        &max_size,
                        PAGE_READWRITE,
                        SEC_COMMIT,
                        NULL);
    if (!NT_SUCCESS(s)) return s;

    s = ZwMapViewOfSection(g_section_handle,
                           ZwCurrentProcess(),
                           &g_section_view,
                           0, 0, NULL,
                           &view_size,
                           ViewShare,
                           0,
                           PAGE_READWRITE);
    if (!NT_SUCCESS(s)) {
        ZwClose(g_section_handle);
        g_section_handle = NULL;
        return s;
    }

    g_shared = (payload_shared_t*)g_section_view;
    RtlZeroMemory(g_shared, sizeof(payload_shared_t));
    g_shared->state = PAYLOAD_STATE_IDLE;
    g_shared->magic = PAYLOAD_MAGIC;
    return STATUS_SUCCESS;
}

static void payload_teardown_section(void)
{
    if (g_section_view) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), g_section_view);
        g_section_view = NULL;
    }
    if (g_section_handle) {
        ZwClose(g_section_handle);
        g_section_handle = NULL;
    }
    g_shared = NULL;
}

// --- request dispatch --------------------------------------------------

static NTSTATUS handle_attach_pid(void)
{
    PEPROCESS   proc = NULL;
    NTSTATUS    s;
    HANDLE      pid_h = (HANDLE)(ULONG_PTR)g_shared->target_pid;

    s = PsLookupProcessByProcessId(pid_h, &proc);
    if (!NT_SUCCESS(s)) return s;

    if (g_target) ObDereferenceObject(g_target);
    g_target     = proc;
    g_target_pid = g_shared->target_pid;
    return STATUS_SUCCESS;
}

static NTSTATUS handle_read_virtual(void)
{
    KAPC_STATE apc;
    ULONG      size;
    ULONG_PTR  va;
    NTSTATUS   s = STATUS_SUCCESS;

    if (!g_target)                            return STATUS_INVALID_HANDLE;
    if (g_shared->size == 0)                  return STATUS_SUCCESS;
    if (g_shared->size > PAYLOAD_DATA_MAX)    return STATUS_INVALID_PARAMETER;

    size = g_shared->size;
    va   = (ULONG_PTR)g_shared->target_va;

    KeStackAttachProcess(g_target, &apc);
    __try {
        // Probe first so we surface STATUS_ACCESS_VIOLATION on unmapped
        // pages instead of bugchecking. Probe reads (align 1) for the
        // whole range; on fault the SEH handler catches it.
        ProbeForRead((PVOID)va, size, 1);
        RtlCopyMemory(g_shared->data, (PVOID)va, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    return s;
}

static NTSTATUS handle_write_virtual(void)
{
    KAPC_STATE apc;
    ULONG      size;
    ULONG_PTR  va;
    NTSTATUS   s = STATUS_SUCCESS;

    if (!g_target)                            return STATUS_INVALID_HANDLE;
    if (g_shared->size == 0)                  return STATUS_SUCCESS;
    if (g_shared->size > PAYLOAD_DATA_MAX)    return STATUS_INVALID_PARAMETER;

    size = g_shared->size;
    va   = (ULONG_PTR)g_shared->target_va;

    KeStackAttachProcess(g_target, &apc);
    __try {
        ProbeForWrite((PVOID)va, size, 1);
        RtlCopyMemory((PVOID)va, g_shared->data, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    return s;
}

extern PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);

static NTSTATUS handle_get_peb(void)
{
    PVOID peb;
    if (!g_target) return STATUS_INVALID_HANDLE;
    peb = PsGetProcessPeb(g_target);
    *(PULONG64)g_shared->data = (ULONG64)(ULONG_PTR)peb;
    g_shared->size = sizeof(ULONG64);
    return peb ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// --- reader thread -----------------------------------------------------

static VOID payload_thread(PVOID ctx)
{
    LARGE_INTEGER wait;
    NTSTATUS      s;

    UNREFERENCED_PARAMETER(ctx);
    wait.QuadPart = -1000LL;   // 100us relative

    for (;;) {
        if (InterlockedCompareExchange(&g_shutdown, 0, 0) != 0)
            break;

        // Try to claim a pending request. CAS REQUEST → PROCESSING.
        LONG prev = InterlockedCompareExchange(&g_shared->state,
                                               PAYLOAD_STATE_PROCESSING,
                                               PAYLOAD_STATE_REQUEST);
        if (prev != PAYLOAD_STATE_REQUEST) {
            if (prev == PAYLOAD_STATE_SHUTDOWN) break;
            KeDelayExecutionThread(KernelMode, FALSE, &wait);
            continue;
        }

        switch (g_shared->op) {
        case PAYLOAD_OP_PING:          s = STATUS_SUCCESS;         break;
        case PAYLOAD_OP_ATTACH_PID:    s = handle_attach_pid();    break;
        case PAYLOAD_OP_READ_VIRTUAL:  s = handle_read_virtual();  break;
        case PAYLOAD_OP_WRITE_VIRTUAL: s = handle_write_virtual(); break;
        case PAYLOAD_OP_GET_PEB:       s = handle_get_peb();       break;
        default:                       s = STATUS_NOT_IMPLEMENTED; break;
        }

        g_shared->status = s;
        InterlockedExchange(&g_shared->state, PAYLOAD_STATE_DONE);
    }

    if (g_target) {
        ObDereferenceObject(g_target);
        g_target = NULL;
    }
    payload_teardown_section();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// --- entry -------------------------------------------------------------

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    NTSTATUS s;

    UNREFERENCED_PARAMETER(drv);
    UNREFERENCED_PARAMETER(reg);

    // Manual-mapped payload: drv/reg are NULL from kdmapper. Don't touch
    // them. Don't call IoCreateDevice/IoCreateSymbolicLink — we own zero
    // driver objects intentionally.

    s = payload_create_section();
    if (!NT_SUCCESS(s)) return s;

    s = PsCreateSystemThread(&g_thread_handle,
                             THREAD_ALL_ACCESS,
                             NULL, NULL, NULL,
                             payload_thread,
                             NULL);
    if (!NT_SUCCESS(s)) {
        payload_teardown_section();
        return s;
    }
    ZwClose(g_thread_handle);
    g_thread_handle = NULL;
    return STATUS_SUCCESS;
}
