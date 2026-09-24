// payload_shared.h — protocol shared between the kernel payload and the
// user-mode cheat. Keep this header stable; both sides include it as-is.
//
// Communication channel: a single named section mapped into both sides.
// Layout: header at offset 0, request/response fields inline, data buffer
// at offset 0x40. Poll/signal on `state` via InterlockedCompareExchange.
//
// State machine:
//   IDLE       (0) — no request pending
//   REQUEST    (1) — user filled req fields and flipped state
//   PROCESSING (2) — kernel picked up the request
//   DONE       (3) — kernel wrote status/buffer, ready for user
//
// User flow:  set op/params/size, CAS state IDLE→REQUEST, spin on DONE,
//             read status/buffer, CAS state DONE→IDLE.
// Kernel flow: spin on REQUEST, CAS REQUEST→PROCESSING, dispatch, write
//             status, CAS PROCESSING→DONE.

#ifndef PAYLOAD_SHARED_H
#define PAYLOAD_SHARED_H

// Named section for kernel↔user handshake. \BaseNamedObjects\Global\<name>
// on kernel side; "Global\<name>" from user via OpenFileMappingA.
// Change the suffix on rebuild to rotate the IOC.
#define PAYLOAD_SECTION_NAME  "Global\\Xh7Km2p9Qr4tZ8"
#define PAYLOAD_SECTION_NT    L"\\BaseNamedObjects\\Global\\Xh7Km2p9Qr4tZ8"
#define PAYLOAD_SECTION_SIZE  0x2000                        // 8 KiB
#define PAYLOAD_DATA_OFFSET   0x40
#define PAYLOAD_DATA_MAX      (PAYLOAD_SECTION_SIZE - PAYLOAD_DATA_OFFSET)

// State values live at [payload_shared.state]. All-atomic via Interlocked.
#define PAYLOAD_STATE_IDLE        0
#define PAYLOAD_STATE_REQUEST     1
#define PAYLOAD_STATE_PROCESSING  2
#define PAYLOAD_STATE_DONE        3
#define PAYLOAD_STATE_SHUTDOWN    0xFF

// Op codes at [payload_shared.op]. The kernel side handler dispatches on this.
#define PAYLOAD_OP_NOOP          0
#define PAYLOAD_OP_ATTACH_PID    1   // set target: params.pid → cache PEPROCESS
#define PAYLOAD_OP_READ_VIRTUAL  2   // read target's VA space: params.va, size → buffer
#define PAYLOAD_OP_WRITE_VIRTUAL 3   // write to target's VA space: buffer → params.va
#define PAYLOAD_OP_PING          4   // liveness / handshake
#define PAYLOAD_OP_GET_PEB       5   // return target's PEB VA in data[0..8] (u64)

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)
typedef struct payload_shared_s {
    volatile long    state;         // one of PAYLOAD_STATE_*
    unsigned long    op;            // one of PAYLOAD_OP_*
    unsigned long    target_pid;    // for ATTACH_PID; ignored on other ops
    unsigned long    size;          // bytes to read/write; must be <= PAYLOAD_DATA_MAX
    unsigned long long target_va;   // target virtual address
    long             status;        // NTSTATUS on completion
    unsigned long    magic;         // set to 0x50414E44 by kernel after init
    unsigned long    reserved[3];   // pad to 0x40 boundary; keep zero
    unsigned char    data[PAYLOAD_DATA_MAX];
} payload_shared_t;
#pragma pack(pop)

#define PAYLOAD_MAGIC 0x50414E44u   // "DNAP" — set by kernel once ready

#ifdef __cplusplus
}
#endif

#endif // PAYLOAD_SHARED_H
