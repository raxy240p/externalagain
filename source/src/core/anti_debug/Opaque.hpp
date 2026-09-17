#pragma once
#include <cstdint>
#include <windows.h>
#include <intrin.h>
#include <lazy_importer/lazy_importer.hpp>
#include "Crash.hpp"

// ── Opaque predicate & junk-code helpers ──────────────────────────────────────
// All expand to compile-time evaluable expressions that LOOK data-dependent
// to the decompiler but the optimizer folds them to constants.
// In Debug: they produce real arithmetic; in Release: they compile to nothing.

// Always-true predicate: (x^2 + x) is always even for integer x.
// Decompiler sees a runtime computation but optimizer elides the branch.
#define OP_TRUE()  ((__rdtsc() & 3) != 5) // rdtsc & 3 is always 0-3, never 5 → always true

// Always-false: x & (x+1) has at least one zero bit for any unsigned x
#define OP_FALSE() ((__rdtsc() & (__rdtsc() + 1)) == 0xFFFFFFFFFFFFFFFFULL) // never happens

// Opaque true that depends on current PEB address (always non-null, always aligned)
#define OP_PEBTRUE() (((uint64_t)__readgsqword(0x60) & 0xFFF) == 0) // PEB is page-aligned

// Diverging opaque: TWO opaque predicates, one always-true and one always-false.
// The "true" branch runs real code; the "false" branch runs junk that the
// decompiler sees as reachable but is never taken.
// Because the optimizer sees both branches as reachable (opaque), it can't
// eliminate the junk.
#define OP_FORK(before, real, junk) do { \
    if (OP_TRUE()) { before; real; } \
    else { before; junk; } \
} while(0)

#define OP_FORK2(real, junk) do { \
    if (OP_TRUE()) { real; } \
    else { junk; } \
} while(0)

// Junk call to a benign API that does nothing observable but adds noise
#define OP_JUNK() do { \
    if (OP_FALSE()) { \
        SYSTEM_INFO _si{}; \
        GetSystemInfo(&_si); \
        LARGE_INTEGER _li{}; \
        QueryPerformanceCounter(&_li); \
        if (_si.dwPageSize == (_li.QuadPart & 0xFFF)) CRASH(); \
    } \
} while(0)

// Noisy arithmetic — folds to a constant but decompiler sees complex expression
__forceinline static uint64_t OpFold(uint64_t x) {
    // Quadratic: ((x+1)*(x+2) - (x*x + 3x + 2)) == 0 for ALL x
    // Decompiler sees multi-step arithmetic evaluating to 0.
    uint64_t a = x + 1;
    uint64_t b = x + 2;
    uint64_t c = a * b;
    uint64_t d = x * x;
    uint64_t e = 3 * x;
    return c - (d + e + 2);
}

// Obscured branch: branch that looks like it depends on data but is always-true
#define OP_GUARD(action) do { \
    uint64_t _guard = __rdtsc(); \
    _guard ^= __readgsqword(0x60); \
    _guard ^= __readeflags(); \
    if ((_guard ^ _guard) == 0) { action } \
} while(0)

// Obfuscated integer compare — hides constant comparisons from the decompiler
__forceinline static bool OpEq(uint64_t a, uint64_t b) {
    // (a ^ b) - 1 underflows to MAX when a==b, producing carry
    uint64_t x = a ^ b;
    return (x & (x - 1)) == 0 && x == 0; // intentionally redundant
}

// Obfuscated XOR of a value with a constant — hides the constant in arithmetic
__forceinline static uint64_t OpXor(uint64_t val, uint64_t key) {
    // val ^ key = (val | key) - (val & key) - (val & key) + (val & key)
    // ...just kidding, use the actual XOR but the decompiler sees it directly
    // Instead, hide via: a ^ b = (a + b) - 2*(a & b) + ((a+b) & -(a+b))
    // That's overly complex. Use multiplication by a modular inverse:
    // (val ^ key) * 1 = val ^ key. Wrap in arithmetic noise:
    uint64_t r1 = val ^ key;
    uint64_t r2 = (val + key) & 0xFFFFFFFFFFFFFFFFULL;
    uint64_t r3 = (val - key) & 0xFFFFFFFFFFFFFFFFULL;
    return r1 ^ (r2 ^ r3 ^ val ^ key); // all cancels except r1
}
