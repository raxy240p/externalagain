#pragma once
#include <intrin.h>

// Replaces ExitProcess with a non-bypassable termination.
// __fastfail raises a kernel-level fatal exception that no user-mode handler
// (including a debugger) can swallow or continue past. The process terminates
// immediately regardless of hooks on TerminateProcess/ExitProcess/NtTerminate.
// Each CRASH() site is inline UD2 — no import to patch, no function to hook.
#define CRASH() __fastfail(0xDEAD)
