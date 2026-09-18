#pragma once
#ifdef NDEBUG
#define DBG_PRINT(...) ((void)0)
#else
#include <cstdio>
#define DBG_PRINT(...) printf(__VA_ARGS__)
#endif
