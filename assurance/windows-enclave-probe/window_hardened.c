/* Public-vector scoped-owner experiment. No secret input or Rust unwind. */
#include "window_guard.c"
#include <intrin.h>

typedef struct {
    ULONG_PTR status, input, workspace, output, comparisons, lifecycles, cleared, workspace_size;
} HARDENED_REPORT;
_Static_assert(sizeof(HARDENED_REPORT) == 64, "x64 report size");
_Static_assert(__alignof(HARDENED_REPORT) == 8, "x64 report alignment");
_Static_assert(offsetof(HARDENED_REPORT, workspace_size) == 56, "last field offset");
extern HARDENED_REPORT PublicHardenedWork(ULONG_PTR mode, ULONG_PTR low, ULONG_PTR high);
static ULONG_PTR mode;
static HARDENED_REPORT report;

__declspec(noreturn) void PublicProbeAbort(void) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }

__declspec(noinline) ULONG_PTR PublicRustBody(ULONG_PTR raise) {
    ULONG_PTR result = BaseLockedBody(raise); /* C exception completes before Rust. */
    report = PublicHardenedWork(mode, PublicLockedLow, PublicLockedHigh);
    return result;
}

__declspec(dllexport) void* CALLBACK PublicRustControl(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    if (active) { return 0; }
    if (op < 4) { mode = op; return (void*)1; }
    switch (op) {
    case 16: return (void*)report.status;
    case 17: return (void*)report.input;
    case 18: return (void*)report.workspace;
    case 19: return (void*)report.output;
    case 20: return (void*)report.comparisons;
    case 21: return (void*)report.lifecycles;
    case 22: return (void*)report.cleared;
    case 23: return (void*)report.workspace_size;
    default: return 0;
    }
}
