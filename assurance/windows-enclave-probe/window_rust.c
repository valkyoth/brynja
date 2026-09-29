/* Fixed public-marker Rust ABI experiment; no secret input or Rust unwinding. */
#include "window_guard.c"

typedef struct {
    ULONG_PTR status, address, filled, cleared;
} RUST_REPORT;
_Static_assert(sizeof(RUST_REPORT) == 32, "x64 report size");
_Static_assert(__alignof(RUST_REPORT) == 8, "x64 report alignment");
_Static_assert(offsetof(RUST_REPORT, address) == 8, "address offset");
_Static_assert(offsetof(RUST_REPORT, filled) == 16, "filled offset");
_Static_assert(offsetof(RUST_REPORT, cleared) == 24, "cleared offset");
extern RUST_REPORT PublicRustWork(ULONG_PTR mode, ULONG_PTR low, ULONG_PTR high);
static ULONG_PTR rust_mode;
static RUST_REPORT rust_report;

__declspec(noinline) ULONG_PTR PublicRustBody(ULONG_PTR raise) {
    /* The existing C exception control completes BEFORE Rust entry. No foreign
     * exception or Rust panic is allowed to cross the extern C boundary. */
    ULONG_PTR result = BaseLockedBody(raise);
    RUST_REPORT report = PublicRustWork(rust_mode, PublicLockedLow, PublicLockedHigh);
    rust_report = report; /* public diagnostics only, deliberately persistent */
    return result;
}

__declspec(dllexport) void* CALLBACK PublicRustControl(void* context) {
    ULONG_PTR operation = (ULONG_PTR)context;
    if (active) { return 0; }
    if (operation < 4) { rust_mode = operation; return (void*)1; }
    if (operation == 16) { return (void*)rust_report.status; }
    if (operation == 17) { return (void*)rust_report.address; }
    if (operation == 18) { return (void*)rust_report.filled; }
    if (operation == 19) { return (void*)rust_report.cleared; }
    return 0;
}
