/* Public-vector SHA-256 adapter; all cryptographic code is existing Rust. */
#include "window_rust.c"
#include <intrin.h>

/* Fatal Rust panic is a failed experiment, never recoverable cleanup evidence. */
__declspec(noreturn) void PublicProbeAbort(void) {
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}
