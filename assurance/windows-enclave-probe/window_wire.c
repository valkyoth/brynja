/* Public-vector scoped wire experiment. No confidential ingress or production ABI. */
#include "window_guard.c"
#include <intrin.h>
#include <bcrypt.h>

typedef struct {
    ULONG_PTR status, snapshot, workspace, output, absorbed, cleared, replay, owner_size;
} WIRE_REPORT;
_Static_assert(sizeof(WIRE_REPORT) == 64, "x64 report size");
_Static_assert(offsetof(WIRE_REPORT, owner_size) == 56, "last report field");
extern WIRE_REPORT PublicWireWork(ULONG_PTR source, ULONG_PTR low, ULONG_PTR high);
static ULONG_PTR wire_source;
static WIRE_REPORT wire_report;
static BOOL restricted, wire_call;
static ULONGLONG identity[2];
#ifdef BRYNJA_PROBE_EXHAUSTED_EPOCH
static ULONGLONG epoch = ~(ULONGLONG)0;
#else
static ULONGLONG epoch;
#endif
static int identity_state; /* 0 uninitialized, -1 failed, 1 ready; never reset. */

__declspec(noreturn) void PublicProbeAbort(void) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
HRESULT PublicCopyIn(void* destination, ULONG_PTR source, SIZE_T size) {
    return EnclaveCopyIntoEnclave(destination, (void*)source, size);
}
HRESULT PublicCopyOut(ULONG_PTR destination, const void* source, SIZE_T size) {
    return EnclaveCopyOutOfEnclave((void*)destination, source, size);
}
int PublicWireNotify(ULONG_PTR step) {
    if (!wire_call || !active || step > 1) { return 0; }
    return notify_host(step + 2) ? 1 : 0;
}
int PublicWireIdentity(ULONGLONG* output) {
    /* Called only by the linked Rust worker with four initialized words. */
    if (!wire_call || !active || identity_state != 1 || epoch == 0) { return 0; }
    output[0] = identity[0]; output[1] = identity[1]; output[2] = epoch; output[3] = 1;
    return 1;
}
static BOOL admit_identity(void) {
    if (identity_state == 0) {
        identity_state = -1;
#ifdef BRYNJA_PROBE_ENTROPY_FAILURE
        return FALSE;
#else
        if (BCryptGenRandom(NULL, (PUCHAR)identity, sizeof(identity),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) { return FALSE; }
#ifdef BRYNJA_PROBE_ZERO_IDENTITY
        identity[0] = identity[1] = 0;
#endif
        if ((identity[0] | identity[1]) == 0) { return FALSE; }
        identity_state = 1;
#endif
    }
    if (identity_state != 1 || epoch == ~(ULONGLONG)0) { return FALSE; }
    epoch += 1; /* Checked before addition; rejected calls never roll it back. */
    return TRUE;
}
__declspec(noinline) ULONG_PTR PublicRustBody(ULONG_PTR raise) {
    ULONG_PTR result = BaseLockedBody(raise);
    if (wire_call) { wire_report = PublicWireWork(wire_source, PublicLockedLow, PublicLockedHigh); }
    return result;
}
__declspec(dllexport) void* CALLBACK PublicWire(void* context) {
    ULONG_PTR result;
    if (active || wire_call || host_callback == NULL) { return 0; }
    if (EnclaveRestrictContainingProcessAccess(TRUE, NULL) != S_OK) { return 0; }
    restricted = TRUE;
    if (!admit_identity()) { return 0; }
    wire_source = (ULONG_PTR)context;
    wire_call = TRUE;
    __try { result = (ULONG_PTR)PublicLockedWindow(0); }
    __finally { wire_source = 0; wire_call = FALSE; }
    return (void*)result;
}
__declspec(dllexport) void* CALLBACK PublicWireControl(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    if (active || wire_call) { return 0; }
    switch (op) {
    case 16: return (void*)wire_report.status;
    case 17: return (void*)wire_report.snapshot;
    case 18: return (void*)wire_report.workspace;
    case 19: return (void*)wire_report.output;
    case 20: return (void*)wire_report.absorbed;
    case 21: return (void*)wire_report.cleared;
    case 22: return (void*)wire_report.replay;
    case 23: return (void*)wire_report.owner_size;
    case 24: return (void*)(ULONG_PTR)restricted;
    default: return 0;
    }
}
