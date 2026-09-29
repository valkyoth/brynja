/* Public input/output boundary research. Not a production secret channel. */
#include "window_guard.c"
#include <intrin.h>
typedef struct {
    ULONG_PTR status, snapshot, workspace, output, absorbed, cleared, exported, owner_size;
} REQUEST_REPORT;
_Static_assert(sizeof(REQUEST_REPORT) == 64, "x64 report size");
_Static_assert(offsetof(REQUEST_REPORT, owner_size) == 56, "last report offset");
extern REQUEST_REPORT PublicRequestWork(ULONG_PTR source, ULONG_PTR low, ULONG_PTR high);
static ULONG_PTR request_source;
static REQUEST_REPORT request_report;
static BOOL restricted;

__declspec(noreturn) void PublicProbeAbort(void) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
HRESULT PublicCopyIn(void* destination, ULONG_PTR source, SIZE_T size) {
#ifdef BRYNJA_PROBE_RAW_REQUEST_COPY
    memcpy(destination, (void*)source, size); /* Deliberate negative image. */
    return S_OK;
#else
    return EnclaveCopyIntoEnclave(destination, (void*)source, size);
#endif
}
HRESULT PublicCopyOut(ULONG_PTR destination, const void* source, SIZE_T size) {
    return EnclaveCopyOutOfEnclave((void*)destination, source, size);
}
int PublicSnapshotReady(void) {
    /* Fixed test hook: host may mutate its wire after it has been copied. */
    return notify_host(2) ? 1 : 0;
}
__declspec(noinline) ULONG_PTR PublicRustBody(ULONG_PTR raise) {
    ULONG_PTR result = BaseLockedBody(raise);
    request_report = PublicRequestWork(request_source, PublicLockedLow, PublicLockedHigh);
    return result;
}

__declspec(dllexport) void* CALLBACK PublicRequest(void* context) {
    ULONG_PTR result;
    if (active || host_callback == NULL) { return 0; }
    if (EnclaveRestrictContainingProcessAccess(TRUE, NULL) != S_OK) { return 0; }
    restricted = TRUE; /* Never relaxed by this prototype. */
    request_source = (ULONG_PTR)context; /* Opaque: never dereferenced here. */
    __try { result = (ULONG_PTR)PublicLockedWindow(0); }
    __finally { request_source = 0; }
    return (void*)result;
}
__declspec(dllexport) void* CALLBACK PublicRequestControl(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    if (active) { return 0; }
    switch (op) {
    case 16: return (void*)request_report.status;
    case 17: return (void*)request_report.snapshot;
    case 18: return (void*)request_report.workspace;
    case 19: return (void*)request_report.output;
    case 20: return (void*)request_report.absorbed;
    case 21: return (void*)request_report.cleared;
    case 22: return (void*)request_report.exported;
    case 23: return (void*)request_report.owner_size;
    case 24: return (void*)(ULONG_PTR)restricted;
    default: return 0;
    }
}
