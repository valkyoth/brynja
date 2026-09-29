/* Synthetic public-marker handshake only. NOT a production secret API. */
#include "synthetic.c"

#define LOCK_EXCEPTION ((DWORD)0xe0425259)
ULONG_PTR PublicLockedLow;
ULONG_PTR PublicLockedHigh;
static LPENCLAVE_ROUTINE host_callback;
static volatile BOOL active;
static volatile ULONG_PTR marker_address, handler_address, steps, admitted, cleared;
extern ULONG_PTR PublicLockedFrame(ULONG_PTR raise);

static BOOL notify_host(ULONG_PTR event) {
    void* reply = NULL;
    return host_callback != NULL &&
        CallEnclave(host_callback, (void*)(PublicLockedLow | event), FALSE, &reply) &&
        reply == (void*)1;
}

ULONG_PTR PublicLockedAdmit(void) {
    if (!active || PublicLockedHigh - PublicLockedLow != 65536 ||
        (PublicLockedLow & 15) != 0) { return 0; }
    admitted = notify_host(0) ? 1 : 0;
    return admitted;
}

ULONG_PTR PublicLockedFinish(ULONG_PTR result) {
    /* Assembly invokes this only after complete window zero readback. A reply
     * confirms host orchestration, NOT independent attestation of residency. */
    cleared = 1;
    return notify_host(1) ? result : 0;
}

__declspec(noinline) static void locked_work(ULONG_PTR raise) {
    volatile unsigned char marker[256];
    SIZE_T i;
    BOOL correct = TRUE;
    marker_address = (ULONG_PTR)marker;
    steps |= 1;
    __try {
        for (i = 0; i < sizeof(marker); ++i) { marker[i] = 0xa5; }
        for (i = 0; i < sizeof(marker); ++i) {
            if (marker[i] != 0xa5) { correct = FALSE; }
        }
        if (correct) { steps |= 2; }
        if (raise) { RaiseException(LOCK_EXCEPTION, 0, 0, NULL); }
        steps |= 16;
    } __finally {
        steps |= 4;
        for (i = 0; i < sizeof(marker); ++i) { marker[i] = 0; }
        for (i = 0; i < sizeof(marker); ++i) {
            if (marker[i] != 0) { correct = FALSE; }
        }
        if (correct) { steps |= 8; }
    }
}

__declspec(noinline) ULONG_PTR PublicLockedBody(ULONG_PTR raise) {
    volatile unsigned char live = 0;
    if (!admitted) { return 0; }
    handler_address = (ULONG_PTR)&live;
    __try {
        locked_work(raise);
    } __except (GetExceptionCode() == LOCK_EXCEPTION ?
                EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        live = 1;
        steps |= 32;
    }
    return steps;
}

/* Explicitly trusted synthetic host callback. No real secret inputs accepted. */
__declspec(dllexport) void* CALLBACK PublicLockedHost(void* context) {
    if (active) { return 0; }
    host_callback = (LPENCLAVE_ROUTINE)context;
    return (void*)1;
}

__declspec(dllexport) void* CALLBACK PublicLockedWindow(void* context) {
    ULONG_PTR operation = (ULONG_PTR)context;
    ULONG_PTR result;
    if (active) { return 0; }
    if (operation <= 1 && host_callback != NULL) {
        active = TRUE;
        steps = admitted = cleared = marker_address = handler_address = 0;
        __try { result = PublicLockedFrame(operation); }
        __finally { active = FALSE; }
        return (void*)result;
    }
    if (operation == 2) { return (void*)PublicLockedLow; }
    if (operation == 3) { return (void*)PublicLockedHigh; }
    if (operation == 4) { return (void*)handler_address; }
    if (operation == 5) { return (void*)marker_address; }
    if (operation == 6) { return (void*)steps; }
    if (operation == 7) { return (void*)cleared; }
    if (operation == 8) { return (void*)admitted; }
    return 0;
}
