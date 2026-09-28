/* Public-marker OS-stack experiment only; NOT a protected execution backend. */
#include "synthetic.c"

#define WINDOW_EXCEPTION ((DWORD)0xe0425259)
ULONG_PTR PublicWindowLow;
ULONG_PTR PublicWindowHigh;
static volatile ULONG_PTR marker_address;
static volatile ULONG_PTR handler_address;
static volatile ULONG_PTR steps;
extern ULONG_PTR PublicWindowFrame(ULONG_PTR raise);

__declspec(noinline) static void window_work(ULONG_PTR raise) {
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
        if (raise) { RaiseException(WINDOW_EXCEPTION, 0, 0, NULL); }
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

/* The exact synthetic exception is caught inside the window, not across the
 * assembly boundary. This does not test Rust panics or unrelated exceptions. */
__declspec(noinline) ULONG_PTR PublicWindowBody(ULONG_PTR raise) {
    volatile unsigned char live = 0;
    handler_address = (ULONG_PTR)&live;
    __try {
        window_work(raise);
    } __except (GetExceptionCode() == WINDOW_EXCEPTION ?
                EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        live = 1;
        steps |= 32;
    }
    return steps;
}

__declspec(dllexport) void* CALLBACK PublicWindow(void* context) {
    ULONG_PTR operation = (ULONG_PTR)context;
    if (operation <= 1) {
        steps = 0;
        marker_address = 0;
        handler_address = 0;
        return (void*)PublicWindowFrame(operation);
    }
    if (operation == 2) { return (void*)PublicWindowLow; }
    if (operation == 3) { return (void*)PublicWindowHigh; }
    if (operation == 4) { return (void*)handler_address; }
    if (operation == 5) { return (void*)marker_address; }
    if (operation == 6) { return (void*)steps; }
    return 0;
}
