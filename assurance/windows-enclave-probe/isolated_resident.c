/* Separate 08A PUBLIC-vector staging experiment; not a supported secret API.
 * Never replaces the original canary or the nineteen family images. */
#include "window_guard.c"
#include "isolated_sdk.h"

#define STAGE_PAGE 4096
typedef struct { ULONG_PTR input, length, output, control; } ResidentRequest;
static ResidentRequest request;
static unsigned char* stage_region;
static BOOL busy, stage_attempted, stage_admitted;
static ULONG_PTR body_calls, published, last_status, retired, released;
extern ULONG_PTR IsolatedSha256(unsigned char*, SIZE_T, unsigned char*);
extern void IsolatedRetirePage(unsigned char*);

void PublicProbeAbort(void) { __fastfail(7); }

static BOOL stage_notify(ULONG_PTR event) {
    void* reply = NULL;
    return host_callback && stage_region &&
        CallEnclave(host_callback, (void*)(((ULONG_PTR)stage_region + STAGE_PAGE) | event),
            FALSE, &reply) && reply == (void*)1;
}

static BOOL stage_guards(void) {
    return page_info((ULONG_PTR)stage_region, PAGE_NOACCESS) &&
        page_info((ULONG_PTR)stage_region + STAGE_PAGE, PAGE_READWRITE) &&
        page_info((ULONG_PTR)stage_region + 2 * STAGE_PAGE, PAGE_NOACCESS);
}

/* No payload exists yet. The allocation is fresh and cannot alias image data,
 * the current stack, or the later stack window. Only the middle page is used. */
static BOOL stage_open(void) {
    DWORD old;
    stage_region = VirtualAlloc(NULL, 3 * STAGE_PAGE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!stage_region) { return FALSE; }
    if (((ULONG_PTR)stage_region & (STAGE_PAGE - 1)) ||
        !VirtualProtect(stage_region, STAGE_PAGE, PAGE_NOACCESS, &old) ||
        !VirtualProtect(stage_region + 2 * STAGE_PAGE, STAGE_PAGE, PAGE_NOACCESS, &old) ||
        !stage_guards()) { return FALSE; }
    stage_attempted = TRUE;
    stage_admitted = stage_notify(8);
    return stage_admitted;
}

static void stage_close(void) {
    if (stage_region) {
        /* No SDK entry until this non-return-on-dirty leaf has retired all 4096
         * bytes, including unused capacity. No borrow or Rust frame remains. */
        IsolatedRetirePage(stage_region + STAGE_PAGE);
        retired = STAGE_PAGE;
        if (stage_attempted && !stage_notify(10)) { __fastfail(7); }
        stage_admitted = stage_attempted = FALSE;
        if (!VirtualFree(stage_region, 0, MEM_RELEASE)) { __fastfail(7); }
        stage_region = NULL;
        released = 1;
    }
}

__declspec(noinline) ULONG_PTR PublicRustBody(ULONG_PTR ignored) {
    (void)ignored;
    if (!busy || !active || !admitted || !stage_admitted || !stage_region) { return 0; }
    body_calls += 1;
    return IsolatedSha256(stage_region + STAGE_PAGE, request.length,
        stage_region + STAGE_PAGE + 1024);
}

__declspec(dllexport) void* CALLBACK PublicIsolatedSha256(void* context) {
    ULONG_PTR status = 0, wrapped;
    SIZE_T i;
    if (busy || active || stage_region || !host_callback) { return 0; }
    busy = TRUE;
    body_calls = published = last_status = retired = released = 0;
    if (EnclaveRestrictContainingProcessAccess(TRUE, NULL) != S_OK ||
        !isolated_sdk(FALSE)) { status = 10; goto done; }
    if (EnclaveCopyIntoEnclave(&request, context, sizeof(request)) != S_OK) {
        status = 11; goto done;
    }
    if (request.length > 1024 || request.control > 1) { status = 12; goto done; }
    if (request.control == 1 && !isolated_sdk(TRUE)) { status = 13; goto done; }
    if (!stage_open()) { status = 17; goto done; }
    if (request.length && EnclaveCopyIntoEnclave(stage_region + STAGE_PAGE,
            (void*)request.input, request.length) != S_OK) { status = 14; goto done; }
    /* Still a transport phase: no hash frame or state exists on this thread. */
    if (!stage_notify(9)) { status = 18; goto done; }
    wrapped = (ULONG_PTR)PublicLockedWindow(0);
    if (wrapped != 65 || !cleared || !admitted) { status = 15; goto done; }
    if (EnclaveCopyOutOfEnclave((void*)request.output, stage_region + STAGE_PAGE + 1024,
            32) != S_OK) { status = 16; goto done; }
    published = 1;
    status = 1;
done:
    stage_close();
    for (i = 0; i < sizeof(request); ++i) { ((volatile unsigned char*)&request)[i] = 0; }
    last_status = status;
    busy = FALSE;
    return (void*)status;
}

__declspec(dllexport) void* CALLBACK PublicIsolatedObserve(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    if (active || busy) { return 0; }
    if (op == 0) { return (void*)body_calls; }
    if (op == 1) { return (void*)published; }
    if (op == 2) { return (void*)last_status; }
    if (op == 3) { return (void*)(ULONG_PTR)(!stage_region && !stage_admitted && !stage_attempted); }
    if (op == 4) { return (void*)retired; }
    if (op == 5) { return (void*)released; }
    return 0;
}
