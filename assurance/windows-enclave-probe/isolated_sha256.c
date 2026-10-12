/* Package 08A PUBLIC-vector feasibility canary. Not a supported secret API.
 * One enclave thread. Staging is enclave-owned, not residency-qualified here.
 * The frozen nineteen family images are deliberately unaffected. */
#include "window_guard.c"
#include "isolated_sdk.h"

typedef struct {
    ULONG_PTR input, length, output, control;
} IsolatedRequest;
static IsolatedRequest request;
static unsigned char input_stage[1024], output_stage[32];
static BOOL busy;
static ULONG_PTR body_calls, published, last_status;
extern ULONG_PTR IsolatedSha256(unsigned char*, SIZE_T, unsigned char*);

void PublicProbeAbort(void) { __fastfail(7); }

static void retire_staging(void) {
    SIZE_T i;
    for (i = 0; i < sizeof(input_stage); ++i) { ((volatile unsigned char*)input_stage)[i] = 0; }
    for (i = 0; i < sizeof(output_stage); ++i) { ((volatile unsigned char*)output_stage)[i] = 0; }
    for (i = 0; i < sizeof(request); ++i) { ((volatile unsigned char*)&request)[i] = 0; }
}

/* Entire compute subtree must later be established from emitted code. No SDK,
 * callback, allocation, query or transport appears in this source-level body. */
__declspec(noinline) ULONG_PTR PublicRustBody(ULONG_PTR ignored) {
    (void)ignored;
    if (!busy || !active || !admitted) { return 0; }
    body_calls += 1;
    return IsolatedSha256(input_stage, request.length, output_stage);
}

__declspec(dllexport) void* CALLBACK PublicIsolatedSha256(void* context) {
    ULONG_PTR status = 0, wrapped;
    if (busy || active || !host_callback) { return 0; }
    busy = TRUE;
    body_calls = published = last_status = 0;
    /* All SDK work here precedes the first hash frame on this thread. */
    if (EnclaveRestrictContainingProcessAccess(TRUE, NULL) != S_OK ||
            !isolated_sdk(FALSE)) { status = 10; goto done; }
    if (EnclaveCopyIntoEnclave(&request, context, sizeof(request)) != S_OK) {
        status = 11; goto done;
    }
    if (request.length > sizeof(input_stage) || request.control > 1) { status = 12; goto done; }
    if (request.control == 1 && !isolated_sdk(TRUE)) { status = 13; goto done; }
    if (request.length && EnclaveCopyIntoEnclave(input_stage, (void*)request.input,
            request.length) != S_OK) { status = 14; goto done; }
    /* PublicLockedWindow holds active until assembly clears/readbacks the
     * compute window, restores guards and completes its register boundary. */
    wrapped = (ULONG_PTR)PublicLockedWindow(0);
    if (wrapped != 65 || !cleared || !admitted) { status = 15; goto done; }
    /* Only explicitly public test digests are published. No hash frame is live. */
    if (EnclaveCopyOutOfEnclave((void*)request.output, output_stage,
            sizeof(output_stage)) != S_OK) { status = 16; goto done; }
    published = 1;
    status = 1;
done:
    retire_staging();
    last_status = status;
    busy = FALSE;
    return (void*)status;
}

__declspec(dllexport) void* CALLBACK PublicIsolatedObserve(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    SIZE_T i;
    unsigned char residue = 0;
    if (active || busy) { return 0; }
    if (op == 0) { return (void*)body_calls; }
    if (op == 1) { return (void*)published; }
    if (op == 2) { return (void*)last_status; }
    if (op != 3) { return 0; }
    for (i = 0; i < sizeof(input_stage); ++i) { residue |= ((volatile unsigned char*)input_stage)[i]; }
    for (i = 0; i < sizeof(output_stage); ++i) { residue |= ((volatile unsigned char*)output_stage)[i]; }
    for (i = 0; i < sizeof(request); ++i) { residue |= ((volatile unsigned char*)&request)[i]; }
    return (void*)(ULONG_PTR)(residue == 0);
}
