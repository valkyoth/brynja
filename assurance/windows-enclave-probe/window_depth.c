/* Public-only stack-depth experiment. No arbitrary callbacks or secret input. */
#include "window_guard.c"

#define DEPTH_EXCEPTION ((DWORD)0xe0425260)
ULONG_PTR PublicDepthBounded = 1;
static ULONG_PTR requested_depth, raise_at_stop;
/* visits, first/min frame, reject frame, rejects, leaves, catches, result,
 * invariant failure, stop-helper local address. All are public diagnostics. */
static ULONG_PTR depth_stats[10];
extern ULONG_PTR PublicDepthRecurse(ULONG_PTR remaining);

ULONG_PTR PublicDepthVisit(ULONG_PTR frame, ULONG_PTR remaining) {
    ULONG_PTR visits = depth_stats[0];
    if (visits > requested_depth || remaining != requested_depth - visits ||
        frame < PublicLockedLow || frame > PublicLockedHigh - 4096 ||
        (frame & 15) != 0 || (visits != 0 && depth_stats[2] - frame != 4112)) {
        depth_stats[8] = 1; return 0;
    }
    if (visits == 0) { depth_stats[1] = frame; }
    depth_stats[2] = frame;
    depth_stats[0] = visits + 1;
    return 1;
}

ULONG_PTR PublicDepthLeaf(void) {
    volatile unsigned char local = 0;
    depth_stats[9] = (ULONG_PTR)&local;
    depth_stats[5] += 1;
    if (raise_at_stop) { RaiseException(DEPTH_EXCEPTION, 0, 0, NULL); }
    return 1;
}

ULONG_PTR PublicDepthReject(ULONG_PTR frame) {
    volatile unsigned char local = 0;
    depth_stats[9] = (ULONG_PTR)&local;
    depth_stats[3] = frame;
    depth_stats[4] += 1;
    if (raise_at_stop) { RaiseException(DEPTH_EXCEPTION, 0, 0, NULL); }
    return 2;
}

ULONG_PTR PublicDepthBody(ULONG_PTR raise) {
    ULONG_PTR result = BaseLockedBody(raise);
    SIZE_T i;
    for (i = 0; i < 10; ++i) { depth_stats[i] = 0; }
    raise_at_stop = raise;
    __try { depth_stats[7] = PublicDepthRecurse(requested_depth); }
    __except (GetExceptionCode() == DEPTH_EXCEPTION ?
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        depth_stats[6] = 1;
        depth_stats[7] = 3;
    }
    return result;
}

__declspec(dllexport) void* CALLBACK PublicDepthControl(void* context) {
    ULONG_PTR operation = (ULONG_PTR)context;
    if (active) { return 0; }
    if (operation <= 32 || (operation >= 256 && operation <= 288)) {
        requested_depth = operation & 255;
        PublicDepthBounded = (operation & 256) != 0;
        return (void*)1;
    }
    if (operation >= 512 && operation < 522) { return (void*)depth_stats[operation - 512]; }
    return 0;
}
