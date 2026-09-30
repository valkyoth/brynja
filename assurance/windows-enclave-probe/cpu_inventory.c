/* Public diagnostic only. No cryptography, secrets, or platform authority. */
#include "synthetic.c"
#include <intrin.h>

#define INVALID_QUERY (~(ULONG_PTR)0)

/* Deliberately queried INSIDE VTL1, not copied from the untrusted host. */
__declspec(dllexport) void* CALLBACK PublicCpuInventory(void* context) {
    ULONG_PTR query = (ULONG_PTR)context;
    int leaf[4] = {0};
    unsigned maximum, subleaves;
    unsigned __int64 xcr;
    if (query == 0) { return (void*)(ULONG_PTR)0x42525943; }
    if (query == 1) { return (void*)(ULONG_PTR)1; }
    if (query > 10) { return (void*)INVALID_QUERY; }
    if (query == 2) {
        ULONG_PTR features = 0;
        if (IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE)) { features |= 1; }
        if (IsProcessorFeaturePresent(PF_XSAVE_ENABLED)) { features |= 2; }
        if (IsProcessorFeaturePresent(PF_AVX_INSTRUCTIONS_AVAILABLE)) { features |= 4; }
        if (IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE)) { features |= 8; }
        return (void*)features;
    }
    /* Exception handling is diagnostic only; a fault is never admission. */
    __try {
        __cpuidex(leaf, 0, 0);
        maximum = (unsigned)leaf[0];
        if (query == 3) { return (void*)(ULONG_PTR)maximum; }
        if (query == 4 || query == 5 || query == 9 || query == 10) {
            if (maximum < 1) { return 0; }
            __cpuidex(leaf, 1, 0);
            if (query == 4) { return (void*)(ULONG_PTR)(unsigned)leaf[3]; }
            if (query == 5) { return (void*)(ULONG_PTR)(unsigned)leaf[2]; }
            /* XGETBV requires both architectural XSAVE and OSXSAVE. */
            if (((unsigned)leaf[2] & 0x0c000000U) != 0x0c000000U) { return 0; }
            xcr = _xgetbv(0);
            return (void*)(ULONG_PTR)(unsigned)(query == 9 ? xcr : xcr >> 32);
        }
        if (maximum < 7) { return 0; }
        __cpuidex(leaf, 7, 0);
        subleaves = (unsigned)leaf[0];
        if (query == 6) { return (void*)(ULONG_PTR)(unsigned)leaf[1]; }
        if (query == 7) { return (void*)(ULONG_PTR)subleaves; }
        if (subleaves < 1) { return 0; }
        __cpuidex(leaf, 7, 1);
        return (void*)(ULONG_PTR)(unsigned)leaf[0];
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return (void*)INVALID_QUERY;
    }
}
