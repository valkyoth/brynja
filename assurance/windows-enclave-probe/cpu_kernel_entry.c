/* Public-vector experiment. No host input buffers or secret processing. */
#include "cpu_inventory.c"
extern SIZE_T PublicCpuKernels(SIZE_T route);
__declspec(noreturn) void PublicProbeAbort(void) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }

__declspec(dllexport) void* CALLBACK PublicCpuKernelProbe(void* context) {
    ULONG_PTR route = (ULONG_PTR)context;
    ULONG_PTR words[11];
    ULONG_PTR i;
    if (route < 1 || route > 5) { return 0; }
    /* The entire Rust image is specialized: require its COMPLETE bundle even
       for SHA-NI, before executing any compiler-generated Rust instruction. */
    for (i = 0; i < 11; ++i) {
        words[i] = (ULONG_PTR)PublicCpuInventory((void*)i);
        if (words[i] == INVALID_QUERY) { return 0; }
    }
    if (words[0] != 0x42525943 || words[1] != 1 || words[2] != 15 || words[3] < 7 ||
        !(words[4] & (1U << 26)) || (words[5] & 0x1c000000U) != 0x1c000000U ||
        !(words[6] & (1U << 29)) || !(words[6] & (1U << 5)) || (words[9] & 6) != 6) { return 0; }
    return (void*)PublicCpuKernels(route);
}
