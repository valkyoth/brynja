/* Public-marker worker inventory only; not a production runtime or crypto. */
#include "synthetic.c"

__declspec(thread) static volatile unsigned char public_tls[8192];
static ULONG_PTR inventory[9];

__declspec(dllexport) void* CALLBACK PublicWorker(void* context) {
    ULONG_PTR operation = (ULONG_PTR)context;
    volatile unsigned char public_frame[8192];
    MEMORY_BASIC_INFORMATION stack_info, tls_info;
    SIZE_T i;
    BOOL correct = TRUE;
    if (operation >= 1 && operation <= 9) {
        return (void*)inventory[operation - 1];
    }
    if (operation != 0) { return 0; }
    if (VirtualQuery((const void*)public_frame, &stack_info, sizeof(stack_info)) != sizeof(stack_info) ||
        VirtualQuery((const void*)public_tls, &tls_info, sizeof(tls_info)) != sizeof(tls_info)) {
        return 0;
    }
    inventory[0] = (ULONG_PTR)public_frame;
    inventory[1] = (ULONG_PTR)stack_info.AllocationBase;
    inventory[2] = (ULONG_PTR)stack_info.BaseAddress;
    inventory[3] = stack_info.RegionSize;
    inventory[4] = (ULONG_PTR)public_tls;
    inventory[5] = (ULONG_PTR)tls_info.AllocationBase;
    inventory[6] = (ULONG_PTR)tls_info.BaseAddress;
    inventory[7] = tls_info.RegionSize;
    inventory[8] = 0;
    for (i = 0; i < sizeof(public_frame); ++i) {
        public_frame[i] = 0xa5;
        public_tls[i] = 0x5a;
    }
    for (i = 0; i < sizeof(public_frame); ++i) {
        if (public_frame[i] != 0xa5 || public_tls[i] != 0x5a) { correct = FALSE; }
    }
#ifndef BRYNJA_PROBE_SKIP_CLEAR
    for (i = 0; i < sizeof(public_frame); ++i) {
        public_frame[i] = 0;
        public_tls[i] = 0;
    }
#endif
    for (i = 0; i < sizeof(public_frame); ++i) {
        if (public_frame[i] != 0 || public_tls[i] != 0) { correct = FALSE; }
    }
    if (correct) { inventory[8] = sizeof(public_frame); }
    return (void*)inventory[8];
}
