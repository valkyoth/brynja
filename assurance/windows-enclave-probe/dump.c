/* Synthetic public markers only. Never link this experiment into a crate. */
#include "synthetic.c"

static volatile unsigned char public_region[8192];

__declspec(dllexport) void* CALLBACK PublicRegion(void* context) {
    ULONG_PTR operation = (ULONG_PTR)context;
    SIZE_T i;
    if (operation == 1 || operation == 3) {
        for (i = 0; i < sizeof(public_region); ++i) {
            public_region[i] = operation == 1 ? 0xa5 : 0;
        }
    }
    if (operation == 1) {
        return (void*)public_region;
    }
    if (operation == 2 || operation == 3) {
        for (i = 0; i < sizeof(public_region); ++i) {
            if (public_region[i] != (operation == 2 ? 0xa5 : 0)) {
                return 0;
            }
        }
        return (void*)(ULONG_PTR)sizeof(public_region);
    }
    return 0;
}
