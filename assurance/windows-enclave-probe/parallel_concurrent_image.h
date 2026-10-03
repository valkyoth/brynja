/* Private one-shot PUBLIC-fixture image; no production API/admission claim. */
#include <winenclave.h>
#include <intrin.h>
#include "cpu_inventory.c"
#include "parallel_accelerated_gate.h"

const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG), IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    0, 0, 0, 0, {0x42, 0x52, 0x59, 0x4e}, {0x50, 0x41, 0x52, 0x43},
    1, 1, 0x10000000, 5, IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE
};
static volatile LONG root_identity;
static volatile LONG root_claimed;
extern ULONG_PTR PrivateParallelRoot(ULONG_PTR identity);
extern ULONG_PTR PrivateParallelLeaf(ULONG_PTR lane);
__declspec(dllexport) void* CALLBACK PublicStackWorker(void* context);
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
__declspec(noreturn) void PrivateParallelAbort(void) { __fastfail(7); }

__declspec(dllexport) void* CALLBACK PublicParallelRoot(void* context) {
    ULONG_PTR identity = (ULONG_PTR)context;
    if (identity < 1 || identity > 4 ||
        InterlockedCompareExchange(&root_claimed, 1, 0) != 0) return 0;
    InterlockedExchange(&root_identity, (LONG)identity);
    return PublicStackWorker((void*)4);
}
