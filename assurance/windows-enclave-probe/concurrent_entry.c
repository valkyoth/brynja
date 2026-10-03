/* Public-data concurrency experiment ONLY. No protected cryptographic owner. */
#include <winenclave.h>
#include <intrin.h>

const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG), IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    0, 0, 0, 0, {0x42, 0x52, 0x59, 0x4e}, {0x43, 0x4f, 0x4e, 0x43},
    1, 1, 0x10000000, 5, IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE
};

static volatile LONG claimed[4], active, completed, released, exhausted;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}

__declspec(dllexport) void* CALLBACK PublicConcurrentWorker(void* context) {
    ULONG_PTR lane = (ULONG_PTR)context;
    unsigned __int64 remaining = 0x100000000ULL;
    LONG bit;
    if (lane >= 4 || InterlockedCompareExchange(&claimed[lane], 1, 0) != 0)
        return (void*)(ULONG_PTR)-1;
    bit = (LONG)(1U << lane);
    InterlockedOr(&active, bit);
    while (InterlockedCompareExchange(&released, 0, 0) == 0 && remaining != 0) {
        --remaining;
        _mm_pause();
    }
    if (remaining == 0) InterlockedOr(&exhausted, bit);
    InterlockedAnd(&active, ~bit);
    InterlockedOr(&completed, bit);
    return remaining == 0 ? (void*)(ULONG_PTR)-1 : (void*)(lane + 100);
}

__declspec(dllexport) void* CALLBACK PublicConcurrentControl(void* context) {
    switch ((ULONG_PTR)context) {
    case 0: return (void*)(ULONG_PTR)InterlockedCompareExchange(&active, 0, 0);
    case 1: InterlockedExchange(&released, 1); return (void*)(ULONG_PTR)1;
    case 2: return (void*)(ULONG_PTR)InterlockedCompareExchange(&completed, 0, 0);
    case 3: return (void*)(ULONG_PTR)InterlockedCompareExchange(&exhausted, 0, 0);
    default: return (void*)(ULONG_PTR)-1;
    }
}
