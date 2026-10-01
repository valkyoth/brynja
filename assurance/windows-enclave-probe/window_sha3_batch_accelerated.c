/* Private version-17 AVX2 development image. Scalar image remains unchanged. */
#include <winenclave.h>
#include "cpu_inventory.c"
#include "sha3_batch_accelerated_gate.h"
#include "window_sha3_batch.c"

/* Baseline-only distinct protocol query, no specialized Rust initialization. */
__declspec(dllexport) void* CALLBACK PublicSha3BatchAvx2Protocol(void* context) {
    if (context || active || retained_call || !Sha3BatchAcceleratedReady()) { return 0; }
    return (void*)(ULONG_PTR)0x42524233;
}
