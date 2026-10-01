/* Private version-14 AVX2 development image. Scalar image remains unchanged. */
#include <winenclave.h>
#include "cpu_inventory.c"
#include "sha3_accelerated_gate.h"
#include "window_sha3_stream.c"

/* Baseline-only distinct protocol query, no specialized Rust initialization. */
__declspec(dllexport) void* CALLBACK PublicSha3Avx2Protocol(void* context) {
    if (context || active || retained_call || !Sha3AcceleratedReady()) { return 0; }
    return (void*)(ULONG_PTR)0x42524b31;
}
