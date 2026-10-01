/* Private version-19 SHA-NI development image. Scalar image remains unchanged. */
#include <winenclave.h>
#include "cpu_inventory.c"
#include "sha2_batch_accelerated_gate.h"
#include "window_sha2_batch.c"

/* Baseline-only distinct protocol query, no specialized Rust initialization. */
__declspec(dllexport) void* CALLBACK PublicSha2BatchShaNiProtocol(void* context) {
    if (context || active || retained_call || !Sha2BatchAcceleratedReady()) { return 0; }
    return (void*)(ULONG_PTR)0x42524232;
}
