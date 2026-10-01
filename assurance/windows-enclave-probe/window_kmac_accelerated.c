/* Private version-15 AVX2 development image. Scalar image remains unchanged. */
#include <winenclave.h>
#include "cpu_inventory.c"
#include "kmac_accelerated_gate.h"
#include "window_kmac_stream.c"

/* Baseline-only distinct protocol query, no specialized Rust initialization. */
__declspec(dllexport) void* CALLBACK PublicKmacAvx2Protocol(void* context) {
    if (context || active || retained_call || !KmacAcceleratedReady()) { return 0; }
    return (void*)(ULONG_PTR)0x42524b32;
}
