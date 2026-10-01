/* Private version-18 AVX2 development image. Scalar image remains unchanged. */
#include <winenclave.h>
#include "cpu_inventory.c"
#include "parallel_accelerated_gate.h"
#include "window_parallel_stream.c"

/* Baseline-only distinct protocol query, no specialized Rust initialization. */
__declspec(dllexport) void* CALLBACK PublicParallelAvx2Protocol(void* context) {
    if (context || active || retained_call || !ParallelAcceleratedReady()) { return 0; }
    return (void*)(ULONG_PTR)0x42525032;
}
