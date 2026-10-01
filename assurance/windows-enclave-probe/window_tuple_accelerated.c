/* Private version-16 AVX2 development image. Scalar image remains unchanged. */
#include <winenclave.h>
#include "cpu_inventory.c"
#include "tuple_accelerated_gate.h"
#include "window_tuple_stream.c"

/* Baseline-only distinct protocol query, no specialized Rust initialization. */
__declspec(dllexport) void* CALLBACK PublicTupleAvx2Protocol(void* context) {
    if (context || active || retained_call || !TupleAcceleratedReady()) { return 0; }
    return (void*)(ULONG_PTR)0x42525432;
}
