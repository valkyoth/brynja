/* Private development image. Existing scalar image is not modified.
 * Build binds the inventory, version-13 copies and exact guarded entry. */
#include <winenclave.h>
#include "cpu_inventory.c"
#include "sha2_accelerated_gate.h"
#include "window_sha2_stream.c"

/* A distinct reviewed protocol is required, never a scalar-image fallback.
 * This baseline-only query performs no Rust initialization. */
__declspec(dllexport) void* CALLBACK PublicSha2ShaNiProtocol(void* context) {
    if (context || active || retained_call || !Sha2AcceleratedReady()) { return 0; }
    return (void*)(ULONG_PTR)0x42525331;
}
