/* Three-wave fixed PUBLIC fixture, no shipping API/qualification claim. */
#include <winenclave.h>
#include <intrin.h>
#include "cpu_inventory.c"
#include "parallel_accelerated_gate.h"
#include "parallel_wave_native_gate.h"

const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG), IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    0, 0, 0, 0, {0x42, 0x52, 0x59, 0x4e}, {0x50, 0x41, 0x57, 0x56},
    1, 1, 0x10000000, 5, IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE
};
static volatile LONG root_identity, root_claimed, root_generation;
extern ULONG_PTR PrivateWaveRoot(ULONG_PTR identity);
extern ULONG_PTR PrivateWaveLeaf(unsigned int generation, ULONG_PTR lane);
__declspec(noreturn) void PrivateWaveAbort(void) { __fastfail(7); }
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
