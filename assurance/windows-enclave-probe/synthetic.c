/* Platform experiment only: public values, no cryptography or secret input. */
#include <winenclave.h>

const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG), IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    0, 0, 0, 0, {0x42, 0x52, 0x59, 0x4e}, {0x50, 0x52, 0x4f, 0x42},
    1, 1, 0x10000000, 1, IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE
};

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}

__declspec(dllexport) void* CALLBACK PublicProbe(void* context) {
    return (void*)((ULONG_PTR)context ^ (ULONG_PTR)0x4252594e);
}
