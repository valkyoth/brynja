/* Public-code diagnostic only. Never accepts secret input or a host pointer. */
#include "synthetic.c"
#include "sdk_expected.h"

#define REJECTED (~(ULONG_PTR)0)
#define MATCHED ((ULONG_PTR)0x42525949)

__declspec(dllexport) void* CALLBACK PublicSdkIdentity(void* context) {
    ULONG_PTR query = (ULONG_PTR)context;
    HMODULE module = NULL;
    ULONG_PTR index;
    if (query > 2) { return (void*)REJECTED; }
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            query == 2 ? L"brynja-nonexistent-sdk.dll" : L"vertdll.dll", &module)
            || !module) { return (void*)REJECTED; }
    /* The input file and supported image geometry are pinned by the builder.
       A changed/inaccessible mapping rejects; no arbitrary address is read. */
    __try {
        const unsigned char* base = (const unsigned char*)module;
        const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
        const IMAGE_NT_HEADERS64* nt;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 64
                || dos->e_lfanew > 4096) { return (void*)REJECTED; }
        nt = (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE
                || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
                || nt->OptionalHeader.SizeOfImage != SDK_IMAGE_SIZE) {
            return (void*)REJECTED;
        }
        if ((const unsigned char*)GetProcAddress(module, "CallEnclave") != base + 0x1010
                || (const unsigned char*)GetProcAddress(module, "EnclaveCopyIntoEnclave") != base + 0x4090
                || (const unsigned char*)GetProcAddress(module, "EnclaveCopyOutOfEnclave") != base + 0x40b0) {
            return (void*)REJECTED;
        }
        /* Volatile reads prevent replacing the observed loaded bytes with the
           compiled expectations. Mutation changes the expectation, not the OS. */
        for (index = 0; index < sizeof(sdk_expected); ++index) {
            unsigned char expected = sdk_expected[index];
            if (query == 1 && index == 0) { expected ^= 1; }
            if (((const volatile unsigned char*)base)[SDK_TEXT_RVA + index] != expected) {
                return (void*)(ULONG_PTR)(SDK_TEXT_RVA + index);
            }
        }
        return (void*)MATCHED;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return (void*)REJECTED;
    }
}
