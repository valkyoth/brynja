/* Included in the actual canary, not a separate diagnostic enclave. The build
 * pins the SDK file. This local comparison is NOT remote attestation. */
#include "sdk_expected.h"

/* These SDK declarations are not dllimport on this kit: &EnclaveCopy* denotes
 * a local jump thunk. Inspect the actual import slots, not those thunk addresses.
 * The x64 import library provides these data symbols. */
extern HRESULT (WINAPI* const __imp_EnclaveCopyIntoEnclave)(void*, const void*, SIZE_T);
extern HRESULT (WINAPI* const __imp_EnclaveCopyOutOfEnclave)(void*, const void*, SIZE_T);

static BOOL isolated_sdk(BOOL changed_expectation) {
    HMODULE module = NULL;
    SIZE_T i;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            L"vertdll.dll", &module) || !module) { return FALSE; }
    __try {
        const unsigned char* base = (const unsigned char*)module;
        const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
        const IMAGE_NT_HEADERS64* nt;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 64 ||
                dos->e_lfanew > 4096) { return FALSE; }
        nt = (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
                nt->OptionalHeader.SizeOfImage != SDK_IMAGE_SIZE) { return FALSE; }
        /* CallEnclave is dllimport; copy accessors require explicit IAT slots.
         * No same-named GetProcAddress result substitutes for actual binding. */
        if ((const unsigned char*)CallEnclave != base + 0x1010 ||
                (const unsigned char*)__imp_EnclaveCopyIntoEnclave != base + 0x4090 ||
                (const unsigned char*)__imp_EnclaveCopyOutOfEnclave != base + 0x40b0) { return FALSE; }
        for (i = 0; i < sizeof(sdk_expected); ++i) {
            unsigned char expected = sdk_expected[i];
            if (changed_expectation && i == 0) { expected ^= 1; }
            if (((const volatile unsigned char*)base)[SDK_TEXT_RVA + i] != expected) {
                return FALSE;
            }
        }
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}
