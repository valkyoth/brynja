/* Extension used only by the transport-data variant of the PUBLIC canary.
 * The original text-only canary and evidence are not rewritten. */
#define isolated_sdk isolated_text_sdk
#include "isolated_sdk.h"
#undef isolated_sdk
#include "sdk_data_expected.h"

static BOOL transport_readonly(const unsigned char* start, SIZE_T size) {
    ULONG_PTR cursor = (ULONG_PTR)start, end = cursor + size;
    if (end < cursor) { return FALSE; }
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info;
        ULONG_PTR region_end;
        if (VirtualQuery((void*)cursor, &info, sizeof(info)) != sizeof(info) ||
            info.State != MEM_COMMIT || info.Protect != PAGE_READONLY ||
            (ULONG_PTR)info.BaseAddress > cursor || info.RegionSize == 0) { return FALSE; }
        region_end = (ULONG_PTR)info.BaseAddress + info.RegionSize;
        if (region_end <= cursor) { return FALSE; }
        cursor = region_end < end ? region_end : end;
    }
    return TRUE;
}

/* mode 0 = real expectation; 1 = text drift; 2..4 = each data-range drift.
 * Negative controls alter the expected byte, never live signed SDK storage. */
static BOOL transport_identity(ULONG_PTR identity_mode) {
    HMODULE module = NULL;
    SIZE_T n, i;
    if (identity_mode > 4 || !isolated_text_sdk(identity_mode == 1) ||
        !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            L"vertdll.dll", &module) || !module) { return FALSE; }
    __try {
        const unsigned char* base = (const unsigned char*)module;
        for (n = 0; n < sizeof(sdk_data)/sizeof(sdk_data[0]); ++n) {
            const SdkDataExpected* row = &sdk_data[n];
            if (row->rva > SDK_IMAGE_SIZE || row->size > SDK_IMAGE_SIZE - row->rva ||
                !transport_readonly(base + row->rva, row->size)) { return FALSE; }
            for (i = 0; i < row->size; ++i) {
                unsigned char expected = row->bytes[i];
                if (identity_mode == n + 2 && i == 0) { expected ^= 1; }
                if (((const volatile unsigned char*)base)[row->rva + i] != expected) {
                    return FALSE;
                }
            }
        }
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

static BOOL isolated_sdk(BOOL changed_expectation) {
    return transport_identity(changed_expectation ? 1 : 0);
}
