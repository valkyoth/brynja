/* Synthetic owned allocation only; public markers, never cryptography. */
#include "synthetic.c"

#define PAYLOAD 8192
#define PAGE_BYTES 4096
#define RESERVATION 65536
static unsigned char* owned_base;
static volatile unsigned char* owned_data;
/* 0 empty, 1 allocated/zero, 2 dirty, 3 cleared, 4 failed setup. */
static ULONG_PTR phase;
static ULONG_PTR last_error;
static ULONG_PTR geometry[13];

static BOOL is_byte(unsigned char value) {
    SIZE_T i;
    BOOL correct = TRUE;
    for (i = 0; i < PAYLOAD; ++i) {
        if (owned_data[i] != value) { correct = FALSE; }
    }
    return correct;
}

static ULONG_PTR allocate_owned(void) {
    MEMORY_BASIC_INFORMATION low, data, high;
    if (phase != 0 || owned_base != NULL) { return 0; }
    last_error = 0;
    owned_base = VirtualAlloc(NULL, RESERVATION, MEM_RESERVE, PAGE_NOACCESS);
    if (owned_base == NULL) { last_error = GetLastError(); return 0; }
    phase = 4;
    owned_data = VirtualAlloc(owned_base + PAGE_BYTES, PAYLOAD, MEM_COMMIT, PAGE_READWRITE);
    if (owned_data != owned_base + PAGE_BYTES) { last_error = GetLastError(); return 0; }
    if (VirtualQuery(owned_base, &low, sizeof(low)) != sizeof(low) ||
        VirtualQuery((const void*)owned_data, &data, sizeof(data)) != sizeof(data) ||
        VirtualQuery(owned_base + PAGE_BYTES + PAYLOAD, &high, sizeof(high)) != sizeof(high)) {
        last_error = GetLastError(); return 0;
    }
    if (low.AllocationBase != owned_base || data.AllocationBase != owned_base ||
        high.AllocationBase != owned_base || low.BaseAddress != owned_base ||
        data.BaseAddress != (void*)owned_data ||
        high.BaseAddress != owned_base + PAGE_BYTES + PAYLOAD ||
        low.State != MEM_RESERVE || data.State != MEM_COMMIT || high.State != MEM_RESERVE ||
        data.Protect != PAGE_READWRITE || low.RegionSize != PAGE_BYTES ||
        data.RegionSize != PAYLOAD || high.RegionSize != RESERVATION - PAGE_BYTES - PAYLOAD ||
        !is_byte(0)) { return 0; }
    geometry[0] = (ULONG_PTR)owned_base;
    geometry[1] = (ULONG_PTR)owned_data;
    geometry[2] = RESERVATION;
    geometry[3] = PAYLOAD;
    geometry[4] = PAGE_BYTES;
    geometry[5] = low.State;
    geometry[6] = data.State;
    geometry[7] = data.Protect;
    geometry[8] = high.State;
    geometry[9] = data.RegionSize;
    geometry[10] = low.RegionSize;
    geometry[11] = high.RegionSize;
    geometry[12] = (ULONG_PTR)high.BaseAddress;
    phase = 1;
    return (ULONG_PTR)owned_data;
}

__declspec(dllexport) void* CALLBACK PublicOwned(void* context) {
    ULONG_PTR operation = (ULONG_PTR)context;
    SIZE_T i;
    if (operation == 1) { return (void*)allocate_owned(); }
    if (operation == 6) { return (void*)phase; }
    if (operation == 7) { return (void*)last_error; }
    if (operation >= 16 && operation < 29 && phase != 0) {
        return (void*)geometry[operation - 16];
    }
    if (operation == 2 && phase == 1) {
        /* Host orchestration must lock first; this integer API cannot attest it. */
        phase = 2;
        for (i = 0; i < PAYLOAD; ++i) { owned_data[i] = 0xa5; }
        return (void*)(ULONG_PTR)(is_byte(0xa5) ? PAYLOAD : 0);
    }
    if (operation == 3 && phase == 2) {
#ifndef BRYNJA_PROBE_SKIP_CLEAR
        for (i = 0; i < PAYLOAD; ++i) { owned_data[i] = 0; }
#endif
        if (!is_byte(0)) { return 0; }
        phase = 3;
        return (void*)(ULONG_PTR)PAYLOAD;
    }
    if (operation == 5 && (phase == 1 || phase == 3)) {
        return (void*)(ULONG_PTR)(is_byte(0) ? PAYLOAD : 0);
    }
    if (operation == 4 && (phase == 1 || phase == 3)) {
        if (!is_byte(0) || !VirtualFree(owned_base, 0, MEM_RELEASE)) { return 0; }
        owned_base = NULL;
        owned_data = NULL;
        phase = 0;
        for (i = 0; i < 13; ++i) { geometry[i] = 0; }
        return (void*)1;
    }
    return 0;
}
