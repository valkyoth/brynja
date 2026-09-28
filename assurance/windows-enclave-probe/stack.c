/* Native stack/unwind experiment. All bytes are public; no crypto or secrets. */
#include "synthetic.c"

#define STACK_BYTES 65536
#define PAGE_BYTES 4096
#define RESERVATION 131072
#define PROBE_EXCEPTION ((DWORD)0xe0425259)
static unsigned char* stack_base;
static volatile unsigned char* stack_data;
static volatile ULONG_PTR steps;
static volatile ULONG_PTR frame_address;
extern ULONG_PTR PublicSwitch(void* top, ULONG_PTR raise);

__declspec(noinline) ULONG_PTR PublicStackWork(ULONG_PTR raise) {
    volatile unsigned char marker[256];
    SIZE_T i;
    BOOL correct = TRUE;
    frame_address = (ULONG_PTR)marker;
    steps |= 1;
    __try {
        for (i = 0; i < sizeof(marker); ++i) { marker[i] = 0xa5; }
        for (i = 0; i < sizeof(marker); ++i) {
            if (marker[i] != 0xa5) { correct = FALSE; }
        }
        if (correct) { steps |= 2; }
        if (raise) { RaiseException(PROBE_EXCEPTION, 0, 0, NULL); }
        steps |= 16;
    } __finally {
        steps |= 4;
        for (i = 0; i < sizeof(marker); ++i) { marker[i] = 0; }
        for (i = 0; i < sizeof(marker); ++i) {
            if (marker[i] != 0) { correct = FALSE; }
        }
        if (correct) { steps |= 8; }
    }
    return steps;
}

static ULONG_PTR geometry_ok(void) {
    MEMORY_BASIC_INFORMATION low, data, high;
    if (stack_base == NULL || stack_data == NULL) { return 0; }
    if (VirtualQuery(stack_base, &low, sizeof(low)) != sizeof(low) ||
        VirtualQuery((const void*)stack_data, &data, sizeof(data)) != sizeof(data) ||
        VirtualQuery(stack_base + PAGE_BYTES + STACK_BYTES, &high, sizeof(high)) != sizeof(high)) {
        return 0;
    }
    return low.AllocationBase == stack_base && data.AllocationBase == stack_base &&
        high.AllocationBase == stack_base && low.BaseAddress == stack_base &&
        data.BaseAddress == (void*)stack_data &&
        high.BaseAddress == stack_base + PAGE_BYTES + STACK_BYTES &&
        low.State == MEM_RESERVE && data.State == MEM_COMMIT && high.State == MEM_RESERVE &&
        data.Protect == PAGE_READWRITE && low.RegionSize == PAGE_BYTES &&
        data.RegionSize == STACK_BYTES && high.RegionSize == RESERVATION - PAGE_BYTES - STACK_BYTES;
}

static ULONG_PTR zero_stack(BOOL write) {
    SIZE_T i;
    BOOL correct = TRUE;
    if (stack_data == NULL) { return 0; }
    if (write) {
        for (i = 0; i < STACK_BYTES; ++i) { stack_data[i] = 0; }
    }
    for (i = 0; i < STACK_BYTES; ++i) {
        if (stack_data[i] != 0) { correct = FALSE; }
    }
    return correct ? STACK_BYTES : 0;
}

__declspec(dllexport) void* CALLBACK PublicStack(void* context) {
    ULONG_PTR operation = (ULONG_PTR)context;
    if (operation == 1 && stack_base == NULL) {
        stack_base = VirtualAlloc(NULL, RESERVATION, MEM_RESERVE, PAGE_NOACCESS);
        if (stack_base == NULL) { return 0; }
        stack_data = VirtualAlloc(stack_base + PAGE_BYTES, STACK_BYTES, MEM_COMMIT, PAGE_READWRITE);
        if (stack_data != stack_base + PAGE_BYTES || !geometry_ok()) { return 0; }
        return (void*)stack_data;
    }
    if (operation == 2) { return (void*)geometry_ok(); }
    if (operation >= 10 && operation <= 15 && geometry_ok()) {
        steps = 0;
        frame_address = 0;
        __try {
            if (operation >= 14) {
                (void)PublicSwitch(NULL, operation & 1);
            } else if (operation >= 12) {
                (void)PublicSwitch((void*)(stack_data + STACK_BYTES), operation & 1);
            } else {
                (void)PublicStackWork(operation & 1);
            }
        } __except (GetExceptionCode() == PROBE_EXCEPTION ?
                    EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            steps |= 32;
        }
        return (void*)steps;
    }
    if (operation == 6) { return (void*)zero_stack(TRUE); }
    if (operation == 7 && zero_stack(FALSE) == STACK_BYTES) {
        if (!VirtualFree(stack_base, 0, MEM_RELEASE)) { return 0; }
        stack_base = NULL;
        stack_data = NULL;
        return (void*)1;
    }
    if (operation == 8) { return (void*)steps; }
    if (operation == 9) { return (void*)frame_address; }
    return 0;
}
