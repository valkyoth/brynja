/* Public markers ONLY. Per-slot guarded stack experiment, not a crypto API. */
#include "concurrent_entry.c"

typedef struct {
    ULONG_PTR low, high; /* Assembly ABI: first two pointer-sized fields. */
    ULONG_PTR lane, marker;
    DWORD low_old, high_old;
    BOOL low_changed, high_changed, admitted, cleared, restored, body;
    volatile LONG claimed, done;
} STACK_SLOT;
_Static_assert(FIELD_OFFSET(STACK_SLOT, low) == 0, "stack low ABI");
_Static_assert(FIELD_OFFSET(STACK_SLOT, high) == 8, "stack high ABI");
static STACK_SLOT slots[4];
static LPENCLAVE_ROUTINE stack_callback;
static volatile LONG registration;
extern ULONG_PTR PublicStackFrame(STACK_SLOT* slot);

static BOOL page(ULONG_PTR address, DWORD protection) {
    MEMORY_BASIC_INFORMATION info;
    return VirtualQuery((void*)address, &info, sizeof(info)) == sizeof(info) &&
        info.State == MEM_COMMIT && info.Protect == protection &&
        (ULONG_PTR)info.BaseAddress <= address && info.RegionSize >= 4096 &&
        address - (ULONG_PTR)info.BaseAddress <= info.RegionSize - 4096;
}

static BOOL notify(STACK_SLOT* slot, ULONG_PTR event) {
    void* reply = NULL;
    return stack_callback != NULL &&
        CallEnclave(stack_callback, (void*)(slot->low | (slot->lane << 4) | event),
                    FALSE, &reply) && reply == (void*)1;
}

ULONG_PTR PublicStackAdmit(STACK_SLOT* slot) {
    if (slot->high - slot->low != 65536 || (slot->low & 4095) != 0 ||
        slot->low < 4096 || !page(slot->low - 4096, PAGE_READWRITE) ||
        !page(slot->high, PAGE_READWRITE)) return 0;
    if (!VirtualProtect((void*)(slot->low - 4096), 4096, PAGE_NOACCESS, &slot->low_old)) return 0;
    slot->low_changed = TRUE;
    if (slot->low_old != PAGE_READWRITE ||
        !VirtualProtect((void*)slot->high, 4096, PAGE_NOACCESS, &slot->high_old)) return 0;
    slot->high_changed = TRUE;
    if (slot->high_old != PAGE_READWRITE || !page(slot->low - 4096, PAGE_NOACCESS) ||
        !page(slot->high, PAGE_NOACCESS)) return 0;
    slot->admitted = notify(slot, 0);
    return slot->admitted;
}

__declspec(noinline) ULONG_PTR PublicStackBody(STACK_SLOT* slot) {
    volatile unsigned char marker[256];
    SIZE_T index;
    ULONG_PTR result;
    slot->marker = (ULONG_PTR)marker;
    if (!slot->admitted || slot->marker < slot->low ||
        slot->marker > slot->high - sizeof(marker)) return (ULONG_PTR)-1;
    for (index = 0; index < sizeof(marker); ++index) marker[index] = (unsigned char)(0xa0 + slot->lane);
    slot->body = TRUE;
    result = (ULONG_PTR)PublicConcurrentWorker((void*)slot->lane);
    for (index = 0; index < sizeof(marker); ++index) {
        if (marker[index] != (unsigned char)(0xa0 + slot->lane)) result = (ULONG_PTR)-1;
        marker[index] = 0;
    }
    return result;
}

ULONG_PTR PublicStackFinish(STACK_SLOT* slot, ULONG_PTR result) {
    slot->cleared = TRUE; /* Called only after assembly clears and reads the full window. */
    return notify(slot, 1) ? result : (ULONG_PTR)-1;
}

ULONG_PTR PublicStackRestore(STACK_SLOT* slot) {
    DWORD ignored;
    BOOL ok = TRUE;
    if (slot->high_changed) {
        if (!VirtualProtect((void*)slot->high, 4096, slot->high_old, &ignored)) ok = FALSE;
        else slot->high_changed = FALSE;
    }
    if (slot->low_changed) {
        if (!VirtualProtect((void*)(slot->low - 4096), 4096, slot->low_old, &ignored)) ok = FALSE;
        else slot->low_changed = FALSE;
    }
    slot->restored = ok && page(slot->low - 4096, PAGE_READWRITE) && page(slot->high, PAGE_READWRITE);
    return slot->restored;
}

__declspec(dllexport) void* CALLBACK PublicStackRegister(void* context) {
    if (context == NULL || InterlockedCompareExchange(&registration, 1, 0) != 0) return 0;
    stack_callback = (LPENCLAVE_ROUTINE)context;
    InterlockedExchange(&registration, 2);
    return (void*)1;
}

__declspec(dllexport) void* CALLBACK PublicStackWorker(void* context) {
    ULONG_PTR lane = (ULONG_PTR)context;
    ULONG_PTR result;
    STACK_SLOT* slot;
    if (lane >= 4 || InterlockedCompareExchange(&registration, 0, 0) != 2) return (void*)(ULONG_PTR)-1;
    slot = &slots[lane];
    if (InterlockedCompareExchange(&slot->claimed, 1, 0) != 0) return (void*)(ULONG_PTR)-1;
    slot->lane = lane;
    if (EnclaveRestrictContainingProcessAccess(TRUE, NULL) != S_OK) return (void*)(ULONG_PTR)-1;
    result = PublicStackFrame(slot);
    InterlockedExchange(&slot->done, 1);
    return (void*)result;
}

/* Query only after the host has joined every call. Diagnostic addresses are public. */
__declspec(dllexport) void* CALLBACK PublicStackQuery(void* context) {
    ULONG_PTR word = (ULONG_PTR)context, lane = word / 16, field = word % 16;
    STACK_SLOT* slot;
    if (lane >= 4) return (void*)(ULONG_PTR)-1;
    slot = &slots[lane];
    if (InterlockedCompareExchange(&slot->done, 0, 0) != 1) return (void*)(ULONG_PTR)-1;
    switch (field) {
    case 0: return (void*)slot->low;
    case 1: return (void*)slot->high;
    case 2: return (void*)slot->marker;
    case 3: return (void*)(ULONG_PTR)slot->admitted;
    case 4: return (void*)(ULONG_PTR)slot->cleared;
    case 5: return (void*)(ULONG_PTR)slot->restored;
    case 6: return (void*)(ULONG_PTR)slot->body;
    case 7: return (void*)(ULONG_PTR)(slot->low_changed || slot->high_changed);
    default: return (void*)(ULONG_PTR)-1;
    }
}
