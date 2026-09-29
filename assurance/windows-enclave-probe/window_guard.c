/* Synthetic page-boundary experiment, NOT production worker qualification. */
#define PublicLockedAdmit BaseLockedAdmit
#define PublicLockedFinish BaseLockedFinish
#define PublicLockedBody BaseLockedBody
#include "window_lock.c"
#undef PublicLockedAdmit
#undef PublicLockedFinish
#undef PublicLockedBody

#define GUARD_PAGE 4096
/* Public observations only: no real secret inputs accepted. */
static ULONG_PTR mode, stats[12];
static DWORD low_old, high_old;
static BOOL low_changed, high_changed;

static BOOL page_info(ULONG_PTR address, DWORD protection) {
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery((void*)address, &info, sizeof(info)) != sizeof(info)) {
        stats[10] = GetLastError(); return FALSE;
    }
    return info.State == MEM_COMMIT && info.Protect == protection &&
        (ULONG_PTR)info.BaseAddress <= address && info.RegionSize >= GUARD_PAGE &&
        address - (ULONG_PTR)info.BaseAddress <= info.RegionSize - GUARD_PAGE;
}

static BOOL protect_page(ULONG_PTR address, DWORD* old, BOOL* changed) {
#ifdef BRYNJA_PROBE_SKIP_STACK_GUARD
    (void)address; (void)old; (void)changed;
    return FALSE;
#else
    if (!VirtualProtect((void*)address, GUARD_PAGE, PAGE_NOACCESS, old)) {
        stats[10] = GetLastError(); return FALSE;
    }
    *changed = TRUE;
    return *old == PAGE_READWRITE && page_info(address, PAGE_NOACCESS);
#endif
}

ULONG_PTR PublicLockedAdmit(void) {
    SIZE_T i;
    for (i = 0; i < 12; ++i) { stats[i] = 0; }
    if (!active || low_changed || high_changed ||
        PublicLockedHigh - PublicLockedLow != 65536 ||
        (PublicLockedLow & (GUARD_PAGE - 1)) != 0 || PublicLockedLow < GUARD_PAGE) {
        return 0;
    }
    stats[0] = PublicLockedLow - GUARD_PAGE;
    stats[1] = PublicLockedHigh;
    if (!page_info(stats[0], PAGE_READWRITE) || !page_info(stats[1], PAGE_READWRITE)) {
        stats[11] = 1; return 0;
    }
    if (!protect_page(stats[0], &low_old, &low_changed) ||
        !protect_page(stats[1], &high_old, &high_changed)) {
        stats[11] = 2; return 0;
    }
    stats[2] = page_info(stats[0], PAGE_NOACCESS) ? 1 : 0;
    stats[3] = page_info(stats[1], PAGE_NOACCESS) ? 1 : 0;
    if (stats[2] != 1 || stats[3] != 1) { stats[11] = 3; return 0; }
    return BaseLockedAdmit();
}

/* Accept only the exact synthetic boundary access, never an arbitrary crash. */
static LONG boundary_filter(EXCEPTION_POINTERS* information, ULONG_PTR address, BOOL write) {
    EXCEPTION_RECORD* record = information->ExceptionRecord;
    if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
        record->NumberParameters < 2 || record->ExceptionInformation[0] != (ULONG_PTR)write ||
        record->ExceptionInformation[1] != address) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    stats[6] = record->ExceptionCode;
    stats[7] = record->ExceptionInformation[0];
    stats[8] = address;
    return EXCEPTION_EXECUTE_HANDLER;
}

ULONG_PTR PublicLockedBody(ULONG_PTR raise) {
    ULONG_PTR result = BaseLockedBody(raise);
    ULONG_PTR address;
    SIZE_T i;
    volatile unsigned char readback = 0;
    BOOL write = mode == 2 || mode == 4;
    if (mode == 0) { return result; }
    address = mode <= 2 ? PublicLockedLow - 1 : PublicLockedHigh;
    for (i = 0; i < 2; ++i) {
        __try {
            if (write) { *(volatile unsigned char*)address = 0xa5; }
            else { readback = *(volatile unsigned char*)address; }
            /* A completed access is a failed guard, regardless of read value. */
            stats[9] += 1;
        } __except (boundary_filter(GetExceptionInformation(), address, write)) {
            stats[4] += 1;
        }
    }
    (void)readback;
    stats[5] = page_info(PublicLockedLow - GUARD_PAGE, PAGE_NOACCESS) &&
               page_info(PublicLockedHigh, PAGE_NOACCESS);
    return result;
}

ULONG_PTR PublicLockedFinish(ULONG_PTR result) {
    return BaseLockedFinish(result);
}

/* Called below both boundaries, on every return path, before the OS reuses them. */
ULONG_PTR PublicGuardRestore(void) {
    DWORD ignored;
    BOOL ok = TRUE;
    if (high_changed) {
        if (!VirtualProtect((void*)PublicLockedHigh, GUARD_PAGE, high_old, &ignored)) {
            stats[10] = GetLastError(); ok = FALSE;
        } else { high_changed = FALSE; }
    }
    if (low_changed) {
        if (!VirtualProtect((void*)(PublicLockedLow - GUARD_PAGE), GUARD_PAGE, low_old, &ignored)) {
            stats[10] = GetLastError(); ok = FALSE;
        } else { low_changed = FALSE; }
    }
    return ok && page_info(PublicLockedLow - GUARD_PAGE, PAGE_READWRITE) &&
                 page_info(PublicLockedHigh, PAGE_READWRITE);
}

__declspec(dllexport) void* CALLBACK PublicGuardControl(void* context) {
    ULONG_PTR operation = (ULONG_PTR)context;
    if (active) { return 0; }
    if (operation <= 4) { mode = operation; return (void*)1; }
    if (operation >= 16 && operation < 28) { return (void*)stats[operation - 16]; }
    if (operation == 28) { return (void*)(ULONG_PTR)(low_changed || high_changed); }
    return 0;
}
