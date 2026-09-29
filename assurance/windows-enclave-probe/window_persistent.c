/* Public-marker allocation experiment only. No crypto, secret inputs or API. */
#include "window_guard.c"

#define SLOT_PAGE 4096
static unsigned char* slot_region;
static ULONG_PTR slot_state, slot_operation, slot_report[11];
static BOOL slot_call, slot_restricted;

static BOOL slot_notify(ULONG_PTR event) {
    void* reply = NULL;
    return host_callback != NULL && slot_region != NULL &&
        CallEnclave(host_callback, (void*)(((ULONG_PTR)slot_region + SLOT_PAGE) | event),
                    FALSE, &reply) && reply == (void*)1;
}

static BOOL slot_page(ULONG_PTR address, DWORD protection) {
    MEMORY_BASIC_INFORMATION info;
    return VirtualQuery((void*)address, &info, sizeof(info)) == sizeof(info) &&
        info.State == MEM_COMMIT && info.Protect == protection &&
        (ULONG_PTR)info.BaseAddress <= address && info.RegionSize >= SLOT_PAGE &&
        address - (ULONG_PTR)info.BaseAddress <= info.RegionSize - SLOT_PAGE;
}

static BOOL slot_guards(void) {
    ULONG_PTR start = (ULONG_PTR)slot_region;
    return slot_page(start, PAGE_NOACCESS) &&
        slot_page(start + SLOT_PAGE, PAGE_READWRITE) &&
        slot_page(start + 2 * SLOT_PAGE, PAGE_NOACCESS);
}

static void slot_write(unsigned char value) {
    volatile unsigned char* data = slot_region + SLOT_PAGE;
    SIZE_T index;
    for (index = 0; index < SLOT_PAGE; ++index) { data[index] = value; }
}

static BOOL slot_matches(unsigned char value) {
    volatile unsigned char* data = slot_region + SLOT_PAGE;
    SIZE_T index;
    unsigned char different = 0;
    for (index = 0; index < SLOT_PAGE; ++index) { different |= data[index] ^ value; }
    return different == 0;
}

static BOOL slot_free(void) {
    if (!VirtualFree(slot_region, 0, MEM_RELEASE)) {
        slot_report[8] = GetLastError(); slot_state = 4; return FALSE;
    }
    slot_region = NULL; slot_state = 0; slot_report[7] = 1;
    return TRUE;
}

static LONG slot_fault(EXCEPTION_POINTERS* information, ULONG_PTR address) {
    EXCEPTION_RECORD* record = information->ExceptionRecord;
    if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || record->NumberParameters < 2 ||
        record->ExceptionInformation[0] != 0 || record->ExceptionInformation[1] != address) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    slot_report[9] += 1;
    return EXCEPTION_EXECUTE_HANDLER;
}

static void slot_work(void) {
    DWORD old;
    SIZE_T i;
    ULONG_PTR start;
    volatile unsigned char readback = 0;
    slot_report[0] = 10; /* State rejection unless exact work completed. */
    if (slot_operation == 0) {
        if (slot_state != 0 || slot_region != NULL) { return; }
        slot_region = VirtualAlloc(NULL, 3 * SLOT_PAGE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (slot_region == NULL) { slot_report[8] = GetLastError(); return; }
        start = (ULONG_PTR)slot_region;
        slot_report[1] = start; slot_report[2] = start + SLOT_PAGE;
        if ((start & (SLOT_PAGE - 1)) != 0 ||
            !(start + 3 * SLOT_PAGE <= PublicLockedLow - SLOT_PAGE ||
              start >= PublicLockedHigh + SLOT_PAGE) ||
            !VirtualProtect(slot_region, SLOT_PAGE, PAGE_NOACCESS, &old) ||
            !VirtualProtect(slot_region + 2 * SLOT_PAGE, SLOT_PAGE, PAGE_NOACCESS, &old) ||
            !slot_guards()) {
            slot_report[8] = GetLastError(); (void)slot_free(); return;
        }
        if (!slot_notify(8)) {
            /* No public marker was written. A callback failure can retain a
             * host lock; the failing harness must tear down the whole enclave. */
            slot_report[0] = 11; (void)slot_free(); return;
        }
        slot_state = 1; slot_report[0] = 1;
        return;
    }
    if (slot_region == NULL || (slot_state != 1 && slot_state != 2)) { return; }
    if (!slot_guards() || !slot_notify(9)) { slot_state = 4; return; }
    if (slot_operation == 1 && slot_state == 1) {
        slot_write(0xa5);
        slot_report[4] = slot_matches(0xa5) ? SLOT_PAGE : 0;
        if (slot_report[4] != SLOT_PAGE) { slot_state = 4; return; }
        slot_state = 2; slot_report[0] = 2;
#ifdef BRYNJA_PROBE_LOSE_RETAINED_SLOT
        slot_write(0);
#endif
    } else if (slot_operation == 2 && slot_state == 2) {
        slot_report[5] = slot_matches(0xa5) ? SLOT_PAGE : 0;
        if (slot_report[5] != SLOT_PAGE) { slot_state = 4; return; }
        slot_report[0] = 3;
    } else if (slot_operation == 3) {
#ifndef BRYNJA_PROBE_SKIP_SLOT_CLEAR
        slot_write(0);
#endif
        slot_report[6] = slot_matches(0) ? SLOT_PAGE : 0;
        if (slot_report[6] != SLOT_PAGE) { slot_state = 4; return; }
        /* Clear/readback happens BEFORE permission to unlock/free. */
        if (!slot_notify(10)) { slot_state = 4; return; }
        if (slot_free()) { slot_report[0] = 4; }
    } else if (slot_operation == 4) {
        for (i = 0; i < 4; ++i) {
            ULONG_PTR address = (ULONG_PTR)slot_region + ((i & 1) ? 2 * SLOT_PAGE : 0);
            __try { readback = *(volatile unsigned char*)address; }
            __except (slot_fault(GetExceptionInformation(), address)) { /* exact AV only */ }
        }
        if (slot_report[9] == 4 && slot_guards()) { slot_report[0] = 5; }
        else { slot_state = 4; }
    }
    (void)readback;
}

__declspec(noinline) ULONG_PTR PublicRustBody(ULONG_PTR raise) {
    ULONG_PTR result = BaseLockedBody(raise);
    SIZE_T i;
    if (!slot_call) { return result; }
    for (i = 0; i < 11; ++i) { slot_report[i] = 0; }
    slot_report[1] = (ULONG_PTR)slot_region;
    slot_report[2] = slot_region ? (ULONG_PTR)slot_region + SLOT_PAGE : 0;
    slot_work();
    slot_report[3] = slot_state;
    slot_report[10] = slot_restricted;
    return result;
}

__declspec(dllexport) void* CALLBACK PublicPersistent(void* context) {
    ULONG_PTR result, operation = (ULONG_PTR)context;
    if (active || slot_call || host_callback == NULL || operation > 4) { return 0; }
    if (EnclaveRestrictContainingProcessAccess(TRUE, NULL) != S_OK) { return 0; }
    slot_restricted = TRUE; slot_operation = operation; slot_call = TRUE;
    __try { result = (ULONG_PTR)PublicLockedWindow(0); }
    __finally { slot_call = FALSE; }
    return (void*)result;
}

__declspec(dllexport) void* CALLBACK PublicPersistentControl(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    if (active || slot_call || op < 16 || op >= 27) { return 0; }
    return (void*)slot_report[op - 16];
}
