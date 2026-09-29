/* Independent retained Rust-owner experiment. PUBLIC fixed vectors only. */
#include "window_guard.c"
#define RPAGE 4096
static unsigned char* retained_region;
static ULONG_PTR retained_operation, retained_output, retained_report[10];
static BOOL retained_call, retained_live;
extern ULONG_PTR RetainedWork(ULONG_PTR, unsigned char*, ULONG_PTR, ULONG_PTR, ULONG_PTR);

void PublicProbeAbort(void) { __fastfail(7); }
int PublicRetainedCopy(ULONG_PTR destination, const unsigned char* source, SIZE_T length) {
    if (!active || !retained_call || !retained_live || length != 32) { return E_FAIL; }
    return EnclaveCopyOutOfEnclave((void*)destination, source, length);
}
static BOOL retained_notify(ULONG_PTR event) {
    void* reply = NULL;
    return host_callback && retained_region &&
        CallEnclave(host_callback, (void*)(((ULONG_PTR)retained_region + RPAGE) | event), FALSE, &reply) && reply == (void*)1;
}
static BOOL retained_page(ULONG_PTR address, DWORD protection) {
    MEMORY_BASIC_INFORMATION info;
    return VirtualQuery((void*)address, &info, sizeof(info)) == sizeof(info) &&
        info.State == MEM_COMMIT && info.Protect == protection &&
        (ULONG_PTR)info.BaseAddress <= address && info.RegionSize >= RPAGE &&
        address - (ULONG_PTR)info.BaseAddress <= info.RegionSize - RPAGE;
}
static BOOL retained_guards(void) {
    return retained_page((ULONG_PTR)retained_region, PAGE_NOACCESS) &&
        retained_page((ULONG_PTR)retained_region + RPAGE, PAGE_READWRITE) &&
        retained_page((ULONG_PTR)retained_region + 2 * RPAGE, PAGE_NOACCESS);
}
static BOOL retained_free(void) {
    if (!VirtualFree(retained_region, 0, MEM_RELEASE)) { retained_report[7] = GetLastError(); return FALSE; }
    retained_region = NULL; retained_report[6] = 1; return TRUE;
}
static void retained_work(void) {
    ULONG_PTR status, op = retained_operation & 255;
    DWORD old;
    SIZE_T i;
    unsigned char residue = 0;
    retained_report[0] = 102;
    if (op == 0) {
        if (retained_live || retained_region) { retained_report[0] = 101; return; }
        retained_region = VirtualAlloc(NULL, 3 * RPAGE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!retained_region) { retained_report[7] = GetLastError(); return; }
        retained_report[1] = (ULONG_PTR)retained_region;
        retained_report[2] = (ULONG_PTR)retained_region + RPAGE;
        if (((ULONG_PTR)retained_region & (RPAGE - 1)) ||
            !((ULONG_PTR)retained_region + 3 * RPAGE <= PublicLockedLow - RPAGE ||
              (ULONG_PTR)retained_region >= PublicLockedHigh + RPAGE) ||
            !VirtualProtect(retained_region, RPAGE, PAGE_NOACCESS, &old) ||
            !VirtualProtect(retained_region + 2 * RPAGE, RPAGE, PAGE_NOACCESS, &old) || !retained_guards()) {
            retained_report[7] = GetLastError(); (void)retained_free(); return;
        }
        if (!retained_notify(8)) { retained_report[0] = 111; (void)retained_free(); return; }
        status = RetainedWork(0, retained_region + RPAGE, PublicLockedLow, PublicLockedHigh, 0);
        retained_report[0] = status;
        if (status == 1) { retained_live = TRUE; }
        return;
    }
    if (!retained_live || !retained_region) { return; }
    if (!retained_guards() || !retained_notify(9)) { retained_report[0] = 112; return; }
    status = RetainedWork(retained_operation, retained_region + RPAGE, PublicLockedLow, PublicLockedHigh, retained_output);
    retained_report[0] = status & 0xffffffff;
    retained_report[4] = status >> 32;
    if (op == 3 && status == 4) {
        retained_live = FALSE;
        /* No Rust object/borrow is live now; only then inspect the full page. */
        for (i = 0; i < RPAGE; ++i) { residue |= ((volatile unsigned char*)retained_region)[RPAGE + i]; }
        if (residue) { retained_report[0] = 113; return; }
        retained_report[5] = RPAGE;
        if (!retained_notify(10)) { retained_report[0] = 114; return; }
        if (!retained_free()) { retained_report[0] = 115; }
    }
}
__declspec(noinline) ULONG_PTR PublicRustBody(ULONG_PTR raise) {
    ULONG_PTR result = BaseLockedBody(raise);
    SIZE_T i;
    if (!retained_call) { return result; }
    for (i = 0; i < 10; ++i) { retained_report[i] = 0; }
    retained_report[1] = (ULONG_PTR)retained_region;
    retained_report[2] = retained_region ? (ULONG_PTR)retained_region + RPAGE : 0;
    retained_work();
    retained_report[3] = retained_live;
    retained_report[8] = 1; /* containing-process restriction succeeded */
    retained_report[9] = retained_operation;
    return result;
}
__declspec(dllexport) void* CALLBACK PublicRetained(void* context) {
    ULONG_PTR result, operation = (ULONG_PTR)context;
    if (active || retained_call || !host_callback || (operation & 255) > 7 || operation >> 8 > 19) { return 0; }
    if (EnclaveRestrictContainingProcessAccess(TRUE, NULL) != S_OK) { return 0; }
    retained_operation = operation; retained_call = TRUE;
    __try { result = (ULONG_PTR)PublicLockedWindow(0); }
    __finally { retained_call = FALSE; }
    return (void*)result;
}
__declspec(dllexport) void* CALLBACK PublicRetainedControl(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    if (active || retained_call || op < 16 || op >= 26) { return 0; }
    return (void*)retained_report[op - 16];
}
__declspec(dllexport) void* CALLBACK PublicRetainedOutput(void* context) {
    if (active || retained_call) { return 0; }
    retained_output = (ULONG_PTR)context; return (void*)1;
}
