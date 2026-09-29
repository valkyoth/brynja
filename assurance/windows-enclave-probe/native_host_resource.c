/* OS resource ownership for the synthetic Rust host. No cryptography here. */
#include "native_host.h"
#include <intrin.h>

static uint64_t created, deleted, calls, retained, cleanup_errors;
#if defined(BRYNJA_HOST_FAIL_CREATE)
static volatile unsigned fail_stage = 1;
#elif defined(BRYNJA_HOST_FAIL_LOAD)
static volatile unsigned fail_stage = 2;
#elif defined(BRYNJA_HOST_FAIL_INIT)
static volatile unsigned fail_stage = 3;
#else
static volatile unsigned fail_stage = 0;
#endif
#ifdef BRYNJA_HOST_FAIL_DELETE
static volatile BOOL fail_delete = TRUE;
#else
static volatile BOOL fail_delete = FALSE;
#endif
BOOL HostCall(LPENCLAVE_ROUTINE routine, ULONG_PTR parameter, ULONG_PTR* result) {
    void* value = NULL;
    if (!routine || !CallEnclave(routine, (void*)parameter, FALSE, &value)) { return FALSE; }
    *result = (ULONG_PTR)value;
    return TRUE;
}
void HostCountRun(void) { calls += 1; } /* Fixed bounded single-thread experiment. */
uint64_t HostCounter(uint64_t which) {
    switch (which) {
    case 0: return created;
    case 1: return deleted;
    case 2: return calls;
    case 3: return retained;
    case 4: return cleanup_errors;
    default: return ~(uint64_t)0;
    }
}
__declspec(noreturn) void HostAbort(void) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }

int HostClose(void* opaque) {
    HOST_INSTANCE* instance = (HOST_INSTANCE*)opaque;
    unsigned attempt;
    if (!instance || instance->busy || instance->owner_thread != GetCurrentThreadId()) { return 0; }
    if (instance->base) {
        if (instance->initialized && !instance->termination_requested) {
            if (!TerminateEnclave(instance->base, FALSE)) { cleanup_errors += 1; return 0; }
            instance->termination_requested = TRUE;
        }
        /* Synthetic OS-failure control. Deliberately retained until child exit. */
        if (fail_delete) { cleanup_errors += 1; return 0; }
        for (attempt = 0; attempt < 100; ++attempt) {
            if (DeleteEnclave(instance->base)) { break; }
            if (GetLastError() != ERROR_ENCLAVE_NOT_TERMINATED) { cleanup_errors += 1; return 0; }
            Sleep(1);
        }
        if (attempt == 100) { cleanup_errors += 1; return 0; }
        instance->base = NULL;
        deleted += 1;
    }
    /* Never free the callback/resource owner while OS deletion is unconfirmed. */
    if (!HeapFree(GetProcessHeap(), 0, instance)) { cleanup_errors += 1; return 0; }
    retained -= 1;
    return 1;
}

void* HostOpen(const wchar_t* image) {
    ENCLAVE_CREATE_INFO_VBS create_info = {0};
    ENCLAVE_INIT_INFO_VBS init = {sizeof(ENCLAVE_INIT_INFO_VBS), 1};
    USHORT process = 0, native = 0;
    SYSTEM_INFO geometry;
    HOST_INSTANCE* instance;
    if (!image || !IsWow64Process2(GetCurrentProcess(), &process, &native)
        || process != 0 || native != IMAGE_FILE_MACHINE_AMD64 || !IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS)) { return NULL; }
    GetSystemInfo(&geometry);
    if (geometry.dwPageSize != 4096 || geometry.dwAllocationGranularity != 65536) { return NULL; }
    instance = (HOST_INSTANCE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*instance));
    if (!instance) { return NULL; }
    retained += 1;
    instance->owner_thread = GetCurrentThreadId();
    create_info.OwnerID[0] = 0x42; create_info.OwnerID[1] = 0x52;
    instance->base = CreateEnclave(GetCurrentProcess(), NULL, 0x10000000, 0, ENCLAVE_TYPE_VBS,
                                 &create_info, sizeof(create_info), NULL);
    if (!instance->base) { goto failed; }
    created += 1;
    if (fail_stage == 1) { goto failed; }
    if (!LoadEnclaveImageW(instance->base, image)) { goto failed; }
    if (fail_stage == 2) { goto failed; }
    if (!InitializeEnclave(GetCurrentProcess(), instance->base, &init, sizeof(init), NULL)) { goto failed; }
    instance->initialized = TRUE;
    if (init.ThreadCount != 1) { goto failed; }
    if (fail_stage == 3) { goto failed; }
    instance->wire = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)instance->base, "PublicWire");
    instance->window = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)instance->base, "PublicLockedWindow");
    instance->registration = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)instance->base, "PublicLockedHost");
    instance->control = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)instance->base, "PublicWireControl");
    instance->guard = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)instance->base, "PublicGuardControl");
    if (!instance->wire || !instance->window || !instance->registration || !instance->control || !instance->guard) { goto failed; }
    return instance;
failed:
    (void)HostClose(instance); /* Failure is retained in counters; never a clean pass. */
    return NULL;
}
