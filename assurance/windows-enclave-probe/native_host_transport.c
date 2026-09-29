/* Fixed callbacks for public test data. No generic caller callbacks are exported. */
#include "native_host.h"
#include <psapi.h>
#include <string.h>

typedef struct {
    HOST_INSTANCE* instance;
    void* user;
    HOST_PROTOCOL protocol;
    unsigned char *command, *output;
    ULONG_PTR low;
    unsigned phase;
    BOOL locked, error;
    uint64_t fault;
} HOST_CALL;
/* An unexpected callback thread has no context and fails closed. */
static __declspec(thread) HOST_CALL* current;

static BOOL pages(ULONG_PTR low, BOOL locked) {
    PSAPI_WORKING_SET_EX_INFORMATION entries[16] = {0};
    unsigned i;
    for (i = 0; i < 16; ++i) { entries[i].VirtualAddress = (void*)(low + (ULONG_PTR)i * 4096); }
    if (!QueryWorkingSetEx(GetCurrentProcess(), entries, sizeof(entries))) { return FALSE; }
    for (i = 0; i < 16; ++i) {
        BOOL observed = entries[i].VirtualAttributes.Valid && entries[i].VirtualAttributes.Locked;
        if (locked ? !observed : observed) { return FALSE; }
    }
    return TRUE;
}

static void* CALLBACK host_callback(void* parameter) {
    HOST_CALL* call = current;
    ULONG_PTR value = (ULONG_PTR)parameter, event = value & 15, low = value & ~(ULONG_PTR)15;
    ULONG_PTR base;
    if (!call || !call->instance->busy || call->error) { return NULL; }
    base = (ULONG_PTR)call->instance->base;
    if (low < base || low - base < 4096 || low - base > 0x10000000 - 65536 - 4096
        || (low & 4095) != 0) { goto failed; }
    if (event == 0) {
        if (call->phase != 0 || !pages(low, FALSE)) { goto failed; }
        call->low = low;
        if (!VirtualLock((void*)low, 65536)) { goto failed; }
        call->locked = TRUE;
        if (!pages(low, TRUE)) { goto failed; }
        call->phase = 1;
        return (void*)1;
    }
    if (low != call->low) { goto failed; }
    if (event == 1) {
        /* Enclave's fixed outer-zero notification; validate all pages before release. */
        if (call->phase < 1 || call->phase > 3 || !call->locked || !pages(low, TRUE)) { goto failed; }
        if (!VirtualUnlock((void*)low, 65536)) { goto failed; }
        call->locked = FALSE;
        call->phase = 4;
        return (void*)1;
    }
    if ((event == 2 && call->phase == 1) || (event == 3 && call->phase == 2)) {
        if (!call->locked || !pages(low, TRUE)) { goto failed; }
        if (event == 2 && call->fault == 1) { return NULL; } /* Controlled denial, then outer clear. */
        if (call->protocol(call->user, event - 2, call->command, call->output) != 1) { goto failed; }
        if (call->fault == 4) {
            uint64_t destination = 1; /* Actual EnclaveCopyOut rejection, not simulated success. */
            memcpy(call->command + 48, &destination, sizeof(destination));
        }
        call->phase += 1;
        return (void*)1;
    }
failed:
    call->error = TRUE;
    return NULL;
}

static BOOL bounded_region(ULONG_PTR address, ULONG_PTR size, ULONG_PTR low) {
    return address >= low && size <= 65536 && address - low <= 65536 - size;
}
static BOOL disjoint(ULONG_PTR a, ULONG_PTR n, ULONG_PTR b, ULONG_PTR m) {
    return a <= b ? b - a >= n : a - b >= m;
}

static BOOL inspect(HOST_INSTANCE* instance, HOST_CALL* call, ULONG_PTR returned,
                    const unsigned char* request, HOST_REPORT* report) {
    ULONG_PTR outer[7], guards[13], inner[8], restricted, length;
    unsigned i;
    for (i = 0; i < 7; ++i) { if (!HostCall(instance->window, i + 2, &outer[i])) { return FALSE; } }
    for (i = 0; i < 13; ++i) { if (!HostCall(instance->guard, i + 16, &guards[i])) { return FALSE; } }
    for (i = 0; i < 8; ++i) { if (!HostCall(instance->control, i + 16, &inner[i])) { return FALSE; } }
    if (!HostCall(instance->control, 24, &restricted)) { return FALSE; }
    memcpy(&length, request + 16, sizeof(length));
    if (returned != 95 || outer[0] != call->low || outer[1] != call->low + 65536
        || outer[4] != 31 || outer[5] != 1 || outer[6] != 1 || call->phase != 4 || call->locked
        || !bounded_region(outer[2], 1, call->low) || !bounded_region(outer[3], 256, call->low)
        || !disjoint(outer[2],1,outer[3],256)) { return FALSE; }
    if (guards[0] != call->low - 4096 || guards[1] != call->low + 65536
        || guards[2] != 1 || guards[3] != 1) { return FALSE; }
    for (i = 4; i < 13; ++i) { if (guards[i] != 0) { return FALSE; } }
    if (restricted != 1 || inner[7] != 1170 || inner[5] != 1 || length > 1024 || inner[4] != length
        || !bounded_region(inner[1],1136,call->low) || !bounded_region(inner[2],1170,call->low)
        || !bounded_region(inner[3],32,call->low) || !disjoint(inner[1],1136,inner[2],1170)
        || !disjoint(inner[1],1136,inner[3],32) || !disjoint(inner[2],1170,inner[3],32)) { return FALSE; }
    report->first = inner[0]; report->second = inner[6]; report->inner_clear = 1;
    report->outer_clear = call->fault == 3 ? 0 : 1;
    return TRUE;
}

int HostRun(void* opaque, void* user, HOST_PROTOCOL protocol, const unsigned char* request,
            unsigned char* command, unsigned char* output, uint64_t fault, HOST_REPORT* report) {
    HOST_INSTANCE* instance = (HOST_INSTANCE*)opaque;
    HOST_CALL call = {0};
    ULONG_PTR result = 0, removed = 0;
    BOOL ok = FALSE, registered = FALSE;
    if (!instance || instance->busy || instance->termination_requested || current
        || instance->owner_thread != GetCurrentThreadId() || !user || !protocol
        || !request || !command || !output || !report || fault > 4) { return 0; }
    HostCountRun();
    memset(report, 0, sizeof(*report));
    call.instance = instance; call.user = user; call.protocol = protocol;
    call.command = command; call.output = output; call.fault = fault;
    instance->busy = TRUE;
    current = &call;
    registered = HostCall(instance->registration, (ULONG_PTR)host_callback, &result) && result == 1;
    if (registered && HostCall(instance->wire, (ULONG_PTR)request, &result) && !call.error) {
        ok = inspect(instance, &call, result, request, report);
    }
    if (registered && (!HostCall(instance->registration, 0, &removed) || removed != 1)) { ok = FALSE; }
    /* Nothing asynchronous retains these pointers. A failed cleanup is not repaired
     * by unlocking dirty pages: the owner is quarantined and terminated instead. */
    current = NULL;
    instance->busy = FALSE;
    if (call.locked || call.error || fault == 2) { ok = FALSE; }
    return ok ? 1 : 0;
}
