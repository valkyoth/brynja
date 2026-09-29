/* Fixed PUBLIC vectors only. No application callbacks or confidential host data. */
#include "native_host.h"
#include <psapi.h>
#include <string.h>
#include "retained_page_admission.h"
#ifdef BRYNJA_RETAINED_DIAGNOSTIC
#include <stdio.h>
#endif

typedef struct {
    HOST_INSTANCE* instance;
    ULONG_PTR low, operation;
    unsigned phase, slot_phase;
    BOOL locked, error;
} RETAINED_CALL;
static __declspec(thread) RETAINED_CALL* current;

static BOOL pages(ULONG_PTR low, unsigned count, BOOL locked) {
    PSAPI_WORKING_SET_EX_INFORMATION entries[16] = {0};
    unsigned i;
    if (count != 1 && count != 16) { return FALSE; }
    for (i = 0; i < count; ++i) { entries[i].VirtualAddress = (void*)(low + (ULONG_PTR)i * 4096); }
    if (!QueryWorkingSetEx(GetCurrentProcess(), entries, (DWORD)(count * sizeof(entries[0])))) { return FALSE; }
    for (i = 0; i < count; ++i) {
        unsigned valid = (unsigned)entries[i].VirtualAttributes.Valid;
        unsigned observed = valid ? (unsigned)entries[i].VirtualAttributes.Locked : 0;
        if (!retained_page_accepts(valid, observed, (unsigned)locked)) { return FALSE; }
    }
    return TRUE;
}
static BOOL inside(HOST_INSTANCE* owner, ULONG_PTR address, ULONG_PTR length) {
    ULONG_PTR base = (ULONG_PTR)owner->base;
    return address >= base && length <= 0x10000000 && address - base <= 0x10000000 - length;
}
static BOOL disjoint(ULONG_PTR a, ULONG_PTR n, ULONG_PTR b, ULONG_PTR m) {
    return a <= b ? b - a >= n : a - b >= m;
}
static void* CALLBACK callback(void* parameter) {
    RETAINED_CALL* call = current;
    ULONG_PTR value = (ULONG_PTR)parameter, event = value & 15, address = value & ~(ULONG_PTR)15;
    HOST_INSTANCE* owner;
    if (!call || call->error || !call->instance->busy) { return NULL; }
    owner = call->instance;
    if ((address & 4095) || address < 4096) { goto failed; }
    if (event == 0) {
        if (call->phase || !inside(owner, address - 4096, 73728) || !pages(address, 16, FALSE)) { goto failed; }
        call->low = address;
        if (!VirtualLock((void*)address, 65536)) { goto failed; }
        call->locked = TRUE;
        if (!pages(address, 16, TRUE)) { goto failed; }
        call->phase = 1;
        return (void*)1;
    }
    if (call->phase != 1 || !call->locked) { goto failed; }
    if (event == 1) {
        if (address != call->low || !pages(address, 16, TRUE)) { goto failed; }
        if (!VirtualUnlock((void*)address, 65536)) { goto failed; }
        call->locked = FALSE; call->phase = 2;
        return (void*)1;
    }
    if (!inside(owner, address - 4096, 12288) ||
        !disjoint(address - 4096, 12288, call->low - 4096, 73728)) { goto failed; }
    if (event == 8) {
        if (call->operation != 0 || call->slot_phase || owner->slot_locked || !pages(address, 1, FALSE)) { goto failed; }
        owner->slot = address;
        if (!VirtualLock((void*)address, 4096)) { goto failed; }
        owner->slot_locked = TRUE;
        if (!pages(address, 1, TRUE)) { goto failed; }
        call->slot_phase = 1;
        return (void*)1;
    }
    if (address != owner->slot || !owner->slot_locked || !pages(address, 1, TRUE)) { goto failed; }
    if (event == 9 && call->operation != 0 && call->slot_phase == 0) {
        call->slot_phase = 1;
        return (void*)1;
    }
    if (event == 10 && call->operation == 3 && call->slot_phase == 1) {
        /* Only trusted fixed enclave code sends this after full zero readback.
         * This is orchestration, NOT hostile-host/enclave residency attestation. */
        if (!VirtualUnlock((void*)address, 4096)) { goto failed; }
        owner->slot_locked = FALSE; call->slot_phase = 2;
        return (void*)1;
    }
failed:
    call->error = TRUE;
    return NULL;
}

static BOOL inspect(RETAINED_CALL* call, ULONG_PTR returned, uint64_t* report) {
    HOST_INSTANCE* owner = call->instance;
    ULONG_PTR outer[7], guards[13], inner[10];
    ULONG_PTR op = call->operation & 255, expected;
    unsigned i;
    for (i = 0; i < 7; ++i) { if (!HostCall(owner->window, i + 2, &outer[i])) { return FALSE; } }
    for (i = 0; i < 13; ++i) { if (!HostCall(owner->guard, i + 16, &guards[i])) { return FALSE; } }
    for (i = 0; i < 10; ++i) { if (!HostCall(owner->control, i + 16, &inner[i])) { return FALSE; } }
#ifdef BRYNJA_RETAINED_DIAGNOSTIC
    fprintf(stderr, "retained diagnostic: returned=%llu phase=%u slot_phase=%u low=%llu slot=%llu locked=%d slot_locked=%d error=%d\n",
        returned, call->phase, call->slot_phase, call->low, owner->slot, call->locked, owner->slot_locked, call->error);
    for (i = 0; i < 7; ++i) { fprintf(stderr, "outer[%u]=%llu\n", i, outer[i]); }
    for (i = 0; i < 13; ++i) { fprintf(stderr, "guards[%u]=%llu\n", i, guards[i]); }
    for (i = 0; i < 10; ++i) { fprintf(stderr, "inner[%u]=%llu\n", i, inner[i]); }
#endif
    if (returned != 95 || outer[0] != call->low || outer[1] != call->low + 65536 ||
        outer[2] < call->low || outer[2] - call->low >= 65536 ||
        outer[3] < call->low || outer[3] - call->low > 65536 - 256 ||
        !disjoint(outer[2], 1, outer[3], 256) || outer[4] != 31 || outer[5] != 1 || outer[6] != 1 ||
        call->phase != 2 || call->locked || call->error) { return FALSE; }
    if (guards[0] != call->low - 4096 || guards[1] != call->low + 65536 || guards[2] != 1 || guards[3] != 1) { return FALSE; }
    for (i = 4; i < 13; ++i) { if (guards[i]) { return FALSE; } }
    expected = op == 0 ? 1 : op == 1 ? 2 : op == 2 ? 3 : op == 3 ? 4 : op == 4 ? 5 : 105;
    if (inner[0] != expected || inner[1] != owner->slot - 4096 || inner[2] != owner->slot ||
        inner[3] != (ULONG_PTR)(op != 3) || inner[4] != (ULONG_PTR)(op == 1) ||
        inner[5] != (op == 3 ? 4096u : 0u) || inner[6] != (ULONG_PTR)(op == 3) || inner[7] != 0 ||
        inner[8] != 1 || inner[9] != call->operation || call->slot_phase != (op == 3 ? 2u : 1u)) { return FALSE; }
    if (op == 3 ? owner->slot_locked : !owner->slot_locked || !pages(owner->slot, 1, TRUE)) { return FALSE; }
    report[0] = inner[0]; report[1] = inner[4]; report[2] = inner[5]; report[3] = inner[6];
    if (op == 3) { owner->slot = 0; }
    return TRUE;
}

int RetainedRun(void* opaque, uint64_t operation, unsigned char* output, uint64_t* report) {
    HOST_INSTANCE* owner = (HOST_INSTANCE*)opaque;
    RETAINED_CALL call = {0};
    ULONG_PTR result = 0, removed = 0, op = (ULONG_PTR)operation & 255;
    BOOL ok = FALSE, registered = FALSE;
    if (!owner || owner->busy || owner->termination_requested || owner->uncertain || current || !report ||
        owner->owner_thread != GetCurrentThreadId() || operation >> 8 > 19 ||
        (op > 4 && op != 6) || (op != 1 && operation >> 8)) { return 0; }
    memset(report, 0, 4 * sizeof(uint64_t));
    HostCountRun();
    owner->busy = TRUE;
    call.instance = owner; call.operation = (ULONG_PTR)operation;
    current = &call;
    if (!HostCall(owner->output, (ULONG_PTR)output, &result) || result != 1) { goto done; }
    registered = HostCall(owner->registration, (ULONG_PTR)callback, &result) && result == 1;
    if (registered && HostCall(owner->wire, (ULONG_PTR)operation, &result)) { ok = inspect(&call, result, report); }
done:
    /* Revoke both retained host addresses even if registration/entry failed. */
    if (!HostCall(owner->registration, 0, &removed) || removed != 1) { ok = FALSE; }
    if (!HostCall(owner->output, 0, &removed) || removed != 1) { ok = FALSE; }
    current = NULL;
    owner->busy = FALSE;
    if (!ok || call.locked || call.error) { owner->uncertain = TRUE; return 0; }
    return 1;
}
