/* Per-generation metadata is never reset. OS thread windows may recur ONLY
 * after native join has observed clear/readback/unlock/guard restoration. */
static ULONG_PTR run_wave_frame(STACK_SLOT* slot, ULONG_PTR index) {
    ULONG_PTR result;
    slot->lane = index;
    if (EnclaveRestrictContainingProcessAccess(TRUE, NULL) != S_OK) return (ULONG_PTR)-1;
    result = PublicStackFrame(slot);
    InterlockedExchange(&slot->done, 1);
    return result;
}

__declspec(dllexport) void* CALLBACK PublicWaveRoot(void* context) {
    ULONG_PTR identity = (ULONG_PTR)context;
    if (identity < 1 || identity > 4 ||
        InterlockedCompareExchange(&registration, 0, 0) != 2 ||
        InterlockedCompareExchange(&root_claimed, 1, 0) != 0) return 0;
    InterlockedExchange(&root_identity, (LONG)identity);
    return (void*)run_wave_frame(&slots[12], 12);
}

__declspec(dllexport) void* CALLBACK PublicWaveWorker(void* context) {
    ULONG_PTR word = (ULONG_PTR)context, generation = word / 16, lane = word % 16;
    ULONG_PTR result, index;
    BOOL clean;
    STACK_SLOT* slot;
    if (InterlockedCompareExchange(&registration, 0, 0) != 2 ||
        !wave_enter(generation, lane)) return (void*)(ULONG_PTR)-1;
    index = (generation - 1) * 4 + lane;
    slot = &slots[index];
    result = run_wave_frame(slot, index);
    clean = result == 1 && slot->admitted && slot->body && slot->cleared &&
        slot->restored && !slot->low_changed && !slot->high_changed;
    wave_leave(generation, lane, clean);
    /* No further slot access beyond the last release. */
    return (void*)result;
}
