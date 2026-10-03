static ULONG_PTR run_scheduler_frame(STACK_SLOT* slot, ULONG_PTR lane) {
    ULONG_PTR result;
    slot->lane = lane;
    if (EnclaveRestrictContainingProcessAccess(TRUE, NULL) != S_OK) return (ULONG_PTR)-1;
    result = PublicStackFrame(slot);
    InterlockedExchange(&slot->done, 1);
    return result;
}
__declspec(dllexport) void* CALLBACK PublicWaveRoot(void* context) {
    if (context == NULL || InterlockedCompareExchange(&input_registration, 0, 0) != 2 ||
        InterlockedCompareExchange(&registration, 0, 0) != 2 ||
        InterlockedCompareExchange(&root_claimed, 1, 0) != 0) return 0;
    root_source = context;
    return (void*)run_scheduler_frame(&slots[4], 4);
}
__declspec(dllexport) void* CALLBACK PublicWaveWorker(void* context) {
    ULONG_PTR word = (ULONG_PTR)context, generation = word / 16, lane = word % 16, result;
    BOOL clean;
    STACK_SLOT* slot;
    if (InterlockedCompareExchange(&registration, 0, 0) != 2 ||
        !scheduler_enter(generation, lane)) return (void*)(ULONG_PTR)-1;
    slot = &slots[lane];
    result = run_scheduler_frame(slot, lane);
    clean = result == 1 && slot->admitted && slot->body && slot->cleared && slot->restored &&
        !slot->low_changed && !slot->high_changed;
    if (!scheduler_leave(generation, lane, clean)) PrivateWaveAbort();
    /* Final release above: NEVER access slot afterward. */
    return (void*)result;
}
__declspec(dllexport) void* CALLBACK PublicSchedulerState(void* context) {
    if (context != NULL) return (void*)(ULONG_PTR)-1;
    return (void*)(ULONG_PTR)scheduler_load();
}
