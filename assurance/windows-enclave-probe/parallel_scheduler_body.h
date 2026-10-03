/* Root is never moved; only four worker records are reused after joined
 * generation retirement. Diagnostic reads participate in that retirement. */
ULONG_PTR PrivateWaveRootRegion(ULONG_PTR pointer, ULONG_PTR size) {
    STACK_SLOT* root = &slots[4];
    return root->admitted && size <= 65536 && pointer >= root->low && pointer <= root->high - size;
}

ULONG_PTR PrivateWaveDispatch(unsigned int generation, ULONG_PTR lanes) {
    ULONG_PTR lane;
    ULONGLONG attempt;
    BOOL dispatched, closed_ack;
    if (!scheduler_reserve(generation, lanes)) return 0;
    /* Reservation excludes stale workers AND readers before resetting metadata.
     * Rust independently keeps its old publication closed until slot cleanup. */
    for (lane = 0; lane < 4; ++lane) SecureZeroMemory(&slots[lane], sizeof(STACK_SLOT));
    if (!scheduler_publish(generation)) return 0;
    dispatched = notify(&slots[4], 2);
    if (!scheduler_close(generation)) PrivateWaveAbort();
    closed_ack = notify(&slots[4], 3);
    for (attempt = 0; attempt < 0x100000000ULL; ++attempt) {
        if (scheduler_quiescent(generation)) {
            BOOL joined_ack = notify(&slots[4], 4);
            return dispatched && closed_ack && joined_ack && scheduler_complete(generation);
        }
        YieldProcessor();
    }
    PrivateWaveAbort();
}

ULONG_PTR PrivateSchedulerRetire(unsigned int generation) {
    ULONGLONG attempt;
    if (!scheduler_complete(generation)) return 0;
    for (attempt = 0; attempt < 0x100000000ULL; ++attempt) {
        if (scheduler_retire(generation)) return 1;
        YieldProcessor();
    }
    /* A nonreturning diagnostic query must not allow storage reuse. */
    PrivateWaveAbort();
}

__declspec(noinline) ULONG_PTR PublicStackBody(STACK_SLOT* slot) {
    volatile unsigned char marker[16] = {0};
    slot->marker = (ULONG_PTR)marker;
    if (!slot->admitted || slot->marker < slot->low || slot->marker > slot->high - sizeof(marker) ||
        !ParallelAcceleratedReady()) return 0;
    slot->body = TRUE;
    if (slot->lane == 4) return PrivateWaveRoot((ULONG_PTR)root_source);
    return PrivateWaveLeaf((unsigned int)(scheduler_load() >> 32), slot->lane);
}
