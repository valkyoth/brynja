/* Root remains on the same live frame across every dispatch and join. */
ULONG_PTR PrivateWaveRootRegion(ULONG_PTR pointer, ULONG_PTR size) {
    STACK_SLOT* root = &slots[12];
    return root->admitted && size <= 65536 && pointer >= root->low &&
        pointer <= root->high - size;
}

ULONG_PTR PrivateWaveDispatch(unsigned int generation, ULONG_PTR lanes) {
    BOOL dispatched, closed_ack;
    ULONGLONG attempt;
    if (generation < 1 || generation > 3 || lanes != (generation == 3 ? 2 : 4) ||
        InterlockedCompareExchange(&root_generation, (LONG)generation,
                                   (LONG)generation - 1) != (LONG)generation - 1 ||
        !wave_open(generation)) return 0;
    dispatched = notify(&slots[12], 2 + generation);
    wave_close(generation);
    /* Diagnostic close acknowledgement releases deliberately held test workers.
     * It cannot authorize storage reuse: independent native ticket join follows. */
    closed_ack = notify(&slots[12], 6 + generation);
    for (attempt = 0; attempt < 0x100000000ULL; ++attempt) {
        if (wave_quiescent(generation)) {
            BOOL joined_ack = notify(&slots[12], 10 + generation);
            return dispatched && closed_ack && joined_ack && wave_complete(generation);
        }
        YieldProcessor();
    }
    PrivateWaveAbort(); /* Never return and free a still-borrowed native frame. */
}

__declspec(noinline) ULONG_PTR PublicStackBody(STACK_SLOT* slot) {
    volatile unsigned char marker[16] = {0};
    ULONG_PTR generation, lane;
    slot->marker = (ULONG_PTR)marker;
    if (!slot->admitted || slot->marker < slot->low ||
        slot->marker > slot->high - sizeof(marker) || !ParallelAcceleratedReady()) return 0;
    slot->body = TRUE;
    if (slot->lane == 12) return PrivateWaveRoot((ULONG_PTR)InterlockedCompareExchange(&root_identity, 0, 0));
    generation = slot->lane / 4 + 1;
    lane = slot->lane % 4;
    return PrivateWaveLeaf((unsigned int)generation, lane);
}
