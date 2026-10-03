/* Included after the per-frame stack metadata and notify() definitions. */
ULONG_PTR PrivateParallelRootRegion(ULONG_PTR pointer, ULONG_PTR size) {
    STACK_SLOT* root = &slots[4];
    return root->admitted && size <= 65536 && pointer >= root->low &&
        pointer <= root->high - size;
}

ULONG_PTR PrivateParallelDispatch(void) {
    /* The original root call remains suspended on its admitted frame while
     * the host starts/joins four other entries. Rust independently closes
     * admission and waits for all slot borrowers before touching its Batch. */
    return notify(&slots[4], 2);
}

__declspec(noinline) ULONG_PTR PublicStackBody(STACK_SLOT* slot) {
    volatile unsigned char marker[16] = {0};
    slot->marker = (ULONG_PTR)marker;
    if (!slot->admitted || slot->marker < slot->low ||
        slot->marker > slot->high - sizeof(marker) || !ParallelAcceleratedReady())
        return 0;
    slot->body = TRUE;
    if (slot->lane == 4) return PrivateParallelRoot((ULONG_PTR)InterlockedCompareExchange(&root_identity, 0, 0));
    return PrivateParallelLeaf(slot->lane);
}
