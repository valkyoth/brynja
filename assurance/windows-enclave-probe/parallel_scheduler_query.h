/* Public metadata snapshots pin their generation while reading reusable slots.
 * Root record is never reused and may only be read after its final release. */
__declspec(dllexport) void* CALLBACK PublicStackQuery(void* context) {
    ULONG_PTR word = (ULONG_PTR)context, generation = word / 256, lane = (word / 16) % 16, field = word % 16;
    ULONG_PTR value = (ULONG_PTR)-1;
    STACK_SLOT* slot;
    BOOL pinned = FALSE;
    if (lane == 4 && generation == 0) {
        slot = &slots[4];
        if (InterlockedCompareExchange(&slot->done, 0, 0) != 1) return (void*)value;
    } else {
        if (lane >= 4 || field >= 8 || !scheduler_read_begin(generation)) return (void*)value;
        pinned = TRUE;
        slot = &slots[lane];
    }
    if (InterlockedCompareExchange(&slot->done, 0, 0) == 1) {
        switch (field) {
        case 0: value=slot->low; break;
        case 1: value=slot->high; break;
        case 2: value=slot->marker; break;
        case 3: value=slot->admitted; break;
        case 4: value=slot->cleared; break;
        case 5: value=slot->restored; break;
        case 6: value=slot->body; break;
        case 7: value=slot->low_changed || slot->high_changed; break;
        default: break;
        }
    }
    if (pinned && !scheduler_read_end(generation)) PrivateWaveAbort();
    return (void*)value; /* No slot access after read pin release. */
}
