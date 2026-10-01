/* Baseline C only. AVX2 Rust entry (including Drop) requires the entire bundle
 * and OS-managed XMM/YMM state; it does not require unrelated SHA-NI features.
 * Lost authority is terminal: never call specialized cleanup after rejection. */
static BOOL accelerated_rejected;
static BOOL TupleAcceleratedReady(void) {
    ULONG_PTR words[11], i;
    if (accelerated_rejected) { return FALSE; }
    for (i = 0; i < 11; ++i) {
        words[i] = (ULONG_PTR)PublicCpuInventory((void*)i);
        if (words[i] == INVALID_QUERY) { goto reject; }
    }
    if (words[0] != 0x42525943 || words[1] != 1 || words[2] != 15 || words[3] < 7 ||
        !(words[4] & (1U << 26)) || (words[5] & 0x1c000000U) != 0x1c000000U ||
        !(words[6] & (1U << 5)) || (words[9] & 6) != 6) { goto reject; }
    return TRUE;
reject:
    accelerated_rejected = TRUE;
    return FALSE;
}
