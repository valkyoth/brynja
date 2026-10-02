/* Baseline C: reject permanently before any specialized Rust entry, including
 * destruction. Lost CPU/OS support cannot be reported as completed cleanup. */
static BOOL simd_rejected;
static BOOL Sha256SimdReady(void) {
    ULONG_PTR words[11], i;
    if (simd_rejected) { return FALSE; }
    for (i = 0; i < 11; ++i) {
        words[i] = (ULONG_PTR)PublicCpuInventory((void*)i);
        if (words[i] == INVALID_QUERY) { goto reject; }
    }
    if (words[0] != 0x42525943 || words[1] != 1 || words[2] != 15 || words[3] < 7 ||
        !(words[4] & (1U << 26)) || (words[5] & 0x1c000000U) != 0x1c000000U ||
        !(words[6] & (1U << 5)) || (words[9] & 6) != 6) { goto reject; }
    return TRUE;
reject:
    simd_rejected = TRUE;
    return FALSE;
}
