/* Private bounded experiment: three unique gates, never reset/recycled.
 * Windows interlocked operations are full barriers. No slot pointer may be
 * read before claim; last release follows full native frame cleanup. */
#define WAVE_OPEN (1L << 16)
#define WAVE_LIVE (15L << 4)
static volatile LONG native_waves[3];

static LONG wave_mask(ULONG_PTR generation) {
    return generation == 3 ? 3 : 15;
}
static BOOL wave_open(ULONG_PTR generation) {
    if (generation < 1 || generation > 3) return FALSE;
    return InterlockedCompareExchange(&native_waves[generation - 1], WAVE_OPEN, 0) == 0;
}
static BOOL wave_enter(ULONG_PTR generation, ULONG_PTR lane) {
    LONG bit, state, next;
    volatile LONG* gate;
    if (generation < 1 || generation > 3 || lane >= 4) return FALSE;
    bit = 1L << lane;
    if (!(wave_mask(generation) & bit)) return FALSE;
    gate = &native_waves[generation - 1];
    state = InterlockedCompareExchange(gate, 0, 0);
    for (;;) {
        if (!(state & WAVE_OPEN) || (state & bit)) return FALSE;
        next = InterlockedCompareExchange(gate, state | bit | (bit << 4), state);
        if (next == state) return TRUE;
        state = next;
    }
}
static void wave_close(ULONG_PTR generation) {
    /* Keep a permanent marker even if no worker claimed a lane. */
    InterlockedOr(&native_waves[generation - 1], 1L << 17);
    InterlockedAnd(&native_waves[generation - 1], ~WAVE_OPEN);
}
static BOOL wave_quiescent(ULONG_PTR generation) {
    return !(InterlockedCompareExchange(&native_waves[generation - 1], 0, 0) & (WAVE_OPEN | WAVE_LIVE));
}
static void wave_leave(ULONG_PTR generation, ULONG_PTR lane, BOOL clean) {
    LONG bit = 1L << lane;
    if (clean) InterlockedOr(&native_waves[generation - 1], bit << 8);
    /* Must be the last native slot access, after clear/readback/unlock/restore. */
    InterlockedAnd(&native_waves[generation - 1], ~(bit << 4));
}
static BOOL wave_complete(ULONG_PTR generation) {
    LONG state = InterlockedCompareExchange(&native_waves[generation - 1], 0, 0);
    LONG mask = wave_mask(generation);
    return !(state & (WAVE_OPEN | WAVE_LIVE)) && (state & 15) == mask && ((state >> 8) & 15) == mask;
}
