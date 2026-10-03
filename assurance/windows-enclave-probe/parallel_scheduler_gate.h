/* Private generation-bound native record lifetime. Full-barrier interlocked
 * operations publish metadata and join native window cleanup. No reset/ABA.
 * Diagnostic readers also pin the generation: a check followed by an unpinned
 * slot read would race the next generation's slot reset. */
#define SCHED_OPEN (1ULL << 16)
#define SCHED_CLOSED (1ULL << 17)
#define SCHED_RESERVED (1ULL << 18)
#define SCHED_LIVE (15ULL << 4)
#define SCHED_READ_ONE (1ULL << 20)
#define SCHED_READERS (4095ULL << 20)
#define SCHED_LOW 0xffffffffULL
#define SCHED_MAX_GENERATION 16384ULL
static volatile LONG64 scheduler_state;

static ULONGLONG scheduler_load(void) {
    return (ULONGLONG)InterlockedCompareExchange64(&scheduler_state, 0, 0);
}
static BOOL scheduler_cas(ULONGLONG old, ULONGLONG next) {
    return (ULONGLONG)InterlockedCompareExchange64(&scheduler_state, (LONG64)next, (LONG64)old) == old;
}
static BOOL scheduler_reserve(ULONG_PTR generation, ULONG_PTR lanes) {
    ULONGLONG old = scheduler_load(), mask;
    if (generation == 0 || generation > SCHED_MAX_GENERATION || lanes == 0 || lanes > 4 ||
        (old & SCHED_LOW) != 0 || (old >> 32) + 1 != generation) return FALSE;
    mask = ((1ULL << lanes) - 1) << 12;
    return scheduler_cas(old, ((ULONGLONG)generation << 32) | mask | SCHED_RESERVED);
}
static BOOL scheduler_publish(ULONG_PTR generation) {
    ULONGLONG old = scheduler_load();
    if ((old >> 32) != generation || (old & SCHED_LOW & ~0xf000ULL) != SCHED_RESERVED) return FALSE;
    return scheduler_cas(old, (old & ~SCHED_RESERVED) | SCHED_OPEN);
}
static BOOL scheduler_enter(ULONG_PTR generation, ULONG_PTR lane) {
    ULONGLONG old = scheduler_load(), bit;
    if (generation == 0 || generation > SCHED_MAX_GENERATION || lane >= 4) return FALSE;
    bit = 1ULL << lane;
    for (;;) {
        if ((old >> 32) != generation || !(old & SCHED_OPEN) || (old & bit) || !(old & (bit << 12))) return FALSE;
        if (scheduler_cas(old, old | bit | (bit << 4))) return TRUE;
        old = scheduler_load();
    }
}
static BOOL scheduler_close(ULONG_PTR generation) {
    ULONGLONG old = scheduler_load();
    for (;;) {
        if ((old >> 32) != generation || !(old & (SCHED_OPEN | SCHED_CLOSED))) return FALSE;
        if (scheduler_cas(old, (old & ~SCHED_OPEN) | SCHED_CLOSED)) return TRUE;
        old = scheduler_load();
    }
}
static BOOL scheduler_leave(ULONG_PTR generation, ULONG_PTR lane, BOOL clean) {
    ULONGLONG old = scheduler_load(), bit;
    if (lane >= 4) return FALSE;
    bit = 1ULL << lane;
    for (;;) {
        if ((old >> 32) != generation || !(old & (bit << 4)) || !(old & bit)) return FALSE;
        /* Final native record access precedes this release. */
        if (scheduler_cas(old, (old & ~(bit << 4)) | (clean ? bit << 8 : 0))) return TRUE;
        old = scheduler_load();
    }
}
static BOOL scheduler_quiescent(ULONG_PTR generation) {
    ULONGLONG state = scheduler_load();
    return (state >> 32) == generation && (state & (SCHED_OPEN | SCHED_CLOSED | SCHED_LIVE)) == SCHED_CLOSED;
}
static BOOL scheduler_complete(ULONG_PTR generation) {
    ULONGLONG state = scheduler_load(), mask = (state >> 12) & 15;
    return (state >> 32) == generation && mask != 0 &&
        (state & (SCHED_OPEN | SCHED_CLOSED | SCHED_LIVE)) == SCHED_CLOSED &&
        (state & 15) == mask && ((state >> 8) & 15) == mask;
}
static BOOL scheduler_read_begin(ULONG_PTR generation) {
    ULONGLONG old = scheduler_load();
    for (;;) {
        if ((old >> 32) != generation || (old & (SCHED_OPEN | SCHED_CLOSED | SCHED_LIVE)) != SCHED_CLOSED ||
            (old & SCHED_READERS) == SCHED_READERS) return FALSE;
        if (scheduler_cas(old, old + SCHED_READ_ONE)) return TRUE;
        old = scheduler_load();
    }
}
static BOOL scheduler_read_end(ULONG_PTR generation) {
    ULONGLONG old = scheduler_load();
    for (;;) {
        if ((old >> 32) != generation || !(old & SCHED_READERS)) return FALSE;
        if (scheduler_cas(old, old - SCHED_READ_ONE)) return TRUE;
        old = scheduler_load();
    }
}
static BOOL scheduler_retire(ULONG_PTR generation) {
    ULONGLONG old = scheduler_load(), mask = (old >> 12) & 15;
    if ((old >> 32) != generation || mask == 0 ||
        (old & (SCHED_OPEN | SCHED_CLOSED | SCHED_RESERVED | SCHED_LIVE | SCHED_READERS)) != SCHED_CLOSED ||
        (old & 15) != mask || ((old >> 8) & 15) != mask) return FALSE;
    return scheduler_cas(old, old & ~SCHED_LOW);
}
