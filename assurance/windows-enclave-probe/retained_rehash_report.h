/* Fixed private metadata checker, not residency attestation. */
#include <stdint.h>
static int retained_rehash_report(const uint64_t r[9], uint64_t op, uint64_t status,
                                  uint64_t low, uint64_t high, uint64_t generation, uint64_t epoch) {
    const uint64_t width[3] = {1170, 32, 32};
    unsigned i, j;
    if (op != 8 && op != 9) {
        for (i = 0; i < 8; ++i) { if (r[i]) { return 0; } }
        return r[8] == (uint64_t)(op == 2 || op == 6);
    }
    if (!generation || !epoch || high < low || high - low != 65536 || r[8] != 0 || r[3] != 1 ||
        r[6] != epoch || r[7] != status) { return 0; }
    if (op == 8) {
        if (generation == UINT64_MAX || status != 8 || r[4] != generation || r[5] != generation + 1) { return 0; }
    } else if (generation < 2 || status != 103 || r[4] != generation - 1 || r[5] != 0) { return 0; }
    for (i = 0; i < 3; ++i) {
        if (r[i] < low || r[i] > high || width[i] > high - r[i]) { return 0; }
        for (j = 0; j < i; ++j) {
            if (r[i] <= r[j] ? r[j] - r[i] < width[i] : r[i] - r[j] < width[j]) { return 0; }
        }
    }
    return 1;
}
