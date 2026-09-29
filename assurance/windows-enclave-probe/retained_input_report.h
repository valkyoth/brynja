/* Private fixed-ABI observation validation, not hostile-host attestation. */
#include <stdint.h>
static int retained_input_report(const uint64_t r[11], uint64_t op, uint64_t status,
                                 uint64_t low, uint64_t high, uint64_t length, uint64_t epoch) {
    const uint64_t widths[4] = {32, 1024, 1170, 32};
    unsigned i, j;
    uint64_t header, payload, admitted;
    if (op != 1) {
        for (i = 0; i < 11; ++i) { if (r[i]) { return 0; } }
        return 1;
    }
    if (length > 1024 || !epoch || high < low || high - low != 65536) { return 0; }
    if (status != 2 && status != 120 && status != 121) { return 0; }
    header = status == 121 && r[1] == 0 ? 0 : 1;
    payload = status != 120 && header && length != 0 ? 1 : 0;
    admitted = status == 120 || !header ? 0 : length;
    if (r[0] != 1 || r[1] != header || r[2] != payload ||
        r[3] != (status == 121 ? 0 : payload) || r[8] != admitted || r[9] != 1 || r[10] != epoch) { return 0; }
    /* A successful copy cannot be called a copy failure with no copy attempted. */
    if (status == 121 && header && !payload) { return 0; }
    for (i = 0; i < 4; ++i) {
        uint64_t a = r[4 + i];
        if (a < low || a > high || widths[i] > high - a) { return 0; }
        for (j = 0; j < i; ++j) {
            uint64_t b = r[4 + j];
            if (a <= b ? b - a < widths[i] : a - b < widths[j]) { return 0; }
        }
    }
    return 1;
}
