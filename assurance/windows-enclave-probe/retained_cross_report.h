/* Source-bound observations, not hostile-host authentication. */
#include <stdint.h>
static inline int retained_cross_report(const uint64_t copy[6], const uint64_t r[9],
    const uint64_t token[4], uint64_t status, uint64_t expected,
    uint64_t low, uint64_t high, uint64_t generation, uint64_t epoch) {
    const uint64_t widths[3] = {1170,32,32};
    unsigned i,j;
    if (copy[0] != 1 || copy[1] != 1 || !generation || !epoch || high < low ||
        high-low != 65536 || status != expected || (status != 8 && status != 103)) { return 0; }
    for (i=0;i<4;++i) { if(copy[i+2] != token[i]) { return 0; } }
    if (r[3] != 1 || r[4] != token[2] || r[6] != epoch || r[7] != status || r[8] != 0) { return 0; }
    if (status == 8 ? generation == UINT64_MAX || token[2] != generation || r[5] != generation+1 : r[5] != 0) { return 0; }
    for(i=0;i<3;++i) {
        if(r[i]<low || r[i]>high || widths[i]>high-r[i]) { return 0; }
        for(j=0;j<i;++j) {
            if(r[i]<=r[j] ? r[j]-r[i]<widths[i] : r[i]-r[j]<widths[j]) { return 0; }
        }
    }
    return 1;
}
