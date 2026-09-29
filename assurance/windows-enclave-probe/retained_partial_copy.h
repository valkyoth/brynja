/* Diagnostic-only prefix-copy policy; not a production operation or OS guarantee. */
#include <stdint.h>
static inline int partial_copy_plan(uint64_t command, uint64_t kind, uint64_t size,
                             uint64_t* prefix) {
    uint64_t selected = command >> 32, count = command & UINT64_C(0xffffffff);
    if ((selected != 1 && selected != 2) || kind > 1 || selected != kind + 1 ||
        size == 0 || size > 1024 || (kind == 0 && size != 32) || count > size) { return 0; }
    *prefix = count;
    return 1;
}
static inline int partial_copy_report(const uint64_t r[5], uint64_t command) {
    uint64_t kind = command >> 32, count = command & UINT64_C(0xffffffff);
    if (kind != 1 && kind != 2) { return 0; }
    if (count > (kind == 1 ? 32u : 1024u)) { return 0; }
    /* matched request, actual successful OS prefix copy (unless zero), forced error */
    return r[0] == command && r[1] == 1 && r[2] == count &&
           r[3] == (uint64_t)(count != 0) && r[4] == 1;
}
