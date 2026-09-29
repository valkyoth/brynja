/* Separate public-data input-copy experiment; leaves the prior wire image intact. */
#include "window_wire.c"
int PublicBorrowedCopied(void) {
    if (!wire_call || !active) { return 0; }
    return notify_host(4) ? 1 : 0;
}
