/* Guest-side query using Linux UAPI names, not target flags or model labels.
 * A missing syscall or unknown key is not a successful negative control. */
#define _GNU_SOURCE
#include <asm/hwprobe.h>
#include <sys/syscall.h>
#include <unistd.h>

int probe_capabilities(void)
{
    struct riscv_hwprobe p = { .key = RISCV_HWPROBE_KEY_IMA_EXT_0 };
    if (syscall(SYS_riscv_hwprobe, &p, 1UL, 0UL, NULL, 0UL) != 0 ||
        p.key != RISCV_HWPROBE_KEY_IMA_EXT_0)
        return -1;
    return ((p.value & RISCV_HWPROBE_IMA_V) ? 1 : 0) |
           ((p.value & RISCV_HWPROBE_EXT_ZBC) ? 2 : 0) |
           ((p.value & RISCV_HWPROBE_EXT_ZVKG) ? 4 : 0) |
           ((p.value & RISCV_HWPROBE_EXT_ZVBC) ? 8 : 0);
}
