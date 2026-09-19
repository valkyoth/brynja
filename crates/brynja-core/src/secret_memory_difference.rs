//! Borrowed comparison accumulation; no intermediate decision is returned.
#![allow(unsafe_code)]

pub(crate) fn accumulate(difference: &mut u8, left: &u8, right: &u8) {
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: One exclusive writable byte and two live shared readable bytes.
    // The shared inputs may alias each other, but not the exclusive accumulator.
    unsafe {
        accumulate_byte(
            core::ptr::from_mut(difference),
            core::ptr::from_ref(left),
            core::ptr::from_ref(right),
        )
    };
    #[cfg(not(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )))]
    {
        *difference |= *left ^ *right;
    }
}

/// # Safety
/// Each pointer covers exactly one live byte. Difference is writable and
/// disjoint from both readable inputs; left/right may alias. Baseline x86-64
/// or little-endian AArch64. All working registers clear on normal return;
/// no guarantee covers interruption, caller copies, spills or platform storage.
#[cfg(all(
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
#[inline(never)]
pub(crate) unsafe extern "C" fn accumulate_byte(
    difference: *mut u8,
    left: *const u8,
    right: *const u8,
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Three byte-only accesses; the early clobber excludes every pointer.
    // No stack, calls or content-dependent control; RAX and flags clear last.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_DIFFERENCE_BEGIN",
            "movzx eax, byte ptr [{left}]",
            "xor al, byte ptr [{right}]",
            "or byte ptr [{difference}], al",
            "# BRYNJA_DIFFERENCE_ERASE",
            "xor eax, eax",
            "# BRYNJA_DIFFERENCE_END",
            difference = in(reg) difference, left = in(reg) left, right = in(reg) right,
            out("rax") _, options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Byte loads/store only; early-clobbered X4/X5 exclude all pointers.
    // Neither input nor the accumulated difference escapes the opaque boundary.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_DIFFERENCE_BEGIN",
            "ldrb w4, [{left}]", "ldrb w5, [{right}]", "eor w4, w4, w5",
            "ldrb w5, [{difference}]", "orr w4, w4, w5", "strb w4, [{difference}]",
            "// BRYNJA_DIFFERENCE_ERASE",
            "mov x4, xzr", "mov x5, xzr", "cmp xzr, xzr",
            "// BRYNJA_DIFFERENCE_END",
            difference = in(reg) difference, left = in(reg) left, right = in(reg) right,
            out("x4") _, out("x5") _, options(nostack),
        );
    }
}
