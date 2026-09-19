//! Borrowed validation predicate; only its Boolean result is declassified.
#![allow(unsafe_code)]

pub(crate) fn apply(byte: &u8, mask: u8) -> bool {
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: The shared borrow provides exactly one live readable byte.
    unsafe {
        mask_is_zero(core::ptr::from_ref(byte), mask) == 1
    }
    #[cfg(not(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )))]
    {
        *byte & mask == 0
    }
}

/// # Safety
/// `byte` points to one live readable byte. The mask and resulting predicate
/// are public. Only a byte load is allowed; the input is never modified.
/// Baseline x86-64/little-endian AArch64 clears its working register and flags
/// on normal return. The Boolean return value intentionally remains visible.
#[cfg(all(
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
#[inline(never)]
pub(crate) unsafe extern "C" fn mask_is_zero(byte: *const u8, mask: u8) -> u32 {
    let result: u32;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: One exact byte load. Early-clobbered r10 and result cannot overlap
    // each other or either input. Result is fully normalized before r10 clears.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_PREDICATE_BEGIN",
            "movzx r10d, byte ptr [{byte}]",
            "and r10d, {mask:e}",
            "sete {result:l}",
            "movzx {result:e}, {result:l}",
            "# BRYNJA_PREDICATE_ERASE",
            "xor r10d, r10d",
            "# BRYNJA_PREDICATE_END",
            byte = in(reg) byte, mask = in(reg) u32::from(mask),
            result = out(reg) result,
            out("r10") _, options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: One ldrb from the live shared byte; early-clobbered w4 contains
    // the secret computation, result is Boolean, and x4/NZCV are then cleared.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_PREDICATE_BEGIN",
            "ldrb w4, [{byte}]",
            "and w4, w4, {mask:w}",
            "cmp w4, #0",
            "cset {result:w}, eq",
            "// BRYNJA_PREDICATE_ERASE",
            "mov x4, xzr",
            "cmp xzr, xzr",
            "// BRYNJA_PREDICATE_END",
            byte = in(reg) byte, mask = in(reg) u32::from(mask),
            result = out(reg) result,
            out("x4") _, options(nostack),
        );
    }
    result
}
