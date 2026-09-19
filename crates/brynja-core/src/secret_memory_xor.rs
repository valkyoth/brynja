//! Borrowed bit transfer; offsets/count are public, bytes remain caller-owned.
#![allow(unsafe_code)]
use crate::SecretBitRangeError;

pub(crate) fn apply(
    destination: &mut u8,
    source: &u8,
    right: u8,
    count: u8,
    left: u8,
) -> Result<(), SecretBitRangeError> {
    let remaining = 8_u8.checked_sub(count).ok_or(SecretBitRangeError)?;
    if count == 0 || right > remaining || left > remaining {
        return Err(SecretBitRangeError);
    }
    let mask = u8::MAX
        .checked_shr(u32::from(remaining))
        .ok_or(SecretBitRangeError)?;
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: Disjoint live byte borrows; checked offsets and count fit each byte.
    unsafe {
        xor_bits(
            core::ptr::from_mut(destination),
            core::ptr::from_ref(source),
            u32::from(right),
            u32::from(left),
            u32::from(mask),
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
        *destination ^= (source
            .checked_shr(u32::from(right))
            .ok_or(SecretBitRangeError)?
            & mask)
            .checked_shl(u32::from(left))
            .ok_or(SecretBitRangeError)?;
    }
    Ok(())
}

/// # Safety
/// Exactly one writable destination byte and one disjoint readable source byte.
/// Public right/left are <=7 and mask selects 1..=8 bits fitting both shifts.
/// Baseline x86-64/little-endian AArch64. No secret byte escapes in the return
/// value. Working registers clear on normal return, not on interruption/abort.
#[cfg(all(
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
#[inline(never)]
pub(crate) unsafe extern "C" fn xor_bits(
    destination: *mut u8,
    source: *const u8,
    right: u32,
    left: u32,
    mask: u32,
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Only byte memory accesses; early clobbers exclude pointers/masks
    // from rax/rcx. Public variable shifts, no calls, stack or data-dependent flow.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_XOR_BEGIN",
            "movzx eax, byte ptr [{source}]",
            "mov ecx, {right:e}", "shr eax, cl",
            "and eax, {mask:e}",
            "mov ecx, {left:e}", "shl eax, cl",
            "xor byte ptr [{destination}], al",
            "# BRYNJA_XOR_ERASE",
            "xor eax, eax", "xor ecx, ecx",
            "# BRYNJA_XOR_END",
            destination = in(reg) destination, source = in(reg) source,
            right = in(reg) right, left = in(reg) left, mask = in(reg) mask,
            out("rax") _, out("rcx") _, options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: ldrb/strb access exactly the borrowed bytes; all secret data stays
    // in early-clobbered w5/w6, and both full registers plus flags clear last.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_XOR_BEGIN",
            "ldrb w5, [{source}]", "lsr w5, w5, {right:w}",
            "and w5, w5, {mask:w}", "lsl w5, w5, {left:w}",
            "ldrb w6, [{destination}]", "eor w6, w6, w5", "strb w6, [{destination}]",
            "// BRYNJA_XOR_ERASE",
            "mov x5, xzr", "mov x6, xzr", "cmp xzr, xzr",
            "// BRYNJA_XOR_END",
            destination = in(reg) destination, source = in(reg) source,
            right = in(reg) right, left = in(reg) left, mask = in(reg) mask,
            out("x5") _, out("x6") _, options(nostack),
        );
    }
}
