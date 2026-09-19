//! Private borrowed-byte operation; not a whole-caller erasure promise.
#![allow(unsafe_code)]

pub(crate) fn apply(byte: &mut u8, keep: u8, set: u8) {
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: One exclusively borrowed live byte, with no alignment requirement.
    unsafe {
        mask_byte(core::ptr::from_mut(byte), keep, set)
    };
    #[cfg(not(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )))]
    {
        *byte = (*byte & keep) | set;
    }
}

/// # Safety
/// `byte` points to one live, exclusively writable byte. Masks are public.
/// Baseline x86-64 or little-endian AArch64; no widened memory accesses, stack
/// spills or calls inside the opaque boundary. Working register clears on normal
/// return; caller copies, spills and interruption snapshots are not covered.
#[cfg(all(
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
#[inline(never)]
pub(crate) unsafe extern "C" fn mask_byte(byte: *mut u8, keep: u8, set: u8) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Exact byte read/write through the exclusive pointer. Inputs cannot
    // overlap the early-clobbered working register; no secret-dependent control.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_MASK_BEGIN",
            "movzx eax, byte ptr [{byte}]",
            "and al, {keep}",
            "or al, {set}",
            "mov byte ptr [{byte}], al",
            "# BRYNJA_MASK_ERASE",
            "xor eax, eax",
            "# BRYNJA_MASK_END",
            byte = in(reg) byte, keep = in(reg_byte) keep, set = in(reg_byte) set,
            out("rax") _, options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Only ldrb/strb touch the exclusively borrowed byte. All secret
    // computation stays in the early-clobbered w4, then x4 is cleared in full.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_MASK_BEGIN",
            "ldrb w4, [{byte}]",
            "and w4, w4, {keep:w}",
            "orr w4, w4, {set:w}",
            "strb w4, [{byte}]",
            "// BRYNJA_MASK_ERASE",
            "mov x4, xzr",
            "cmp xzr, xzr",
            "// BRYNJA_MASK_END",
            byte = in(reg) byte, keep = in(reg) u32::from(keep), set = in(reg) u32::from(set),
            out("x4") _, options(nostack),
        );
    }
}
