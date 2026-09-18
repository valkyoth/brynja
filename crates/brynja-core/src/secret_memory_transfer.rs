//! Private secret-initialization transfer; not a whole-caller erasure promise.
#![allow(unsafe_code)]

use crate::SecretMemoryError;

pub(crate) fn copy(destination: &mut [u8], input: &[u8]) -> Result<(), SecretMemoryError> {
    if destination.len() != input.len() {
        return Err(SecretMemoryError::InsufficientCapacity);
    }
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: Equal, live, disjoint Rust slices; zero length performs no access.
    unsafe {
        copy_bytes(destination.as_mut_ptr(), input.as_ptr(), input.len())
    };
    #[cfg(not(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )))]
    for (output, byte) in destination.iter_mut().zip(input.iter()) {
        *output = *byte;
    }
    Ok(())
}

/// # Safety
/// For nonzero length both pointers must cover that many live, disjoint bytes,
/// writable/readable respectively. Length is bounded by Rust slice allocation
/// limits. No dereference occurs at zero length. Baseline x86-64 or little-endian
/// AArch64 only; working registers clear on normal return, without stack spills.
#[cfg(all(
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
#[inline(never)]
pub(crate) unsafe extern "C" fn copy_bytes(destination: *mut u8, source: *const u8, length: usize) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Public remaining count admits each eight-byte or one-byte access.
    // Offsets cannot wrap under the Rust allocation bound; all work is opaque.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_COPY_BEGIN",
            "xor ecx, ecx",
            "mov rdx, {length}",
            "cmp rdx, 8",
            "jb 3f",
            "2:",
            "mov rax, [{source} + rcx]",
            "mov [{destination} + rcx], rax",
            "add rcx, 8",
            "sub rdx, 8",
            "cmp rdx, 8",
            "jae 2b",
            "3:",
            "test rdx, rdx",
            "jz 5f",
            "4:",
            "movzx eax, byte ptr [{source} + rcx]",
            "mov byte ptr [{destination} + rcx], al",
            "inc rcx",
            "dec rdx",
            "jne 4b",
            "5:",
            "# BRYNJA_COPY_ERASE",
            "xor eax, eax",
            "xor ecx, ecx",
            "xor edx, edx",
            "# BRYNJA_COPY_END",
            destination = in(reg) destination, source = in(reg) source, length = in(reg) length,
            out("rax") _, out("rcx") _, out("rdx") _, options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Same checked remaining count and bounds, including empty input.
    // All secret loads/stores stay inside the call-free, stack-free boundary.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_COPY_BEGIN",
            "mov x5, xzr",
            "mov x6, {length}",
            "cmp x6, #8",
            "b.lo 3f",
            "2:",
            "ldr x4, [{source}, x5]",
            "str x4, [{destination}, x5]",
            "add x5, x5, #8",
            "sub x6, x6, #8",
            "cmp x6, #8",
            "b.hs 2b",
            "3:",
            "cbz x6, 5f",
            "4:",
            "ldrb w4, [{source}, x5]",
            "strb w4, [{destination}, x5]",
            "add x5, x5, #1",
            "sub x6, x6, #1",
            "cbnz x6, 4b",
            "5:",
            "// BRYNJA_COPY_ERASE",
            "mov x4, xzr",
            "mov x5, xzr",
            "mov x6, xzr",
            "cmp xzr, xzr",
            "// BRYNJA_COPY_END",
            destination = in(reg) destination, source = in(reg) source, length = in(reg) length,
            out("x4") _, out("x5") _, out("x6") _, options(nostack),
        );
    }
}
