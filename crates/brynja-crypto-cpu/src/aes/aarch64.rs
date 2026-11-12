//! Internal little-endian AArch64 AES block candidate; no admission here.
#![allow(unsafe_code)]

/// Transforms one block using forward FIPS 197 round keys (11, 13 or 15).
/// Unlike AES-NI, AESE/AESD add the key before substitution. Middle decrypt
/// keys are inverse-mixed in registers; the stored schedule stays forward.
///
/// # Safety
/// NEON and AES must be available on every CPU eligible to execute this call.
/// The caller must provide the schedule for the intended AES key and own its
/// lifecycle. This private primitive supplies no execution authorization.
#[target_feature(enable = "neon,aes")]
#[inline(never)]
pub(crate) unsafe fn transform<const N: usize>(
    state: &mut [u8; 16],
    schedule: &[[u8; 16]; N],
    inverse: bool,
) {
    const {
        assert!(matches!(N, 11 | 13 | 15));
        assert!(cfg!(target_endian = "little"));
    }
    // SAFETY: N complete keys bound every 16-byte load, including the two
    // endpoints. Normal unaligned memory is supported. Input and output use
    // exactly the borrowed 16-byte state; schedule accesses are read-only.
    // Only public offsets/direction control branches. No calls, stack memory,
    // callee-saved vector registers or Rust secret outputs are used. All
    // working vectors and scratch GPRs, then NZCV, are cleared on return.
    // This bounded boundary does not erase upstream copies or detect faults.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_AES_SECRET_BEGIN",
            "ldr q0, [{state}]",
            "cbnz {inverse}, 4f",
            "mov x9, #0",
            "sub x10, {last}, #16",
            "2:",
            "ldr q1, [{schedule}, x9]",
            "aese v0.16b, v1.16b",
            "aesmc v0.16b, v0.16b",
            "add x9, x9, #16",
            "cmp x9, x10",
            "b.ne 2b",
            "ldr q1, [{schedule}, x9]",
            "aese v0.16b, v1.16b",
            "ldr q1, [{schedule}, {last}]",
            "eor v0.16b, v0.16b, v1.16b",
            "b 6f",
            "4:",
            "mov x9, {last}",
            "ldr q1, [{schedule}, x9]",
            "aesd v0.16b, v1.16b",
            "aesimc v0.16b, v0.16b",
            "5:",
            "sub x9, x9, #16",
            "ldr q1, [{schedule}, x9]",
            "aesimc v1.16b, v1.16b",
            "aesd v0.16b, v1.16b",
            "cmp x9, #16",
            "b.eq 7f",
            "aesimc v0.16b, v0.16b",
            "b 5b",
            "7:",
            "ldr q1, [{schedule}]",
            "eor v0.16b, v0.16b, v1.16b",
            "6:",
            "str q0, [{state}]",
            "// BRYNJA_AES_REGISTER_ERASE",
            "movi v0.16b, #0",
            "movi v1.16b, #0",
            "mov x9, #0",
            "mov x10, #0",
            "msr nzcv, xzr",
            "// BRYNJA_AES_SECRET_END",
            state = in(reg) state.as_mut_ptr(),
            schedule = in(reg) schedule.as_ptr(),
            last = in(reg) schedule.len().wrapping_sub(1).wrapping_mul(16),
            inverse = in(reg) usize::from(inverse),
            out("x9") _, out("x10") _, out("v0") _, out("v1") _,
            options(nostack),
        );
    }
}
