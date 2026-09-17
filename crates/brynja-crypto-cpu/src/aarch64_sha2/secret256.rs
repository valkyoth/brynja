//! SHA-224/256 secret compression with an opaque register-cleanup boundary.
#![allow(unsafe_code)]

/// Compress the first 64 input bytes into the first 32 state bytes.
/// Caller-owned buffers and pre-existing caller registers are not erased.
///
/// # Safety
/// NEON/SHA2 support must hold on every eligible CPU throughout the call.
/// This boundary supports little-endian AArch64; it grants no platform authority.
#[target_feature(enable = "neon,sha2")]
#[inline(never)]
pub unsafe extern "C" fn compress(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut [u8; 704],
    constants: &[u32; 64],
) {
    const {
        assert!(cfg!(target_endian = "little"));
    }
    // SAFETY: Four exact live borrows bound every access. Public byte offsets
    // initialize 0..64, expand 64..256, then run sixteen four-round groups.
    // The -64/-60/-28/-8 recurrence stays in initialized schedule storage.
    // State loads/stores cover precisely 32 bytes; scratch cleanup covers 704.
    // No stack, call or secret Rust result crosses the block. All working
    // X4/X5/X6/X7/X9 and V0..5 are declared and erased; NZCV is reset. ABI
    // preserved V8..15 are untouched. Unaligned normal-memory loads are valid.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_SECRET_BEGIN",
            "mov x4, #0",
            "2:",
            "ldr w5, [{block}, x4]",
            "rev w5, w5",
            "str w5, [{scratch}, x4]",
            "add x4, x4, #4",
            "cmp x4, #64",
            "b.ne 2b",
            "3:",
            "add x7, {scratch}, x4",
            "ldur w5, [x7, #-60]",
            "ror w6, w5, #7",
            "eor w6, w6, w5, ror #18",
            "lsr w5, w5, #3",
            "eor w6, w6, w5",
            "ldur w5, [x7, #-8]",
            "ror w9, w5, #17",
            "eor w9, w9, w5, ror #19",
            "lsr w5, w5, #10",
            "eor w9, w9, w5",
            "add w6, w6, w9",
            "ldur w5, [x7, #-64]",
            "add w6, w6, w5",
            "ldur w5, [x7, #-28]",
            "add w6, w6, w5",
            "str w6, [x7]",
            "add x4, x4, #4",
            "cmp x4, #256",
            "b.ne 3b",
            "ldp q0, q1, [{state}]",
            "rev32 v0.16b, v0.16b",
            "rev32 v1.16b, v1.16b",
            "mov v2.16b, v0.16b",
            "mov v3.16b, v1.16b",
            "mov x4, #0",
            "4:",
            "ldr q4, [{scratch}, x4]",
            "ldr q5, [{constants}, x4]",
            "add v4.4s, v4.4s, v5.4s",
            "mov v5.16b, v0.16b",
            "sha256h q0, q1, v4.4s",
            "sha256h2 q1, q5, v4.4s",
            "add x4, x4, #16",
            "cmp x4, #256",
            "b.ne 4b",
            "add v0.4s, v0.4s, v2.4s",
            "add v1.4s, v1.4s, v3.4s",
            "rev32 v0.16b, v0.16b",
            "rev32 v1.16b, v1.16b",
            "stp q0, q1, [{state}]",
            "mov x4, #0",
            "5:",
            "str xzr, [{scratch}, x4]",
            "add x4, x4, #8",
            "cmp x4, #704",
            "b.ne 5b",
            "// BRYNJA_REGISTER_ERASE",
            "movi v0.16b, #0", "movi v1.16b, #0", "movi v2.16b, #0",
            "movi v3.16b, #0", "movi v4.16b, #0", "movi v5.16b, #0",
            "mov x4, xzr", "mov x5, xzr", "mov x6, xzr",
            "mov x7, xzr", "mov x9, xzr",
            "cmp xzr, xzr",
            "// BRYNJA_SECRET_END",
            state = in(reg) state.as_mut_ptr(),
            block = in(reg) block.as_ptr(),
            scratch = in(reg) scratch.as_mut_ptr(),
            constants = in(reg) constants.as_ptr(),
            out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x9") _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _,
            options(nostack),
        );
    }
}
