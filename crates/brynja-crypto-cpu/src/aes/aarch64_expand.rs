//! Little-endian expansion, behind sealed admission or explicit test harnesses.
#![allow(unsafe_code)]

/// Writes a complete forward FIPS 197 schedule, including the original key.
///
/// # Safety
/// Little-endian NEON/AES must remain available on every eligible CPU. Normal
/// memory must support unaligned word accesses. Caller owns/clears both buffers;
/// no admission, secret owner or fault resistance is established here.
#[target_feature(enable = "neon,aes")]
#[inline(never)]
pub(crate) unsafe fn expand<const K: usize, const S: usize>(key: &[u8; K], schedule: &mut [u8; S]) {
    const {
        assert!(matches!((K, S), (16, 176) | (24, 208) | (32, 240)));
        assert!(cfg!(target_endian = "little"));
    }
    // SAFETY: The exact matched lengths bound all unaligned 4-byte reads and
    // writes; previous words are read only after initialization. Key/output
    // borrows are disjoint. Replicating the word in every column makes
    // ShiftRows an identity, so AESE with a zero round key computes SubWord.
    // Word rotation/Rcon complete Algorithm 2. Only public widths, offsets and
    // Rcon affect control flow. No calls, stack access or callee-saved vector
    // registers; scratch GPRs/vectors and NZCV are cleared before return.
    // This does not erase caller copies, spills or physical observations.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_AES_EXPANSION_SECRET_BEGIN",
            "mov x9, #0",
            "movi v1.16b, #0",
            "2:",
            "ldr w12, [{key}, x9]",
            "str w12, [{schedule}, x9]",
            "add x9, x9, #4",
            "cmp x9, #{key_bytes}",
            "b.ne 2b",
            "mov x10, #0",
            "mov w11, #1",
            "3:",
            "sub x14, x9, #4",
            "ldr w12, [{schedule}, x14]",
            "cbz x10, 4f",
            "mov x14, #{key_bytes}",
            "cmp x14, #32",
            "b.ne 6f",
            "cmp x10, #16",
            "b.ne 6f",
            "4:",
            "dup v0.4s, w12",
            "aese v0.16b, v1.16b",
            "umov w12, v0.s[0]",
            "cbnz x10, 6f",
            "ror w12, w12, #8",
            "eor w12, w12, w11",
            // Public Rcon recurrence, without a secret-dependent branch.
            "lsl w14, w11, #1",
            "tbz w11, #7, 5f",
            "mov w11, #0x1b",
            "eor w14, w14, w11",
            "5:",
            "and w11, w14, #0xff",
            "6:",
            "sub x14, x9, #{key_bytes}",
            "ldr w13, [{schedule}, x14]",
            "eor w12, w12, w13",
            "str w12, [{schedule}, x9]",
            "add x9, x9, #4",
            "add x10, x10, #4",
            "cmp x10, #{key_bytes}",
            "b.ne 7f",
            "mov x10, #0",
            "7:",
            "cmp x9, #{schedule_bytes}",
            "b.ne 3b",
            "// BRYNJA_AES_EXPANSION_REGISTER_ERASE",
            "movi v0.16b, #0",
            "movi v1.16b, #0",
            "mov x9, #0",
            "mov x10, #0",
            "mov x11, #0",
            "mov x12, #0",
            "mov x13, #0",
            "mov x14, #0",
            "msr nzcv, xzr",
            "// BRYNJA_AES_EXPANSION_SECRET_END",
            key = in(reg) key.as_ptr(),
            schedule = in(reg) schedule.as_mut_ptr(),
            key_bytes = const K,
            schedule_bytes = const S,
            out("x9") _, out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _,
            out("v0") _, out("v1") _,
            options(nostack),
        );
    }
}
