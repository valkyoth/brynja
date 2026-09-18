//! Scalar normal-return boundary; no crypto or SIMD instruction prerequisite.
#![allow(unsafe_code)]

const SHIFTS: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

pub(super) fn compress(state: &mut [u8; 16], block: &[u8; 64]) {
    // SAFETY: Exclusive state, disjoint live block and fixed public tables.
    // This module is only built for baseline x86-64/little-endian AArch64.
    unsafe { scalar(state, block, &super::CONSTANTS, &SHIFTS) };
}

/// # Safety
/// All four fixed operands must be live and disjoint; tables must contain the
/// RFC 1321 constants and shifts. Byte operands may be unaligned. Only baseline
/// x86-64 or little-endian AArch64 is supported; no crypto/SIMD feature is needed.
#[inline(never)]
pub(super) unsafe extern "C" fn scalar(
    state: &mut [u8; 16],
    block: &[u8; 64],
    constants: &[u32; 64],
    shifts: &[u32; 16],
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Round is public and bounded by 64, message indices masked to 16
    // words and shift indices to 16 entries. All secret arithmetic and accesses
    // stay inside this stack/call-free block. Feed-forward precedes erasure.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_SCALAR_BEGIN",
            "mov r8d, [{state}]", "mov r9d, [{state} + 4]",
            "mov r10d, [{state} + 8]", "mov r11d, [{state} + 12]",
            "xor r14d, r14d",
            "2:",
            "cmp r14d, 16", "jae 3f",
            "mov eax, r9d", "and eax, r10d",
            "mov ecx, r9d", "not ecx", "and ecx, r11d", "or eax, ecx",
            "mov edx, r14d", "jmp 6f",
            "3:", "cmp r14d, 32", "jae 4f",
            "mov eax, r9d", "and eax, r11d",
            "mov ecx, r11d", "not ecx", "and ecx, r10d", "or eax, ecx",
            "lea edx, [r14 + r14 * 4 + 1]", "jmp 6f",
            "4:", "cmp r14d, 48", "jae 5f",
            "mov eax, r9d", "xor eax, r10d", "xor eax, r11d",
            "lea edx, [r14 + r14 * 2 + 5]", "jmp 6f",
            "5:",
            "mov eax, r11d", "not eax", "or eax, r9d", "xor eax, r10d",
            "imul edx, r14d, 7",
            "6:",
            "and edx, 15",
            "add r8d, eax", "add r8d, [{block} + rdx * 4]",
            "add r8d, [{constants} + r14 * 4]",
            "mov ecx, r14d", "shr ecx, 2", "and ecx, 12",
            "mov edx, r14d", "and edx, 3", "or ecx, edx",
            "mov ecx, [{shifts} + rcx * 4]", "rol r8d, cl", "add r8d, r9d",
            "mov eax, r8d", "mov r8d, r11d", "mov r11d, r10d",
            "mov r10d, r9d", "mov r9d, eax",
            "inc r14d", "cmp r14d, 64", "jne 2b",
            "add [{state}], r8d", "add [{state} + 4], r9d",
            "add [{state} + 8], r10d", "add [{state} + 12], r11d",
            "# BRYNJA_SCALAR_ERASE",
            "xor eax, eax", "xor ecx, ecx", "xor edx, edx",
            "xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d", "xor r11d, r11d",
            "xor r14d, r14d",
            "# BRYNJA_SCALAR_END",
            state = in(reg) state.as_mut_ptr(), block = in(reg) block.as_ptr(),
            constants = in(reg) constants.as_ptr(), shifts = in(reg) shifts.as_ptr(),
            out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
            out("r10") _, out("r11") _, out("r14") _,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Same bounds and table contract. W4-W11 hold all scalar working
    // values. The opaque block never touches stack, X18 or vector registers.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_SCALAR_BEGIN",
            "ldr w4, [{state}]", "ldr w5, [{state}, #4]",
            "ldr w6, [{state}, #8]", "ldr w7, [{state}, #12]",
            "mov w10, wzr",
            "2:",
            "cmp w10, #16", "b.hs 3f",
            "and w8, w5, w6", "bic w11, w7, w5", "orr w8, w8, w11",
            "mov w9, w10", "b 6f",
            "3:", "cmp w10, #32", "b.hs 4f",
            "and w8, w5, w7", "bic w11, w6, w7", "orr w8, w8, w11",
            "add w9, w10, w10, lsl #2", "add w9, w9, #1", "b 6f",
            "4:", "cmp w10, #48", "b.hs 5f",
            "eor w8, w5, w6", "eor w8, w8, w7",
            "add w9, w10, w10, lsl #1", "add w9, w9, #5", "b 6f",
            "5:",
            "orn w8, w5, w7", "eor w8, w8, w6",
            "lsl w9, w10, #3", "sub w9, w9, w10",
            "6:",
            "and w9, w9, #15", "add w4, w4, w8",
            "ldr w11, [{block}, w9, uxtw #2]", "add w4, w4, w11",
            "ldr w11, [{constants}, w10, uxtw #2]", "add w4, w4, w11",
            "lsr w9, w10, #2", "and w9, w9, #12",
            "and w11, w10, #3", "orr w9, w9, w11",
            "ldr w9, [{shifts}, w9, uxtw #2]", "neg w9, w9", "ror w4, w4, w9",
            "add w4, w4, w5",
            "mov w8, w4", "mov w4, w7", "mov w7, w6", "mov w6, w5", "mov w5, w8",
            "add w10, w10, #1", "cmp w10, #64", "b.ne 2b",
            "ldr w8, [{state}]", "add w4, w4, w8", "str w4, [{state}]",
            "ldr w8, [{state}, #4]", "add w5, w5, w8", "str w5, [{state}, #4]",
            "ldr w8, [{state}, #8]", "add w6, w6, w8", "str w6, [{state}, #8]",
            "ldr w8, [{state}, #12]", "add w7, w7, w8", "str w7, [{state}, #12]",
            "// BRYNJA_SCALAR_ERASE",
            "mov x4, xzr", "mov x5, xzr", "mov x6, xzr", "mov x7, xzr",
            "mov x8, xzr", "mov x9, xzr", "mov x10, xzr", "mov x11, xzr",
            "cmp xzr, xzr",
            "// BRYNJA_SCALAR_END",
            state = in(reg) state.as_mut_ptr(), block = in(reg) block.as_ptr(),
            constants = in(reg) constants.as_ptr(), shifts = in(reg) shifts.as_ptr(),
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            options(nostack),
        );
    }
}
