//! Baseline scalar boundary: big-endian state/input, private native-endian scratch.
#![allow(unsafe_code)]

pub(super) fn compress(state: &mut [u8; 20], block: &[u8; 64], schedule: &mut [u8; 320]) {
    // SAFETY: Disjoint fixed live operands; no instruction extension is needed.
    unsafe { scalar(state, block, schedule) };
}

/// # Safety
/// Operands must be live, disjoint fixed arrays. Unaligned byte arrays are valid.
/// Only baseline x86-64/little-endian AArch64 is supported. The schedule is
/// overwritten completely before use and cleared before normal return.
#[inline(never)]
pub(super) unsafe extern "C" fn scalar(
    state: &mut [u8; 20],
    block: &[u8; 64],
    schedule: &mut [u8; 320],
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Public byte offsets are 0..64 for input and 0..320 for schedule.
    // Expansion begins at offset 64, so all four backward reads are in bounds.
    // Every secret load/round/store and erasure is in this stack/call-free block.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_SCALAR_BEGIN",
            "xor r14d, r14d",
            "2:", "mov edx, [{block} + r14]", "bswap edx",
            "mov [{schedule} + r14], edx", "add r14d, 4", "cmp r14d, 64", "jne 2b",
            "3:", "mov edx, [{schedule} + r14 - 12]",
            "xor edx, [{schedule} + r14 - 32]", "xor edx, [{schedule} + r14 - 56]",
            "xor edx, [{schedule} + r14 - 64]", "rol edx, 1",
            "mov [{schedule} + r14], edx", "add r14d, 4", "cmp r14d, 320", "jne 3b",
            "mov r8d, [{state}]", "bswap r8d",
            "mov r9d, [{state} + 4]", "bswap r9d",
            "mov r10d, [{state} + 8]", "bswap r10d",
            "mov r11d, [{state} + 12]", "bswap r11d",
            "mov eax, [{state} + 16]", "bswap eax",
            "xor r14d, r14d",
            "4:", "cmp r14d, 80", "jae 5f",
            "mov ecx, r9d", "and ecx, r10d",
            "mov edx, r9d", "not edx", "and edx, r11d", "xor ecx, edx",
            "add eax, 0x5a827999", "jmp 8f",
            "5:", "cmp r14d, 160", "jae 6f",
            "mov ecx, r9d", "xor ecx, r10d", "xor ecx, r11d",
            "add eax, 0x6ed9eba1", "jmp 8f",
            "6:", "cmp r14d, 240", "jae 7f",
            "mov ecx, r9d", "and ecx, r10d",
            "mov edx, r9d", "or edx, r10d", "and edx, r11d", "or ecx, edx",
            "add eax, 0x8f1bbcdc", "jmp 8f",
            "7:", "mov ecx, r9d", "xor ecx, r10d", "xor ecx, r11d",
            "add eax, 0xca62c1d6",
            "8:", "add eax, ecx", "mov edx, r8d", "rol edx, 5", "add eax, edx",
            "add eax, [{schedule} + r14]",
            "mov ecx, eax", "mov eax, r11d", "mov r11d, r10d",
            "mov r10d, r9d", "rol r10d, 30", "mov r9d, r8d", "mov r8d, ecx",
            "add r14d, 4", "cmp r14d, 320", "jne 4b",
            "mov edx, [{state}]", "bswap edx", "add r8d, edx", "bswap r8d", "mov [{state}], r8d",
            "mov edx, [{state} + 4]", "bswap edx", "add r9d, edx", "bswap r9d", "mov [{state} + 4], r9d",
            "mov edx, [{state} + 8]", "bswap edx", "add r10d, edx", "bswap r10d", "mov [{state} + 8], r10d",
            "mov edx, [{state} + 12]", "bswap edx", "add r11d, edx", "bswap r11d", "mov [{state} + 12], r11d",
            "mov edx, [{state} + 16]", "bswap edx", "add eax, edx", "bswap eax", "mov [{state} + 16], eax",
            "xor r14d, r14d",
            "9:", "mov dword ptr [{schedule} + r14], 0", "add r14d, 4", "cmp r14d, 320", "jne 9b",
            "# BRYNJA_SCALAR_ERASE",
            "xor eax, eax", "xor ecx, ecx", "xor edx, edx",
            "xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d", "xor r11d, r11d",
            "xor r14d, r14d",
            "# BRYNJA_SCALAR_END",
            state = in(reg) state.as_mut_ptr(), block = in(reg) block.as_ptr(),
            schedule = in(reg) schedule.as_mut_ptr(),
            out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
            out("r10") _, out("r11") _, out("r14") _,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Same fixed bounds; X12 holds only a schedule pointer. No stack,
    // vector registers or platform-reserved X18. All working registers cleared.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_SCALAR_BEGIN",
            "mov x11, xzr",
            "2:", "ldr w9, [{block}, x11]", "rev w9, w9",
            "str w9, [{schedule}, x11]", "add x11, x11, #4", "cmp x11, #64", "b.ne 2b",
            "3:", "add x12, {schedule}, x11",
            "ldur w9, [x12, #-12]", "ldur w10, [x12, #-32]", "eor w9, w9, w10",
            "ldur w10, [x12, #-56]", "eor w9, w9, w10",
            "ldur w10, [x12, #-64]", "eor w9, w9, w10", "ror w9, w9, #31",
            "str w9, [{schedule}, x11]", "add x11, x11, #4", "cmp x11, #320", "b.ne 3b",
            "ldr w4, [{state}]", "rev w4, w4",
            "ldr w5, [{state}, #4]", "rev w5, w5",
            "ldr w6, [{state}, #8]", "rev w6, w6",
            "ldr w7, [{state}, #12]", "rev w7, w7",
            "ldr w8, [{state}, #16]", "rev w8, w8",
            "mov x11, xzr",
            "4:", "cmp x11, #80", "b.hs 5f",
            "and w9, w5, w6", "bic w10, w7, w5", "eor w9, w9, w10",
            "movz w10, #0x7999", "movk w10, #0x5a82, lsl #16", "b 8f",
            "5:", "cmp x11, #160", "b.hs 6f",
            "eor w9, w5, w6", "eor w9, w9, w7",
            "movz w10, #0xeba1", "movk w10, #0x6ed9, lsl #16", "b 8f",
            "6:", "cmp x11, #240", "b.hs 7f",
            "and w9, w5, w6", "orr w10, w5, w6", "and w10, w10, w7", "orr w9, w9, w10",
            "movz w10, #0xbcdc", "movk w10, #0x8f1b, lsl #16", "b 8f",
            "7:", "eor w9, w5, w6", "eor w9, w9, w7",
            "movz w10, #0xc1d6", "movk w10, #0xca62, lsl #16",
            "8:", "add w8, w8, w9", "add w8, w8, w10",
            "ror w9, w4, #27", "add w8, w8, w9",
            "ldr w10, [{schedule}, x11]", "add w8, w8, w10",
            "mov w9, w8", "mov w8, w7", "mov w7, w6", "ror w6, w5, #2", "mov w5, w4", "mov w4, w9",
            "add x11, x11, #4", "cmp x11, #320", "b.ne 4b",
            "ldr w9, [{state}]", "rev w9, w9", "add w4, w4, w9", "rev w4, w4", "str w4, [{state}]",
            "ldr w9, [{state}, #4]", "rev w9, w9", "add w5, w5, w9", "rev w5, w5", "str w5, [{state}, #4]",
            "ldr w9, [{state}, #8]", "rev w9, w9", "add w6, w6, w9", "rev w6, w6", "str w6, [{state}, #8]",
            "ldr w9, [{state}, #12]", "rev w9, w9", "add w7, w7, w9", "rev w7, w7", "str w7, [{state}, #12]",
            "ldr w9, [{state}, #16]", "rev w9, w9", "add w8, w8, w9", "rev w8, w8", "str w8, [{state}, #16]",
            "mov x11, xzr",
            "9:", "str wzr, [{schedule}, x11]", "add x11, x11, #4", "cmp x11, #320", "b.ne 9b",
            "// BRYNJA_SCALAR_ERASE",
            "mov x4, xzr", "mov x5, xzr", "mov x6, xzr", "mov x7, xzr",
            "mov x8, xzr", "mov x9, xzr", "mov x10, xzr", "mov x11, xzr", "mov x12, xzr",
            "cmp xzr, xzr",
            "// BRYNJA_SCALAR_END",
            state = in(reg) state.as_mut_ptr(), block = in(reg) block.as_ptr(),
            schedule = in(reg) schedule.as_mut_ptr(),
            out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _,
            out("x9") _, out("x10") _, out("x11") _, out("x12") _,
            options(nostack),
        );
    }
}
