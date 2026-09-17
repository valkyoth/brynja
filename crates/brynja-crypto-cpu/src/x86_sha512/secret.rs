//! All secret loads, arithmetic, stores and cleanup inhabit one opaque block.
//!
//! The compiler sees pointers, fixed array bounds and discarded clobbers, not
//! the secret values. No call or stack access occurs inside the block. The
//! enclosing function may spill pointers or preserve caller registers; those
//! are NOT fresh copies of this block's secret intermediates.

#![allow(unsafe_code)]

use core::arch::asm;

/// Private compression boundary; callers retain ownership of input/state.
///
/// # Safety
/// SHA512, AVX2/AVX and OS YMM context support must hold throughout execution on
/// every CPU to which this thread can migrate. The four typed borrows provide
/// exact, initialized, non-aliasing writable state/scratch and readable input.
#[target_feature(enable = "sha512,avx2,avx")]
#[inline(never)]
pub unsafe extern "C" fn compress(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut [u8; 704],
    constants: &[u64; 80],
) {
    // SAFETY: Only fixed public loops address these four exact borrows:
    // input words 0..16; schedule 0..80; vector staging 640..704;
    // state 0..64; constants 0..80. The schedule recurrence starts at 16,
    // so its -16/-15/-7/-2 offsets never underflow. The rounds advance 32
    // bytes to exactly 640. All memory writes are to state or scratch.
    // No stack use, call, Rust value output or secret-dependent branch exists.
    // All seven touched integer registers and all three touched YMM registers
    // are declared clobbered and erased after the final output/scratch store.
    // This side-effecting assembly is intentionally NOT pure/nomem/readonly.
    unsafe {
        asm!(
            "# BRYNJA_SECRET_BEGIN",
            "xor ecx, ecx",
            "2:",
            "mov rax, [{block} + rcx]",
            "bswap rax",
            "mov [{scratch} + rcx], rax",
            "add rcx, 8",
            "cmp rcx, 128",
            "jne 2b",
            "3:",
            "mov rax, [{scratch} + rcx - 120]",
            "mov r8, rax",
            "mov r9, rax",
            "ror rax, 1",
            "ror r8, 8",
            "shr r9, 7",
            "xor rax, r8",
            "xor rax, r9",
            "mov rdx, [{scratch} + rcx - 16]",
            "mov r8, rdx",
            "mov r9, rdx",
            "ror rdx, 19",
            "ror r8, 61",
            "shr r9, 6",
            "xor rdx, r8",
            "xor rdx, r9",
            "add rax, rdx",
            "add rax, [{scratch} + rcx - 128]",
            "add rax, [{scratch} + rcx - 56]",
            "mov [{scratch} + rcx], rax",
            "add rcx, 8",
            "cmp rcx, 640",
            "jne 3b",
            // ABEF/CDGH lanes, least-significant first: F,E,B,A,H,G,D,C.
            "mov rax, [{state} + 40]",
            "bswap rax",
            "mov [{scratch} + 640], rax",
            "mov rax, [{state} + 32]",
            "bswap rax",
            "mov [{scratch} + 648], rax",
            "mov rax, [{state} + 8]",
            "bswap rax",
            "mov [{scratch} + 656], rax",
            "mov rax, [{state}]",
            "bswap rax",
            "mov [{scratch} + 664], rax",
            "mov rax, [{state} + 56]",
            "bswap rax",
            "mov [{scratch} + 672], rax",
            "mov rax, [{state} + 48]",
            "bswap rax",
            "mov [{scratch} + 680], rax",
            "mov rax, [{state} + 24]",
            "bswap rax",
            "mov [{scratch} + 688], rax",
            "mov rax, [{state} + 16]",
            "bswap rax",
            "mov [{scratch} + 696], rax",
            "vmovdqu ymm0, [{scratch} + 640]",
            "vmovdqu ymm1, [{scratch} + 672]",
            "xor ecx, ecx",
            "4:",
            "mov rax, [{scratch} + rcx]",
            "add rax, [{constants} + rcx]",
            "vmovq xmm2, rax",
            "mov rax, [{scratch} + rcx + 8]",
            "add rax, [{constants} + rcx + 8]",
            "vpinsrq xmm2, xmm2, rax, 1",
            "vsha512rnds2 ymm1, ymm0, xmm2",
            "mov rax, [{scratch} + rcx + 16]",
            "add rax, [{constants} + rcx + 16]",
            "vmovq xmm2, rax",
            "mov rax, [{scratch} + rcx + 24]",
            "add rax, [{constants} + rcx + 24]",
            "vpinsrq xmm2, xmm2, rax, 1",
            "vsha512rnds2 ymm0, ymm1, xmm2",
            "add rcx, 32",
            "cmp rcx, 640",
            "jne 4b",
            "vmovdqu [{scratch} + 640], ymm0",
            "vmovdqu [{scratch} + 672], ymm1",
            // Packed public lane offsets: 24,16,56,48,8,0,40,32.
            "mov r10, 0x2028000830381018",
            "xor ecx, ecx",
            "5:",
            "movzx r11d, r10b",
            "mov rax, [{state} + rcx]",
            "bswap rax",
            "add rax, [{scratch} + r11 + 640]",
            "bswap rax",
            "mov [{state} + rcx], rax",
            "shr r10, 8",
            "add rcx, 8",
            "cmp rcx, 64",
            "jne 5b",
            "xor eax, eax",
            "xor ecx, ecx",
            "6:",
            "mov [{scratch} + rcx], rax",
            "add rcx, 8",
            "cmp rcx, 704",
            "jne 6b",
            "# BRYNJA_REGISTER_ERASE",
            "vpxor ymm0, ymm0, ymm0",
            "vpxor ymm1, ymm1, ymm1",
            "vpxor ymm2, ymm2, ymm2",
            "xor eax, eax",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            // Unlike XOR's undefined AF, CMP fixes all arithmetic status flags.
            "cmp eax, eax",
            "# BRYNJA_SECRET_END",
            state = in(reg) state.as_mut_ptr(),
            block = in(reg) block.as_ptr(),
            scratch = in(reg) scratch.as_mut_ptr(),
            constants = in(reg) constants.as_ptr(),
            out("rax") _, out("rcx") _, out("rdx") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("ymm0") _, out("ymm1") _, out("ymm2") _,
            options(nostack),
        );
    }
}
