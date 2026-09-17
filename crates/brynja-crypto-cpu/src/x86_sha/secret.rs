//! SHA-224/256 secret compression in one spill-free assembly boundary.
#![allow(unsafe_code)]

/// Only the first 32 state bytes and first 64 input bytes belong to SHA-256.
/// All 704 scratch bytes are erased; caller buffers remain caller-owned.
///
/// # Safety
/// SHA/SSE2 support must hold on every CPU eligible to execute this call.
/// This does not establish that authority or erase pre-existing caller state.
#[target_feature(enable = "sha,sse2")]
#[inline(never)]
pub unsafe extern "C" fn compress(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut [u8; 704],
    constants: &[u32; 64],
) {
    // SAFETY: Fixed public byte offsets initialize schedule 0..64, expand it
    // through 256, and execute sixteen four-round groups. Recurrence offsets
    // -64/-60/-28/-8 are in the initialized prefix. Vector staging occupies
    // 640..672; caller state accesses stay in 0..32. Every vector load/store is
    // explicitly unaligned (constants have only u32 alignment). No SSE4/AVX
    // instruction, stack access, call, secret Rust output or secret branch is
    // present. All touched GPRs/XMM registers and arithmetic flags are cleared;
    // early clobbers prevent overlap with the four live input pointers.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_SECRET_BEGIN",
            "xor ecx, ecx",
            "2:",
            "mov eax, [{block} + rcx]",
            "bswap eax",
            "mov [{scratch} + rcx], eax",
            "add rcx, 4",
            "cmp rcx, 64",
            "jne 2b",
            "3:",
            "mov eax, [{scratch} + rcx - 60]",
            "mov r8d, eax",
            "mov r9d, eax",
            "ror eax, 7",
            "ror r8d, 18",
            "shr r9d, 3",
            "xor eax, r8d",
            "xor eax, r9d",
            "mov edx, [{scratch} + rcx - 8]",
            "mov r8d, edx",
            "mov r9d, edx",
            "ror edx, 17",
            "ror r8d, 19",
            "shr r9d, 10",
            "xor edx, r8d",
            "xor edx, r9d",
            "add eax, edx",
            "add eax, [{scratch} + rcx - 64]",
            "add eax, [{scratch} + rcx - 28]",
            "mov [{scratch} + rcx], eax",
            "add rcx, 4",
            "cmp rcx, 256",
            "jne 3b",
            // XMM1 = F,E,B,A; XMM2 = H,G,D,C, low lane first.
            "mov eax, [{state} + 20]",
            "bswap eax",
            "mov [{scratch} + 640], eax",
            "mov eax, [{state} + 16]",
            "bswap eax",
            "mov [{scratch} + 644], eax",
            "mov eax, [{state} + 4]",
            "bswap eax",
            "mov [{scratch} + 648], eax",
            "mov eax, [{state}]",
            "bswap eax",
            "mov [{scratch} + 652], eax",
            "mov eax, [{state} + 28]",
            "bswap eax",
            "mov [{scratch} + 656], eax",
            "mov eax, [{state} + 24]",
            "bswap eax",
            "mov [{scratch} + 660], eax",
            "mov eax, [{state} + 12]",
            "bswap eax",
            "mov [{scratch} + 664], eax",
            "mov eax, [{state} + 8]",
            "bswap eax",
            "mov [{scratch} + 668], eax",
            "movdqu xmm1, [{scratch} + 640]",
            "movdqu xmm2, [{scratch} + 656]",
            "xor ecx, ecx",
            "4:",
            "movdqu xmm0, [{scratch} + rcx]",
            "movdqu xmm3, [{constants} + rcx]",
            "paddd xmm0, xmm3",
            "sha256rnds2 xmm2, xmm1, xmm0",
            "pshufd xmm0, xmm0, 0x0e",
            "sha256rnds2 xmm1, xmm2, xmm0",
            "add rcx, 16",
            "cmp rcx, 256",
            "jne 4b",
            "movdqu [{scratch} + 640], xmm1",
            "movdqu [{scratch} + 656], xmm2",
            // Public byte offsets for A,B,C,D,E,F,G,H.
            "mov r10, 0x10140004181c080c",
            "xor ecx, ecx",
            "5:",
            "movzx r11d, r10b",
            "mov eax, [{state} + rcx]",
            "bswap eax",
            "add eax, [{scratch} + r11 + 640]",
            "bswap eax",
            "mov [{state} + rcx], eax",
            "shr r10, 8",
            "add rcx, 4",
            "cmp rcx, 32",
            "jne 5b",
            "xor eax, eax",
            "xor ecx, ecx",
            "6:",
            "mov [{scratch} + rcx], rax",
            "add rcx, 8",
            "cmp rcx, 704",
            "jne 6b",
            "# BRYNJA_REGISTER_ERASE",
            "pxor xmm0, xmm0", "pxor xmm1, xmm1",
            "pxor xmm2, xmm2", "pxor xmm3, xmm3",
            "xor eax, eax", "xor ecx, ecx", "xor edx, edx",
            "xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d", "xor r11d, r11d",
            "cmp eax, eax",
            "# BRYNJA_SECRET_END",
            state = in(reg) state.as_mut_ptr(),
            block = in(reg) block.as_ptr(),
            scratch = in(reg) scratch.as_mut_ptr(),
            constants = in(reg) constants.as_ptr(),
            out("rax") _, out("rcx") _, out("rdx") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            options(nostack),
        );
    }
}
