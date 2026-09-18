//! Opaque Keccak lane transposition; no secret word crosses the Rust boundary.
#![allow(unsafe_code)]

use super::Workspace;

pub(super) fn pack_bytes(s: &mut Workspace, states: &[[u8; 200]; 4], width: usize) {
    // SAFETY: Disjoint fixed arrays cover 25 words in four lanes. Supported
    // native targets are little-endian, matching canonical Keccak byte order.
    unsafe {
        transpose::<true>(
            s.state.as_mut_ptr().cast(),
            states.as_ptr().cast(),
            width.min(4),
        );
    }
}

pub(super) fn pack(s: &mut Workspace, states: &[[u64; 25]; 4], width: usize) {
    // SAFETY: Same fixed disjoint layout; no typed word is loaded in Rust.
    unsafe {
        transpose::<true>(
            s.state.as_mut_ptr().cast(),
            states.as_ptr().cast(),
            width.min(4),
        );
    }
}

pub(super) fn commit_bytes(s: &Workspace, states: &mut [[u8; 200]; 4], width: usize) {
    // SAFETY: Fixed disjoint arrays; only active lanes are committed. Native
    // and canonical Keccak byte order agree on both supported architectures.
    unsafe {
        transpose::<false>(
            states.as_mut_ptr().cast(),
            s.state.as_ptr().cast(),
            width.min(4),
        );
    }
}

pub(super) fn commit(s: &Workspace, states: &mut [[u64; 25]; 4], width: usize) {
    // SAFETY: Same bounds with native words. No secret value is returned.
    unsafe {
        transpose::<false>(
            states.as_mut_ptr().cast(),
            s.state.as_ptr().cast(),
            width.min(4),
        );
    }
}

/// # Safety
/// Width <= 4. Both nonoverlapping buffers are live for 800 bytes. The packed
/// layout contains 25 rows of 32 bytes; unpacked layout is four 200-byte states.
/// Only active lanes are accessed. Unaligned addresses are permitted.
#[inline(never)]
pub(super) unsafe extern "C" fn transpose<const PACK: bool>(
    destination: *mut u8,
    source: *const u8,
    width: usize,
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Public row/lane loops stay below 25/width; each eight-byte access
    // fits the stated 800-byte layouts. RAX alone holds secret bytes, erased
    // before return along with counters/offsets. No stack, calls, SIMD or Rust
    // secret outputs. Early clobbers cannot overlap the input pointers.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_TRANSFER_BEGIN",
            "xor r8d, r8d",
            "test {width}, {width}",
            "jz 4f",
            "2:",
            "xor ecx, ecx",
            "3:",
            "imul rdx, r8, {source_word}",
            "imul r9, rcx, {source_lane}",
            "add rdx, r9",
            "mov rax, [{source} + rdx]",
            "imul rdx, r8, {destination_word}",
            "imul r9, rcx, {destination_lane}",
            "add rdx, r9",
            "mov [{destination} + rdx], rax",
            "inc rcx",
            "cmp rcx, {width}",
            "jne 3b",
            "inc r8",
            "cmp r8, 25",
            "jne 2b",
            "4:",
            "# BRYNJA_TRANSFER_ERASE",
            "xor eax, eax", "xor ecx, ecx", "xor edx, edx",
            "xor r8d, r8d", "xor r9d, r9d",
            "# BRYNJA_TRANSFER_END",
            destination = in(reg) destination, source = in(reg) source,
            width = in(reg) width,
            source_word = const if PACK { 8 } else { 32 },
            source_lane = const if PACK { 200 } else { 8 },
            destination_word = const if PACK { 32 } else { 8 },
            destination_lane = const if PACK { 8 } else { 200 },
            out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Same fixed bounds. Only X4 contains secret bytes; all working
    // registers and NZCV are erased before return. Multiplications depend only
    // on public lane indices. No SIMD, stack, X18, calls or Rust secret results.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_TRANSFER_BEGIN",
            "mov x6, xzr",
            "cbz {width}, 4f",
            "2:",
            "mov x5, xzr",
            "3:",
            "mov x7, {source_lane}",
            "mul x7, x5, x7",
            "add x7, x7, x6, lsl {source_word_shift}",
            "ldr x4, [{source}, x7]",
            "mov x7, {destination_lane}",
            "mul x7, x5, x7",
            "add x7, x7, x6, lsl {destination_word_shift}",
            "str x4, [{destination}, x7]",
            "add x5, x5, #1",
            "cmp x5, {width}",
            "b.ne 3b",
            "add x6, x6, #1",
            "cmp x6, #25",
            "b.ne 2b",
            "4:",
            "// BRYNJA_TRANSFER_ERASE",
            "mov x4, xzr", "mov x5, xzr", "mov x6, xzr", "mov x7, xzr",
            "cmp xzr, xzr",
            "// BRYNJA_TRANSFER_END",
            destination = in(reg) destination, source = in(reg) source,
            width = in(reg) width,
            source_word_shift = const if PACK { 3 } else { 5 },
            source_lane = const if PACK { 200 } else { 8 },
            destination_word_shift = const if PACK { 5 } else { 3 },
            destination_lane = const if PACK { 8 } else { 200 },
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            options(nostack),
        );
    }
}
