//! Opaque state/block transposition; no secret word crosses the Rust boundary.
#![allow(unsafe_code)]

use super::Workspace;

pub(super) fn pack_bytes(
    s: &mut Workspace,
    states: &[[u8; 32]; 8],
    blocks: &[[u8; 64]; 8],
    width: usize,
) {
    let width = width.min(8);
    // SAFETY: Typed arrays have exactly eight contiguous lanes. The private
    // caller validated width=4/8 and cleared inactive workspace capacity.
    unsafe {
        transpose::<8, true>(
            s.initial.as_mut_ptr().cast(),
            states.as_ptr().cast(),
            width,
            1,
        );
        transpose::<16, true>(
            s.schedule.as_mut_ptr().cast(),
            blocks.as_ptr().cast(),
            width,
            1,
        );
    }
}

pub(super) fn pack(
    s: &mut Workspace,
    states: &[[u32; 8]; 8],
    blocks: &[[u8; 64]; 8],
    width: usize,
) {
    let width = width.min(8);
    // SAFETY: As above. Native words and packed words share little-endian order;
    // only canonical block bytes need reversal. No typed word is loaded in Rust.
    unsafe {
        transpose::<8, true>(
            s.initial.as_mut_ptr().cast(),
            states.as_ptr().cast(),
            width,
            0,
        );
        transpose::<16, true>(
            s.schedule.as_mut_ptr().cast(),
            blocks.as_ptr().cast(),
            width,
            1,
        );
    }
}

pub(super) fn commit_bytes(s: &Workspace, states: &mut [[u8; 32]; 8], width: usize) {
    // SAFETY: Disjoint live fixed arrays, eight words per lane; clipping width
    // retains the former iterator's take(width) behavior for private callers.
    unsafe {
        transpose::<8, false>(
            states.as_mut_ptr().cast(),
            s.work.as_ptr().cast(),
            width.min(8),
            1,
        );
    }
}

pub(super) fn commit(s: &Workspace, states: &mut [[u32; 8]; 8], width: usize) {
    // SAFETY: As above, with native-endian caller words. Only pointers escape.
    unsafe {
        transpose::<8, false>(
            states.as_mut_ptr().cast(),
            s.work.as_ptr().cast(),
            width.min(8),
            0,
        );
    }
}

/// # Safety
/// Width <= 8. Both nonoverlapping buffers are live for their fixed layout:
/// packed WORDS rows of 32 bytes; unpacked eight lanes of WORDS * 4 bytes.
/// WORDS is 8 or 16; only the first width lanes may be accessed. Swap is public.
#[inline(never)]
pub(super) unsafe extern "C" fn transpose<const WORDS: usize, const PACK: bool>(
    destination: *mut u8,
    source: *const u8,
    width: usize,
    swap: u32,
) {
    const {
        assert!(WORDS == 8 || WORDS == 16);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Each address is word*word_stride + lane*lane_stride. The public
    // counters stay below WORDS and width; the four-byte access fits exactly.
    // RAX is the only secret-bearing register and is erased before return.
    // All scratch registers and flags are cleared; no stack, calls, SIMD, or
    // secret Rust values occur. Early clobbers cannot overlap input pointers.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_TRANSFER_BEGIN",
            "xor r8d, r8d",
            "test {width}, {width}",
            "jz 5f",
            "2:",
            "xor ecx, ecx",
            "3:",
            "imul rdx, r8, {source_word}",
            "imul r9, rcx, {source_lane}",
            "add rdx, r9",
            "mov eax, [{source} + rdx]",
            "test {swap:e}, {swap:e}",
            "jz 4f",
            "bswap eax",
            "4:",
            "imul rdx, r8, {destination_word}",
            "imul r9, rcx, {destination_lane}",
            "add rdx, r9",
            "mov [{destination} + rdx], eax",
            "inc rcx",
            "cmp rcx, {width}",
            "jne 3b",
            "inc r8",
            "cmp r8, {words}",
            "jne 2b",
            "5:",
            "# BRYNJA_TRANSFER_ERASE",
            "xor eax, eax", "xor ecx, ecx", "xor edx, edx",
            "xor r8d, r8d", "xor r9d, r9d",
            "# BRYNJA_TRANSFER_END",
            destination = in(reg) destination, source = in(reg) source,
            width = in(reg) width, swap = in(reg) swap,
            words = const WORDS,
            source_word = const if PACK { 4 } else { 32 },
            source_lane = const if PACK { WORDS * 4 } else { 4 },
            destination_word = const if PACK { 32 } else { 4 },
            destination_lane = const if PACK { 4 } else { WORDS * 4 },
            out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Same fixed transposition bounds. W4 alone holds secret bytes and
    // is erased along with working counters/offsets and NZCV. No SIMD, stack,
    // reserved X18, call or Rust secret result is used. Unaligned memory works.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_TRANSFER_BEGIN",
            "mov x6, xzr",
            "cbz {width}, 5f",
            "2:",
            "mov x5, xzr",
            "3:",
            "lsl x7, x6, {source_word_shift}",
            "add x7, x7, x5, lsl {source_lane_shift}",
            "ldr w4, [{source}, x7]",
            "cbz {swap:w}, 4f",
            "rev w4, w4",
            "4:",
            "lsl x7, x6, {destination_word_shift}",
            "add x7, x7, x5, lsl {destination_lane_shift}",
            "str w4, [{destination}, x7]",
            "add x5, x5, #1",
            "cmp x5, {width}",
            "b.ne 3b",
            "add x6, x6, #1",
            "cmp x6, {words}",
            "b.ne 2b",
            "5:",
            "// BRYNJA_TRANSFER_ERASE",
            "mov x4, xzr", "mov x5, xzr", "mov x6, xzr", "mov x7, xzr",
            "cmp xzr, xzr",
            "// BRYNJA_TRANSFER_END",
            destination = in(reg) destination, source = in(reg) source,
            width = in(reg) width, swap = in(reg) swap,
            words = const WORDS,
            source_word_shift = const if PACK { 2 } else { 5 },
            source_lane_shift = const if PACK { if WORDS == 8 { 5 } else { 6 } } else { 2 },
            destination_word_shift = const if PACK { 5 } else { 2 },
            destination_lane_shift = const if PACK { 2 } else { if WORDS == 8 { 5 } else { 6 } },
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            options(nostack),
        );
    }
}
