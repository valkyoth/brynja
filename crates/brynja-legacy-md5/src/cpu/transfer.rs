//! Transfers between clearing owners without Rust-side secret words.
#![allow(unsafe_code)]
use super::{Md5BackendError, scratch::Scratch};

pub(crate) fn pack_state(
    s: &mut Scratch,
    state: &[u8; 16],
    lane: usize,
) -> Result<(), Md5BackendError> {
    if lane >= 8 {
        return Err(Md5BackendError::Quarantined);
    }
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: Four input words and four packed rows are live/disjoint, lane < 8.
    unsafe {
        transpose::<4, true>(s.initial.as_mut_ptr().cast(), state.as_ptr(), lane);
    }
    #[cfg(any(
        miri,
        kani,
        not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        ))
    ))]
    for (row, bytes) in s.initial.iter_mut().zip(state.as_chunks::<4>().0) {
        row.as_chunks_mut::<4>()
            .0
            .get_mut(lane)
            .ok_or(Md5BackendError::Quarantined)?
            .copy_from_slice(bytes);
    }
    Ok(())
}

pub(crate) fn pack_block(
    s: &mut Scratch,
    block: &[u8; 64],
    lane: usize,
) -> Result<(), Md5BackendError> {
    if lane >= 8 {
        return Err(Md5BackendError::Quarantined);
    }
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: Sixteen input words and packed rows are live/disjoint, lane < 8.
    unsafe {
        transpose::<16, true>(s.words.as_mut_ptr().cast(), block.as_ptr(), lane);
    }
    #[cfg(any(
        miri,
        kani,
        not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        ))
    ))]
    for (row, bytes) in s.words.iter_mut().zip(block.as_chunks::<4>().0) {
        row.as_chunks_mut::<4>()
            .0
            .get_mut(lane)
            .ok_or(Md5BackendError::Quarantined)?
            .copy_from_slice(bytes);
    }
    Ok(())
}

pub(crate) fn commit_state(
    s: &Scratch,
    state: &mut [u8; 16],
    lane: usize,
) -> Result<(), Md5BackendError> {
    if lane >= 8 {
        return Err(Md5BackendError::Quarantined);
    }
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: Four packed rows and the exclusive state are disjoint, lane < 8.
    unsafe {
        transpose::<4, false>(state.as_mut_ptr(), s.initial.as_ptr().cast(), lane);
    }
    #[cfg(any(
        miri,
        kani,
        not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        ))
    ))]
    for (bytes, row) in state.as_chunks_mut::<4>().0.iter_mut().zip(&s.initial) {
        bytes.copy_from_slice(
            row.as_chunks::<4>()
                .0
                .get(lane)
                .ok_or(Md5BackendError::Quarantined)?,
        );
    }
    Ok(())
}

pub(crate) fn advance(s: &mut Scratch) {
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: Distinct 128-byte regions in one exclusive owner. This fixed
    // copy specialization preserves all eight lanes and never reads beyond them.
    unsafe {
        transpose::<32, true>(s.initial.as_mut_ptr().cast(), s.work.as_ptr().cast(), 0);
    }
    #[cfg(any(
        miri,
        kani,
        not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        ))
    ))]
    for (dst, src) in s.initial.iter_mut().zip(&s.work) {
        dst.copy_from_slice(src);
    }
}

/// # Safety
/// WORDS=4/16 transfers one lane, lane<8: the packed region is WORDS*32 bytes
/// and contiguous region WORDS*4 bytes. WORDS=32, PACK=true copies 128 bytes;
/// lane must be zero. Buffers must be live, disjoint; unaligned accesses allowed.
#[cfg(all(
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
#[inline(never)]
pub(super) unsafe extern "C" fn transpose<const WORDS: usize, const PACK: bool>(
    destination: *mut u8,
    source: *const u8,
    lane: usize,
) {
    const {
        assert!(WORDS == 4 || WORDS == 16 || (WORDS == 32 && PACK));
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Public word counter stays below its fixed domain. All four-byte
    // accesses fit their layout and lane. Only EAX contains secret data; it and
    // public offsets/counter are erased. No stack, call, SIMD or Rust result.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_TRANSFER_BEGIN",
            "xor r8d, r8d",
            "2:",
            "imul rdx, r8, {source_stride}",
            "imul r9, {lane}, {source_lane}",
            "add rdx, r9",
            "mov eax, [{source} + rdx]",
            "imul rdx, r8, {destination_stride}",
            "imul r9, {lane}, {destination_lane}",
            "add rdx, r9",
            "mov [{destination} + rdx], eax",
            "inc r8",
            "cmp r8, {words}",
            "jne 2b",
            "# BRYNJA_TRANSFER_ERASE",
            "xor eax, eax", "xor edx, edx", "xor r8d, r8d", "xor r9d, r9d",
            "# BRYNJA_TRANSFER_END",
            destination = in(reg) destination, source = in(reg) source, lane = in(reg) lane,
            words = const WORDS,
            source_stride = const if PACK { 4 } else { 32 },
            source_lane = const if PACK { 0 } else { 4 },
            destination_stride = const if !PACK || WORDS == 32 { 4 } else { 32 },
            destination_lane = const if !PACK || WORDS == 32 { 0 } else { 4 },
            out("rax") _, out("rdx") _, out("r8") _, out("r9") _,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Same bounds; X4 alone carries secret bytes. X4-X7 and NZCV clear.
    // Only public offsets enter multiplication. No stack, X18, calls or SIMD.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_TRANSFER_BEGIN",
            "mov x6, xzr",
            "2:",
            "mov x5, {source_lane}",
            "mul x7, {lane}, x5",
            "add x7, x7, x6, lsl {source_shift}",
            "ldr w4, [{source}, x7]",
            "mov x5, {destination_lane}",
            "mul x7, {lane}, x5",
            "add x7, x7, x6, lsl {destination_shift}",
            "str w4, [{destination}, x7]",
            "add x6, x6, #1",
            "cmp x6, {words}",
            "b.ne 2b",
            "// BRYNJA_TRANSFER_ERASE",
            "mov x4, xzr", "mov x5, xzr", "mov x6, xzr", "mov x7, xzr",
            "cmp xzr, xzr",
            "// BRYNJA_TRANSFER_END",
            destination = in(reg) destination, source = in(reg) source, lane = in(reg) lane,
            words = const WORDS,
            source_shift = const if PACK { 2 } else { 5 },
            source_lane = const if PACK { 0 } else { 4 },
            destination_shift = const if !PACK || WORDS == 32 { 2 } else { 5 },
            destination_lane = const if !PACK || WORDS == 32 { 0 } else { 4 },
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            options(nostack),
        );
    }
}

#[cfg(test)]
#[path = "transfer/tests.rs"]
mod tests;
