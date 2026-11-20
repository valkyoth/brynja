//! Experimental two-guard tentative write, NOT a protected publication API.

/// Whether this build has the opaque x86-64 candidate, NOT qualification.
pub const fn uses_guarded_copy_candidate() -> bool {
    cfg!(all(target_arch = "x86_64", not(any(miri, kani))))
}

/// Check both 32-byte candidate receipts and conditionally copy sixteen bytes.
///
/// Experimental and unsupported. On normal execution invalid receipts leave
/// `output` unchanged and set `report` to zero; exact success receipts copy
/// `proposed` and set the diagnostic report to 0xa5. The report is NOT release
/// authority: its corruption cannot be allowed to bypass a caller's guards.
///
/// This does not construct/refresh receipts, bind them to this data/operation,
/// check lifecycle state, perform destination readback, or restore old bytes.
/// Valid but stale/forged receipts can copy ANY proposed block. No AES correctness,
/// instruction-fault, constant-time, physical atomicity or C1/DC1 claim is made.
/// All arguments and report need caller-owned clearing storage. Inputs may
/// overlap each other; safe mutable borrows make output/report disjoint.
///
/// Only x86-64 outside Miri/Kani currently uses the opaque candidate. Elsewhere
/// the implementation is an ordinary functional model, never platform admission.
#[inline(never)]
pub fn tentative_copy_16(
    output: &mut [u8; 16],
    proposed: &[u8; 16],
    forward: &[u8; 32],
    reverse: &[u8; 32],
    report: &mut u8,
) {
    #[cfg(all(target_arch = "x86_64", not(any(miri, kani))))]
    // SAFETY: Fixed arrays prove the lengths below; exclusive output/report
    // borrows prohibit overlap with each other or the readable source regions.
    unsafe {
        opaque(
            output.as_mut_ptr(),
            proposed.as_ptr(),
            forward.as_ptr(),
            reverse.as_ptr(),
            report,
        );
    }
    #[cfg(not(all(target_arch = "x86_64", not(any(miri, kani)))))]
    model(output, proposed, forward, reverse, report);
}

#[cfg(any(test, not(all(target_arch = "x86_64", not(any(miri, kani))))))]
fn model(
    output: &mut [u8; 16],
    proposed: &[u8; 16],
    forward: &[u8; 32],
    reverse: &[u8; 32],
    report: &mut u8,
) {
    let mut difference = 0u8;
    let mut agreement = 0xffu8;
    *report = 0;
    for (byte, code) in forward.iter().zip([0xa5, 0x3c].into_iter().cycle()) {
        difference |= byte ^ code;
    }
    for (byte, code) in reverse.iter().rev().zip([0xc3, 0x5a].into_iter().cycle()) {
        agreement &= !(byte ^ code);
    }
    if difference != 0 {
        return;
    }
    if agreement != 0xff {
        return;
    }
    output.copy_from_slice(proposed);
    *report = 0xa5;
}

/// # Safety
/// output/proposed each cover sixteen bytes, forward/reverse thirty-two, and
/// report one byte. output/report are writable and mutually disjoint from all
/// live input ranges. Unaligned ranges are supported; inputs may alias.
#[cfg(all(target_arch = "x86_64", not(any(miri, kani))))]
#[inline(never)]
unsafe extern "C" fn opaque(
    output: *mut u8,
    proposed: *const u8,
    forward: *const u8,
    reverse: *const u8,
    report: *mut u8,
) {
    // SAFETY: Public loops visit 0,2,...30 and 30,28,...0 with 2-byte loads;
    // MOVDQU accesses exactly sixteen bytes. Baseline x86-64 includes SSE2.
    // Fixed pointer registers are inputs only; all working registers are early
    // clobbers. No stack use/calls in asm; flags are not claimed preserved.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_FAULT_GUARDED_COPY_BEGIN",
            "mov byte ptr [r8], 0",
            "xor eax, eax", "xor r9d, r9d",
            "2:",
            "movzx r10d, word ptr [rdx + r9]",
            "xor r10d, 0x3ca5", "or eax, r10d",
            "add r9d, 2", "cmp r9d, 32", "jb 2b",
            "mov r11d, 65535", "mov r9d, 32",
            "3:", "sub r9d, 2",
            "movzx r10d, word ptr [rcx + r9]",
            "xor r10d, 0xc35a", "not r10d", "and r11d, r10d",
            "test r9d, r9d", "jnz 3b",
            "# BRYNJA_FAULT_GUARD_FIRST",
            "test eax, eax", "jnz 4f",
            "# BRYNJA_FAULT_GUARD_SECOND",
            "cmp r11d, 65535", "jne 4f",
            "# BRYNJA_FAULT_TENTATIVE_COPY",
            "movdqu xmm0, xmmword ptr [rsi]",
            "movdqu xmmword ptr [rdi], xmm0",
            "mov byte ptr [r8], 0xa5",
            "4:",
            "pxor xmm0, xmm0", "xor eax, eax", "xor r9d, r9d",
            "xor r10d, r10d", "xor r11d, r11d",
            "# BRYNJA_FAULT_GUARDED_COPY_END",
            in("rdi") output, in("rsi") proposed, in("rdx") forward,
            in("rcx") reverse, in("r8") report,
            out("rax") _, out("r9") _, out("r10") _, out("r11") _, out("xmm0") _, options(nostack),
        );
    }
}

#[cfg(test)]
mod tests;
