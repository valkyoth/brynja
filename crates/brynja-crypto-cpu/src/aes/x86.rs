//! Internal AES-NI block candidate; no feature detection or admission here.
#![allow(unsafe_code)]

/// Transforms one block using forward FIPS 197 round keys (11, 13 or 15).
/// Schedule and output remain caller-owned; no key expansion is performed.
///
/// # Safety
/// AES and SSE2 must be available on every CPU eligible to execute this call.
/// The caller must provide the schedule for the intended AES key. This private
/// primitive does not establish execution authority, quarantine or key ownership.
#[target_feature(enable = "aes,sse2")]
#[inline(never)]
pub(crate) unsafe fn transform<const N: usize>(
    state: &mut [u8; 16],
    schedule: &[[u8; 16]; N],
    inverse: bool,
) {
    const { assert!(matches!(N, 11 | 13 | 15)) };
    // SAFETY: The typed schedule has exactly N complete round keys. All loads
    // are unaligned: offsets visit 0,16,...,(N-1)*16 only. One 16-byte state
    // load/store is in bounds and disjoint from the immutable schedule. AESDEC
    // needs inverse-mixed middle round keys, not inverse-mixed endpoint keys.
    // Public direction/offsets are the only branch inputs. This opaque boundary
    // makes no calls or stack accesses; it clears its working XMM registers
    // before returning. This is not erasure of caller copies or physical-fault
    // protection. Early clobbers exclude the live pointers and last offset.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_AES_SECRET_BEGIN",
            "movdqu xmm0, [{state}]",
            "test {inverse}, {inverse}",
            "jnz 4f",
            "movdqu xmm1, [{schedule}]",
            "pxor xmm0, xmm1",
            "mov rax, 16",
            "2:",
            "movdqu xmm1, [{schedule} + rax]",
            "aesenc xmm0, xmm1",
            "add rax, 16",
            "cmp rax, {last}",
            "jne 2b",
            "movdqu xmm1, [{schedule} + rax]",
            "aesenclast xmm0, xmm1",
            "jmp 6f",
            "4:",
            "mov rax, {last}",
            "movdqu xmm1, [{schedule} + rax]",
            "pxor xmm0, xmm1",
            "5:",
            "sub rax, 16",
            "movdqu xmm1, [{schedule} + rax]",
            "aesimc xmm1, xmm1",
            "aesdec xmm0, xmm1",
            "cmp rax, 16",
            "jne 5b",
            "movdqu xmm1, [{schedule}]",
            "aesdeclast xmm0, xmm1",
            "6:",
            "movdqu [{state}], xmm0",
            "# BRYNJA_AES_REGISTER_ERASE",
            "pxor xmm0, xmm0",
            "pxor xmm1, xmm1",
            "xor eax, eax",
            "# BRYNJA_AES_SECRET_END",
            state = in(reg) state.as_mut_ptr(),
            schedule = in(reg) schedule.as_ptr(),
            last = in(reg) schedule.len().wrapping_sub(1).wrapping_mul(16),
            inverse = in(reg) usize::from(inverse),
            out("rax") _, out("xmm0") _, out("xmm1") _,
            options(nostack),
        );
    }
}
