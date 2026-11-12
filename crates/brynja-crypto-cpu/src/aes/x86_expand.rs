//! AES-NI expansion, entered only through sealed admission or explicit test harnesses.
#![allow(unsafe_code)]

/// Writes the complete forward FIPS 197 schedule, including the original key.
///
/// # Safety
/// AES/SSE2 must remain available throughout execution on every eligible CPU.
/// Caller owns the input and output lifetime/clearing. This private kernel
/// does not authorize execution or supply a clearing key owner.
#[target_feature(enable = "aes,sse2")]
#[inline(never)]
pub(crate) unsafe fn expand<const K: usize, const S: usize>(key: &[u8; K], schedule: &mut [u8; S]) {
    const { assert!(matches!((K, S), (16, 176) | (24, 208) | (32, 240))) };
    // SAFETY: All accesses are unaligned 4-byte words. Copy offsets are
    // 0..K in steps of four; generated offsets are K..S. Prior-word and
    // prior-key-width reads stay within already initialized output. Typed
    // shared/mutable borrows are disjoint. Only public counters/key width
    // control branches. Secret words never leave this opaque, call-free,
    // stack-free asm boundary except in the caller's schedule. AESKEYGENASSIST
    // with a replicated word and zero immediate yields SubWord in lane zero;
    // ror 8 implements RotWord for its little-endian representation.
    // Scratch GPR/vector registers are cleared; upstream copies/spills are
    // not covered, and this is not physical-fault/side-channel qualification.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_AES_EXPANSION_SECRET_BEGIN",
            "xor eax, eax",
            "2:",
            "mov edx, dword ptr [{key} + rax]",
            "mov dword ptr [{schedule} + rax], edx",
            "add rax, 4",
            "cmp rax, {key_bytes}",
            "jne 2b",
            "xor r8d, r8d",
            "mov ecx, 1",
            "3:",
            "mov edx, dword ptr [{schedule} + rax - 4]",
            "test r8, r8",
            "jz 4f",
            "mov r10d, {key_bytes}",
            "cmp r10d, 32",
            "jne 6f",
            "cmp r8, 16",
            "jne 6f",
            "4:",
            "movd xmm0, edx",
            "pshufd xmm0, xmm0, 0",
            "aeskeygenassist xmm0, xmm0, 0",
            "movd edx, xmm0",
            "test r8, r8",
            "jnz 6f",
            "ror edx, 8",
            "xor edx, ecx",
            // Rcon is public; this carry branch is independent of the key.
            "add cl, cl",
            "jnc 6f",
            "xor cl, 0x1b",
            "6:",
            "mov r10, rax",
            "sub r10, {key_bytes}",
            "xor edx, dword ptr [{schedule} + r10]",
            "mov dword ptr [{schedule} + rax], edx",
            "add rax, 4",
            "add r8, 4",
            "cmp r8, {key_bytes}",
            "jne 7f",
            "xor r8d, r8d",
            "7:",
            "cmp rax, {schedule_bytes}",
            "jne 3b",
            "# BRYNJA_AES_EXPANSION_REGISTER_ERASE",
            "pxor xmm0, xmm0",
            "xor eax, eax",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor r8d, r8d",
            "xor r10d, r10d",
            "# BRYNJA_AES_EXPANSION_SECRET_END",
            key = in(reg) key.as_ptr(),
            schedule = in(reg) schedule.as_mut_ptr(),
            key_bytes = const K,
            schedule_bytes = const S,
            out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r10") _, out("xmm0") _,
            options(nostack),
        );
    }
}
