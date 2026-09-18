use brynja_crypto_cpu::hardened_execution::KeccakSession;
use brynja_keccak_session_cleanup::invoke;

#[cfg(target_arch = "x86_64")]
const WIDTH: usize = 256;
#[cfg(target_arch = "aarch64")]
const WIDTH: usize = 384;

// Rust 1.90 Arm debug write_volatile's alignment precondition computes
// popcount(align_of::<u8>()) in V0 (FMOV/CNT/UADDLV): the public constant 1.
// Everything else observed must be zero. This is deliberately an exact allowlist,
// not a heuristic that classifies all unmatched words as non-secret.
pub fn only_cleanup_metadata(vectors: &[u8]) -> bool {
    vectors.len() == WIDTH
        && vectors.iter().enumerate().all(|(index, byte)| {
            *byte == 0
                || (cfg!(all(target_arch = "aarch64", debug_assertions))
                    && index == 0
                    && *byte == 1)
        })
}

#[test]
fn exact_metadata_allowlist_rejects_other_bytes_and_widths() {
    let mut vectors = [0; WIDTH];
    assert!(only_cleanup_metadata(&vectors));
    assert!(!only_cleanup_metadata(&vectors[..WIDTH - 1]));
    for index in 0..WIDTH {
        for bit in 0..8 {
            vectors[index] = 1 << bit;
            let permitted =
                cfg!(all(target_arch = "aarch64", debug_assertions)) && index == 0 && bit == 0;
            assert_eq!(only_cleanup_metadata(&vectors), permitted);
        }
        vectors[index] = 0;
    }
}

// Snapshot selected volatile vector registers at the public session return.
// General registers contain public metadata/pointers and are not qualified here.
pub fn capture(session: &mut KeccakSession<'_>, state: &mut [u8; 200]) -> (u8, [u8; WIDTH]) {
    capture_with(invoke, session, state)
}

pub fn capture_with(
    function: extern "C" fn(&mut KeccakSession<'_>, &mut [u8; 200]) -> u8,
    session: &mut KeccakSession<'_>,
    state: &mut [u8; 200],
) -> (u8, [u8; WIDTH]) {
    let mut backing = [0xa5; WIDTH + 33];
    let snapshot = &mut backing[16..17 + WIDTH];
    snapshot.fill(0);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SysV C call with exact disjoint borrows. R12 is preserved; all
    // volatile clobbers declared. No Rust instruction intervenes in the snapshot.
    unsafe {
        core::arch::asm!(
            "pxor xmm0, xmm0",
            "pxor xmm1, xmm1",
            "pxor xmm2, xmm2",
            "pxor xmm3, xmm3",
            "pxor xmm4, xmm4",
            "pxor xmm5, xmm5",
            "pxor xmm6, xmm6",
            "pxor xmm7, xmm7",
            "pxor xmm8, xmm8",
            "pxor xmm9, xmm9",
            "pxor xmm10, xmm10",
            "pxor xmm11, xmm11",
            "pxor xmm12, xmm12",
            "pxor xmm13, xmm13",
            "pxor xmm14, xmm14",
            "pxor xmm15, xmm15",
            "call r13",
            "mov [r12], al",
            "movdqu [r12 + 1], xmm0",
            "movdqu [r12 + 17], xmm1",
            "movdqu [r12 + 33], xmm2",
            "movdqu [r12 + 49], xmm3",
            "movdqu [r12 + 65], xmm4",
            "movdqu [r12 + 81], xmm5",
            "movdqu [r12 + 97], xmm6",
            "movdqu [r12 + 113], xmm7",
            "movdqu [r12 + 129], xmm8",
            "movdqu [r12 + 145], xmm9",
            "movdqu [r12 + 161], xmm10",
            "movdqu [r12 + 177], xmm11",
            "movdqu [r12 + 193], xmm12",
            "movdqu [r12 + 209], xmm13",
            "movdqu [r12 + 225], xmm14",
            "movdqu [r12 + 241], xmm15",
            in("r13") function, in("rdi") session, in("rsi") state.as_mut_ptr(),
            in("r12") snapshot.as_mut_ptr(), clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 C call; X20 preserves the snapshot; X18 and D8..15
    // are untouched. Link/volatile clobbers declared and offsets fit exactly.
    unsafe {
        core::arch::asm!(
            "movi v0.16b, #0",
            "movi v1.16b, #0",
            "movi v2.16b, #0",
            "movi v3.16b, #0",
            "movi v4.16b, #0",
            "movi v5.16b, #0",
            "movi v6.16b, #0",
            "movi v7.16b, #0",
            "movi v16.16b, #0",
            "movi v17.16b, #0",
            "movi v18.16b, #0",
            "movi v19.16b, #0",
            "movi v20.16b, #0",
            "movi v21.16b, #0",
            "movi v22.16b, #0",
            "movi v23.16b, #0",
            "movi v24.16b, #0",
            "movi v25.16b, #0",
            "movi v26.16b, #0",
            "movi v27.16b, #0",
            "movi v28.16b, #0",
            "movi v29.16b, #0",
            "movi v30.16b, #0",
            "movi v31.16b, #0",
            "blr x21",
            "strb w0, [x20]",
            "stur q0, [x20, #1]",
            "stur q1, [x20, #17]",
            "stur q2, [x20, #33]",
            "stur q3, [x20, #49]",
            "stur q4, [x20, #65]",
            "stur q5, [x20, #81]",
            "stur q6, [x20, #97]",
            "stur q7, [x20, #113]",
            "stur q16, [x20, #129]",
            "stur q17, [x20, #145]",
            "stur q18, [x20, #161]",
            "stur q19, [x20, #177]",
            "stur q20, [x20, #193]",
            "stur q21, [x20, #209]",
            "stur q22, [x20, #225]",
            "stur q23, [x20, #241]",
            "add x9, x20, #257",
            "str q24, [x9, #0]",
            "str q25, [x9, #16]",
            "str q26, [x9, #32]",
            "str q27, [x9, #48]",
            "str q28, [x9, #64]",
            "str q29, [x9, #80]",
            "str q30, [x9, #96]",
            "str q31, [x9, #112]",
            in("x21") function, in("x0") session, in("x1") state.as_mut_ptr(),
            in("x20") snapshot.as_mut_ptr(), clobber_abi("C"),
        );
    }
    let status = snapshot[0];
    let mut vectors = [0; WIDTH];
    vectors.copy_from_slice(&snapshot[1..]);
    assert_eq!(&backing[..16], &[0xa5; 16]);
    assert_eq!(&backing[WIDTH + 17..], &[0xa5; 16]);
    (status, vectors)
}

/// Positive residue control: deliberately dirty one volatile vector after the call.
#[inline(never)]
pub extern "C" fn poisoned(session: &mut KeccakSession<'_>, state: &mut [u8; 200]) -> u8 {
    let status = invoke(session, state);
    // SAFETY: Only a constant public marker in a declared volatile register.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("pcmpeqd xmm0, xmm0", out("xmm0") _, options(nomem, nostack));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("movi v0.16b, #255", out("v0") _, options(nomem, nostack));
    }
    status
}

/// Regression control: model a caller reloading actual result bytes after cleanup.
#[inline(never)]
pub extern "C" fn reloaded(session: &mut KeccakSession<'_>, state: &mut [u8; 200]) -> u8 {
    let status = invoke(session, state);
    // SAFETY: Read sixteen initialized result bytes from the live state borrow;
    // unaligned loads are supported and the volatile vector clobber is declared.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("movdqu xmm0, [{state}]", state = in(reg) state.as_ptr(), out("xmm0") _, options(readonly, nostack));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("ldr q0, [{state}]", state = in(reg) state.as_ptr(), out("v0") _, options(readonly, nostack));
    }
    status
}
