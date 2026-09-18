//! Linux diagnostic observers. No stale-stack reads or secret-value logging.
use brynja_caller_residue_audit::Probe;

#[cfg(target_arch = "x86_64")]
pub const SIZE: usize = 328;
#[cfg(target_arch = "aarch64")]
pub const SIZE: usize = 528;

pub fn has_marker(snapshot: &[u8], marker: u8) -> bool {
    snapshot.windows(8).any(|window| window == [marker; 8])
}

/// Capture caller-clobbered registers immediately after the wrapper returns.
/// Caller inputs, output destinations and snapshots are distinct live borrows.
pub fn capture(
    probe: Probe,
    input: &[u8; 256],
    output: &mut [u8; 64],
    length: usize,
) -> [u8; SIZE] {
    let mut storage = [0xa5; SIZE + 32];
    let snapshot = &mut storage[16..16 + SIZE];
    snapshot.fill(0);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SysV C function pointer with three arguments and exact live buffers.
    // R12/R13 are ABI-preserved. All volatile registers are declared clobbered.
    // Stack use is allowed, permitting compiler call alignment/red-zone handling.
    // Seed observed volatile registers, except public arguments, before the call;
    // the only instructions after return are fixed-bounds snapshot stores.
    unsafe {
        core::arch::asm!(
            "xor eax, eax", "xor ecx, ecx", "xor r8d, r8d", "xor r9d, r9d",
            "xor r10d, r10d", "xor r11d, r11d",
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
            "mov [r12 + 0], rax",
            "mov [r12 + 8], rcx",
            "mov [r12 + 16], rdx",
            "mov [r12 + 24], rsi",
            "mov [r12 + 32], rdi",
            "mov [r12 + 40], r8",
            "mov [r12 + 48], r9",
            "mov [r12 + 56], r10",
            "mov [r12 + 64], r11",
            "movdqu [r12 + 72], xmm0",
            "movdqu [r12 + 88], xmm1",
            "movdqu [r12 + 104], xmm2",
            "movdqu [r12 + 120], xmm3",
            "movdqu [r12 + 136], xmm4",
            "movdqu [r12 + 152], xmm5",
            "movdqu [r12 + 168], xmm6",
            "movdqu [r12 + 184], xmm7",
            "movdqu [r12 + 200], xmm8",
            "movdqu [r12 + 216], xmm9",
            "movdqu [r12 + 232], xmm10",
            "movdqu [r12 + 248], xmm11",
            "movdqu [r12 + 264], xmm12",
            "movdqu [r12 + 280], xmm13",
            "movdqu [r12 + 296], xmm14",
            "movdqu [r12 + 312], xmm15",
            in("rdi") input.as_ptr(), in("rsi") output.as_mut_ptr(), in("rdx") length,
            in("r12") snapshot.as_mut_ptr(), in("r13") probe,
            clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 C call, X21/X20 are preserved; X18 is platform-reserved
    // and not touched. Only volatile integer/vector registers are observed.
    // D8..D15 are not part of this snapshot. BLR's link register is clobbered.
    unsafe {
        core::arch::asm!(
            "mov x3, xzr",
            "mov x4, xzr",
            "mov x5, xzr",
            "mov x6, xzr",
            "mov x7, xzr",
            "mov x8, xzr",
            "mov x9, xzr",
            "mov x10, xzr",
            "mov x11, xzr",
            "mov x12, xzr",
            "mov x13, xzr",
            "mov x14, xzr",
            "mov x15, xzr",
            "mov x16, xzr",
            "mov x17, xzr",
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
            "stp x0, x1, [x20, #0]",
            "stp x2, x3, [x20, #16]",
            "stp x4, x5, [x20, #32]",
            "stp x6, x7, [x20, #48]",
            "stp x8, x9, [x20, #64]",
            "stp x10, x11, [x20, #80]",
            "stp x12, x13, [x20, #96]",
            "stp x14, x15, [x20, #112]",
            "stp x16, x17, [x20, #128]",
            "stp q0, q1, [x20, #144]",
            "stp q2, q3, [x20, #176]",
            "stp q4, q5, [x20, #208]",
            "stp q6, q7, [x20, #240]",
            "stp q16, q17, [x20, #272]",
            "stp q18, q19, [x20, #304]",
            "stp q20, q21, [x20, #336]",
            "stp q22, q23, [x20, #368]",
            "stp q24, q25, [x20, #400]",
            "stp q26, q27, [x20, #432]",
            "stp q28, q29, [x20, #464]",
            "stp q30, q31, [x20, #496]",
            in("x0") input.as_ptr(), in("x1") output.as_mut_ptr(), in("x2") length,
            in("x21") probe, in("x20") snapshot.as_mut_ptr(),
            clobber_abi("C"),
        );
    }
    let mut result = [0; SIZE];
    result.copy_from_slice(snapshot);
    assert_eq!(&storage[..16], &[0xa5; 16], "snapshot prefix overwrite");
    assert_eq!(
        &storage[16 + SIZE..],
        &[0xa5; 16],
        "snapshot suffix overwrite"
    );
    result
}

#[inline(never)]
extern "C" fn retaining_control(_: &[u8; 256], _: &mut [u8; 64], _: usize) -> u8 {
    // SAFETY: Only a fixed public test marker in caller-clobbered registers.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov rax, 0x3636363636363636", "movq xmm0, rax", "xor eax, eax",
            out("rax") _, out("xmm0") _, options(nomem, nostack),
        );
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "movi v0.16b, #54", out("v0") _, options(nomem, nostack),
        );
    }
    0
}

#[inline(never)]
extern "C" fn clearing_control(_: &[u8; 256], _: &mut [u8; 64], _: usize) -> u8 {
    // SAFETY: Same public marker, then an explicit wipe of the same register.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov rax, 0x3636363636363636", "movq xmm0, rax",
            "pxor xmm0, xmm0", "xor eax, eax",
            out("rax") _, out("xmm0") _, options(nomem, nostack),
        );
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "movi v0.16b, #54", "movi v0.16b, #0",
            out("v0") _, options(nomem, nostack),
        );
    }
    0
}

#[test]
fn observer_detects_retention_and_accepts_the_explicitly_cleared_control() {
    let input = [0; 256];
    let mut output = [0; 64];
    let retained = capture(retaining_control, &input, &mut output, 0);
    let cleared = capture(clearing_control, &input, &mut output, 0);
    assert_eq!(retained[0], 0);
    assert_eq!(cleared[0], 0);
    assert!(
        has_marker(&retained, 0x36),
        "observer missed deliberate residue"
    );
    assert!(
        !has_marker(&cleared, 0x36),
        "observer retained its own marker"
    );
}

#[test]
fn classifier_requires_eight_consecutive_matching_bytes() {
    assert!(!has_marker(&[0x36; 7], 0x36));
    assert!(has_marker(&[0x36; 8], 0x36));
    let mut interrupted = [0x36; 8];
    interrupted[4] = 0;
    assert!(!has_marker(&interrupted, 0x36));
}
