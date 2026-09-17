extern crate std;

#[cfg(target_arch = "aarch64")]
use crate::arm_sha512::compress;
use crate::constants::ROUND_CONSTANTS;
#[cfg(target_arch = "x86_64")]
use crate::sha512::compress;

// The cross-ABI driver changes only the ABI in its temporary production-source
// copy. Refuse to compile a Win64 observer paired with a SysV function: directly
// enabling this test-only feature must never create a mismatched machine call.
#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "windows"),
    feature = "win64-probe"
))]
const _: unsafe extern "win64" fn(&mut [u8; 64], &[u8; 128], &mut [u8; 704], &[u64; 80]) = compress;

// This is an execution test, never a silent pass on an unsupported build.
#[test]
#[cfg_attr(
    not(any(
        all(
            target_arch = "x86_64",
            target_feature = "sha512",
            target_feature = "avx2",
            target_feature = "avx"
        ),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha3"
        )
    )),
    ignore = "requires matching SHA512 hardware/emulator and the complete build feature bundle"
)]
fn compression_and_actual_return_registers() {
    assert!(core::hint::black_box(cfg!(any(
        all(
            target_arch = "x86_64",
            target_feature = "sha512",
            target_feature = "avx2",
            target_feature = "avx"
        ),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha3"
        )
    ))));
    let mut seed = 0x1579_af39_120f_8857_u64;
    for case in 0..1024 {
        let mut state = [0_u8; 64];
        let mut block = [0_u8; 128];
        for byte in state.iter_mut().chain(&mut block) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed.to_le_bytes()[0];
        }
        if case < 2 {
            state.fill(if case == 0 { 0 } else { 0xff });
            block.fill(if case == 0 { 0 } else { 0xff });
        }
        let original_block = block;
        let expected = reference(state, &block);
        let mut scratch = [0xa5_u8; 704];
        #[cfg(all(
            target_arch = "x86_64",
            not(target_os = "windows"),
            not(feature = "win64-probe")
        ))]
        {
            let mut snapshot = [0xa5_u8; 152];
            // SAFETY: The ignored-by-default test requires an explicit matching
            // CPU/SDE invocation. Borrows are disjoint, and the observer uses
            // the SysV argument ABI with every volatile register clobbered.
            unsafe { observe(&mut state, &block, &mut scratch, &mut snapshot) };
            assert_eq!(snapshot, [0; 152], "register residue in case {case}");
        }
        #[cfg(all(
            target_arch = "x86_64",
            any(target_os = "windows", feature = "win64-probe")
        ))]
        {
            let mut snapshot = [0xa5_u8; 312];
            // SAFETY: Same platform precondition; observes the Win64 ABI,
            // including the caller's lower XMM6–15 nonvolatile lanes.
            unsafe { observe_win64(&mut state, &block, &mut scratch, &mut snapshot) };
            assert_eq!(
                &snapshot[..152],
                &[0; 152],
                "Win64 working-register residue"
            );
            assert_eq!(
                &snapshot[152..],
                &[0xff; 160],
                "Win64 callee-saved XMM corruption"
            );
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut snapshot = [0xa5_u8; 320];
            // SAFETY: The explicitly enabled test requires a matching native
            // machine or QEMU; borrows and fixed snapshot are disjoint.
            unsafe { observe_arm(&mut state, &block, &mut scratch, &mut snapshot) };
            assert_eq!(&snapshot[..256], &[0; 256], "Arm working-register residue");
            assert_eq!(
                &snapshot[256..],
                &[0xff; 64],
                "Arm callee-saved D8–15 corruption"
            );
        }
        assert_eq!(state, expected, "compression case {case}");
        assert_eq!(scratch, [0; 704], "scratch case {case}");
        assert_eq!(block, original_block, "caller input was modified");
    }
    std::println!(
        "EXPERIMENTAL_SHA512_CLEANUP: 1024 compression cases; production qualification PENDING"
    );
}

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "windows"),
    not(feature = "win64-probe")
))]
#[target_feature(enable = "sha512,avx2,avx")]
unsafe fn observe(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut [u8; 704],
    snapshot: &mut [u8; 152],
) {
    // SAFETY: Snapshot uses a preserved register across the real ABI call;
    // there is no Rust/compiler code between return and the recorded values.
    // Each store lies wholly within the exact initialized snapshot borrow.
    unsafe {
        core::arch::asm!(
            "call {kernel}",
            "mov [r12], rax", "mov [r12 + 8], rcx", "mov [r12 + 16], rdx",
            "mov [r12 + 24], r8", "mov [r12 + 32], r9",
            "mov [r12 + 40], r10", "mov [r12 + 48], r11",
            "vmovdqu [r12 + 56], ymm0", "vmovdqu [r12 + 88], ymm1",
            "vmovdqu [r12 + 120], ymm2",
            kernel = sym compress,
            in("rdi") state.as_mut_ptr(),
            in("rsi") block.as_ptr(),
            in("rdx") scratch.as_mut_ptr(),
            in("rcx") ROUND_CONSTANTS.as_ptr(),
            in("r12") snapshot.as_mut_ptr(),
            clobber_abi("C"),
        );
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", feature = "win64-probe")
))]
#[target_feature(enable = "sha512,avx2,avx")]
unsafe fn observe_win64(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut [u8; 704],
    snapshot: &mut [u8; 312],
) {
    // SAFETY: Win64 takes four pointer arguments in RCX/RDX/R8/R9 and needs
    // 32 bytes of caller shadow space, preserving 16-byte stack alignment.
    // R12 retains the exact exclusive snapshot across the call. All altered
    // registers are declared clobbered, including the caller-preservation
    // canaries; compiler-generated caller saves remain outside the observer.
    unsafe {
        core::arch::asm!(
            "vpcmpeqd xmm6, xmm6, xmm6", "vpcmpeqd xmm7, xmm7, xmm7",
            "vpcmpeqd xmm8, xmm8, xmm8", "vpcmpeqd xmm9, xmm9, xmm9",
            "vpcmpeqd xmm10, xmm10, xmm10", "vpcmpeqd xmm11, xmm11, xmm11",
            "vpcmpeqd xmm12, xmm12, xmm12", "vpcmpeqd xmm13, xmm13, xmm13",
            "vpcmpeqd xmm14, xmm14, xmm14", "vpcmpeqd xmm15, xmm15, xmm15",
            "sub rsp, 32",
            "call {kernel}",
            "add rsp, 32",
            "mov [r12], rax", "mov [r12 + 8], rcx", "mov [r12 + 16], rdx",
            "mov [r12 + 24], r8", "mov [r12 + 32], r9",
            "mov [r12 + 40], r10", "mov [r12 + 48], r11",
            "vmovdqu [r12 + 56], ymm0", "vmovdqu [r12 + 88], ymm1",
            "vmovdqu [r12 + 120], ymm2",
            "vmovdqu [r12 + 152], xmm6", "vmovdqu [r12 + 168], xmm7",
            "vmovdqu [r12 + 184], xmm8", "vmovdqu [r12 + 200], xmm9",
            "vmovdqu [r12 + 216], xmm10", "vmovdqu [r12 + 232], xmm11",
            "vmovdqu [r12 + 248], xmm12", "vmovdqu [r12 + 264], xmm13",
            "vmovdqu [r12 + 280], xmm14", "vmovdqu [r12 + 296], xmm15",
            kernel = sym compress,
            in("rcx") state.as_mut_ptr(),
            in("rdx") block.as_ptr(),
            in("r8") scratch.as_mut_ptr(),
            in("r9") ROUND_CONSTANTS.as_ptr(),
            in("r12") snapshot.as_mut_ptr(),
            out("xmm6") _, out("xmm7") _, out("xmm8") _, out("xmm9") _,
            out("xmm10") _, out("xmm11") _, out("xmm12") _, out("xmm13") _,
            out("xmm14") _, out("xmm15") _,
            clobber_abi("win64"),
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,sha3")]
unsafe fn observe_arm(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut [u8; 704],
    snapshot: &mut [u8; 320],
) {
    // SAFETY: X20 is ABI-preserved and holds the exclusive 320-byte snapshot.
    // All other call clobbers, including LR, are described to the compiler.
    // Snapshot stores are wholly in bounds, and no compiler code can intervene
    // between the actual kernel return and the register observation.
    unsafe {
        core::arch::asm!(
            "movi v8.16b, #255", "movi v9.16b, #255",
            "movi v10.16b, #255", "movi v11.16b, #255",
            "movi v12.16b, #255", "movi v13.16b, #255",
            "movi v14.16b, #255", "movi v15.16b, #255",
            "bl {kernel}",
            "stp x4, x5, [x20]", "stp x6, x7, [x20, #16]",
            "stp x9, xzr, [x20, #32]",
            "stp q0, q1, [x20, #48]", "stp q2, q3, [x20, #80]",
            "stp q4, q5, [x20, #112]", "stp q6, q7, [x20, #144]",
            "stp q16, q17, [x20, #176]", "stp q18, q19, [x20, #208]",
            "str q20, [x20, #240]",
            "stp d8, d9, [x20, #256]", "stp d10, d11, [x20, #272]",
            "stp d12, d13, [x20, #288]", "stp d14, d15, [x20, #304]",
            kernel = sym compress,
            in("x0") state.as_mut_ptr(),
            in("x1") block.as_ptr(),
            in("x2") scratch.as_mut_ptr(),
            in("x3") ROUND_CONSTANTS.as_ptr(),
            in("x20") snapshot.as_mut_ptr(),
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            clobber_abi("C"),
        );
    }
}

pub(super) fn reference(mut bytes: [u8; 64], block: &[u8; 128]) -> [u8; 64] {
    let mut state = [0_u64; 8];
    for (word, part) in state.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*part);
    }
    let mut schedule = [0_u64; 80];
    for (word, part) in schedule.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*part);
    }
    for t in 16..80 {
        let x = schedule[t - 15];
        let y = schedule[t - 2];
        schedule[t] = schedule[t - 16]
            .wrapping_add(schedule[t - 7])
            .wrapping_add(x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7))
            .wrapping_add(y.rotate_right(19) ^ y.rotate_right(61) ^ (y >> 6));
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for (w, k) in schedule.into_iter().zip(ROUND_CONSTANTS) {
        let t1 = h
            .wrapping_add(e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(k)
            .wrapping_add(w);
        let t2 = (a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39))
            .wrapping_add((a & b) ^ (a & c) ^ (b & c));
        (a, b, c, d, e, f, g, h) = (t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g);
    }
    for ((slot, initial), final_word) in bytes
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(state)
        .zip([a, b, c, d, e, f, g, h])
    {
        *slot = initial.wrapping_add(final_word).to_be_bytes();
    }
    bytes
}
