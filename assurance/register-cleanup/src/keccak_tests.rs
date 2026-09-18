extern crate std;
use crate::{
    constants::{ROUND_CONSTANTS, ZERO_STATE_RESULT},
    kernel::permute,
};

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "windows"),
    feature = "win64-probe"
))]
const _: unsafe extern "win64" fn(&mut [u8; 576], &[u64; 24], &mut [u8; 200]) = permute;

const AVAILABLE: bool = cfg!(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha3"
    )
));

// Independent coordinate recurrence: rho offsets and round constants are
// generated, not imported from the implementation's table or lane mapping.
fn reference(bytes: &[u8]) -> [u8; 200] {
    let mut a = [0_u64; 25];
    for (word, part) in a.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*part);
    }
    let mut lfsr = 1_u8;
    for _ in 0..24 {
        let mut c = [0; 5];
        for x in 0..5 {
            for y in 0..5 {
                c[x] ^= a[x + 5 * y];
            }
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0; 25];
        b[0] = a[0];
        let (mut x, mut y) = (1, 0);
        for t in 0..24_u32 {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left((t + 1) * (t + 2) / 2);
            (x, y) = (y, (2 * x + 3 * y) % 5);
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        let mut rc = 0;
        for j in 0..7 {
            if lfsr & 1 != 0 {
                rc ^= 1_u64 << ((1 << j) - 1);
            }
            lfsr = (lfsr << 1) ^ if lfsr & 0x80 != 0 { 0x71 } else { 0 };
        }
        a[0] ^= rc;
    }
    let mut result = [0; 200];
    for (part, word) in result.as_chunks_mut::<8>().0.iter_mut().zip(a) {
        *part = word.to_le_bytes();
    }
    result
}

#[test]
fn independent_oracle_known_answer() {
    let actual = reference(&[0; 200]);
    for (part, word) in actual.as_chunks::<8>().0.iter().zip(ZERO_STATE_RESULT) {
        assert_eq!(u64::from_le_bytes(*part), word);
    }
}

#[test]
#[cfg_attr(
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha3"
        )
    )),
    ignore = "requires matching AVX2 or NEON/SHA3 hardware/emulator"
)]
fn permutation_and_actual_return_registers() {
    assert!(core::hint::black_box(AVAILABLE));
    let mut seed = 0x1f93_574a_56d1_8829_u64;
    for case in 0..1024 {
        let mut scratch = [0xa5; 576];
        let mut state = [0; 200];
        for byte in &mut state {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed.to_le_bytes()[0];
        }
        if case < 2 {
            state.fill(if case == 0 { 0 } else { 255 });
        }
        let expected = reference(&state);
        #[cfg(target_arch = "x86_64")]
        {
            let mut snapshot = [0xa5; 320];
            // SAFETY: Explicit ISA-gated test; exact exclusive snapshot and
            // scratch, with all ABI-clobbered registers declared by observer.
            unsafe { observe(&mut scratch, &mut state, &mut snapshot) };
            assert_eq!(&snapshot[..160], &[0; 160], "register residue case {case}");
            #[cfg(any(target_os = "windows", feature = "win64-probe"))]
            assert_eq!(&snapshot[160..], &[255; 160], "Win64 XMM6..15 corruption");
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut snapshot = [0xa5; 176];
            // SAFETY: Same platform precondition, exact fixed live borrows.
            unsafe { observe(&mut scratch, &mut state, &mut snapshot) };
            assert_eq!(
                &snapshot[..112],
                &[0; 112],
                "Arm register residue case {case}"
            );
            assert_eq!(&snapshot[112..], &[255; 64], "Arm D8..15 corruption");
        }
        assert_eq!(state, expected, "permutation case {case}");
        assert_eq!(scratch, [0; 576], "scratch residue case {case}");
    }
    for offset in 1..32 {
        let mut backing = [0xa5; 607];
        let mut state_backing = [0x93; 231];
        let Ok(scratch) = <&mut [u8; 576]>::try_from(&mut backing[offset..offset + 576]) else {
            panic!("fixed test bounds")
        };
        let Ok(state) = <&mut [u8; 200]>::try_from(&mut state_backing[offset..offset + 200]) else {
            panic!("fixed state bounds")
        };
        let expected = reference(state);
        // SAFETY: Same ISA gate, byte-aligned exact borrow.
        unsafe { permute(scratch, &ROUND_CONSTANTS, state) };
        assert_eq!(*state, expected);
        assert_eq!(*scratch, [0; 576]);
        assert!(
            state_backing[..offset]
                .iter()
                .chain(&state_backing[offset + 200..])
                .all(|b| *b == 0x93)
        );
        assert!(
            backing[..offset]
                .iter()
                .chain(&backing[offset + 576..])
                .all(|b| *b == 0xa5)
        );
    }
    std::println!("KECCAK_CLEANUP: 1024 permutations; 31 unaligned placements; PASS");
}

#[cfg(all(
    target_arch = "x86_64",
    not(any(target_os = "windows", feature = "win64-probe"))
))]
#[target_feature(enable = "avx2")]
unsafe fn observe(scratch: &mut [u8; 576], state: &mut [u8; 200], snapshot: &mut [u8; 320]) {
    // SAFETY: C/SysV call with three pointers; R12 preserves the snapshot. All
    // volatile clobbers declared. Record registers before any compiler code.
    unsafe {
        core::arch::asm!(
            "call {kernel}",
            "mov [r12], rax", "mov [r12 + 8], rcx", "mov [r12 + 16], rdx", "mov [r12 + 24], r8",
            "vmovdqu [r12 + 32], ymm0", "vmovdqu [r12 + 64], ymm1",
            "vmovdqu [r12 + 96], ymm2", "vmovdqu [r12 + 128], ymm3",
            kernel = sym permute, in("rdi") scratch.as_mut_ptr(),
            in("rsi") ROUND_CONSTANTS.as_ptr(), in("r12") snapshot.as_mut_ptr(),
            in("rdx") state.as_mut_ptr(),
            clobber_abi("C"),
        );
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", feature = "win64-probe")
))]
#[target_feature(enable = "avx2")]
unsafe fn observe(scratch: &mut [u8; 576], state: &mut [u8; 200], snapshot: &mut [u8; 320]) {
    // SAFETY: Win64 arguments RCX/RDX/R8, 32-byte shadow space, R12-preserved
    // snapshot. Caller XMM6..15 canaries explicitly declared altered.
    unsafe {
        core::arch::asm!(
            "vpcmpeqd xmm6, xmm6, xmm6", "vpcmpeqd xmm7, xmm7, xmm7",
            "vpcmpeqd xmm8, xmm8, xmm8", "vpcmpeqd xmm9, xmm9, xmm9",
            "vpcmpeqd xmm10, xmm10, xmm10", "vpcmpeqd xmm11, xmm11, xmm11",
            "vpcmpeqd xmm12, xmm12, xmm12", "vpcmpeqd xmm13, xmm13, xmm13",
            "vpcmpeqd xmm14, xmm14, xmm14", "vpcmpeqd xmm15, xmm15, xmm15",
            "sub rsp, 32", "call {kernel}", "add rsp, 32",
            "mov [r12], rax", "mov [r12 + 8], rcx", "mov [r12 + 16], rdx", "mov [r12 + 24], r8",
            "vmovdqu [r12 + 32], ymm0", "vmovdqu [r12 + 64], ymm1",
            "vmovdqu [r12 + 96], ymm2", "vmovdqu [r12 + 128], ymm3",
            "vmovdqu [r12 + 160], xmm6", "vmovdqu [r12 + 176], xmm7",
            "vmovdqu [r12 + 192], xmm8", "vmovdqu [r12 + 208], xmm9",
            "vmovdqu [r12 + 224], xmm10", "vmovdqu [r12 + 240], xmm11",
            "vmovdqu [r12 + 256], xmm12", "vmovdqu [r12 + 272], xmm13",
            "vmovdqu [r12 + 288], xmm14", "vmovdqu [r12 + 304], xmm15",
            kernel = sym permute, in("rcx") scratch.as_mut_ptr(), in("rdx") ROUND_CONSTANTS.as_ptr(),
            in("r8") state.as_mut_ptr(),
            in("r12") snapshot.as_mut_ptr(),
            out("xmm6") _, out("xmm7") _, out("xmm8") _, out("xmm9") _, out("xmm10") _,
            out("xmm11") _, out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            clobber_abi("win64"),
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,sha3")]
unsafe fn observe(scratch: &mut [u8; 576], state: &mut [u8; 200], snapshot: &mut [u8; 176]) {
    // SAFETY: ABI-preserved X20 holds the exact snapshot across the C call.
    // Record all working registers and preserved D8..15 immediately at return.
    unsafe {
        core::arch::asm!(
            "movi v8.16b, #255", "movi v9.16b, #255", "movi v10.16b, #255", "movi v11.16b, #255",
            "movi v12.16b, #255", "movi v13.16b, #255", "movi v14.16b, #255", "movi v15.16b, #255",
            "bl {kernel}",
            "stp x4, x5, [x20]", "stp x6, x7, [x20, #16]", "stp x9, xzr, [x20, #32]",
            "stp q0, q1, [x20, #48]", "stp q2, q3, [x20, #80]",
            "stp d8, d9, [x20, #112]", "stp d10, d11, [x20, #128]",
            "stp d12, d13, [x20, #144]", "stp d14, d15, [x20, #160]",
            kernel = sym permute, in("x0") scratch.as_mut_ptr(), in("x1") ROUND_CONSTANTS.as_ptr(),
            in("x2") state.as_mut_ptr(),
            in("x20") snapshot.as_mut_ptr(),
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            clobber_abi("C"),
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha3"
        )
    )),
    ignore = "requires matching AVX2 or NEON/SHA3 hardware/emulator"
)]
fn guarded_bounds() -> std::io::Result<()> {
    use crate::guard_pages::Pages;
    assert!(core::hint::black_box(AVAILABLE));
    for placement in 0..8 {
        let mut scratch = Pages::new()?;
        let mut constants = Pages::new()?;
        let mut state = Pages::new()?;
        let s_end = placement & 1 != 0;
        let c_end = placement & 2 != 0;
        let state_end = placement & 4 != 0;
        scratch.bytes::<576>(s_end).fill(0xa5);
        state.bytes::<200>(state_end).fill(0x93);
        for (part, word) in constants
            .bytes::<192>(c_end)
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(ROUND_CONSTANTS)
        {
            *part = word.to_ne_bytes();
        }
        constants.readonly()?;
        let bytes = constants.read::<192>(c_end);
        assert_eq!(bytes.as_ptr().align_offset(core::mem::align_of::<u64>()), 0);
        // SAFETY: Exact aligned initialized read-only 24-word mapping.
        let words = unsafe { &*bytes.as_ptr().cast::<[u64; 24]>() };
        let expected = reference(state.read::<200>(state_end));
        // SAFETY: ISA gate, disjoint exact regions with inaccessible neighbors.
        unsafe { permute(scratch.bytes(s_end), words, state.bytes(state_end)) };
        assert_eq!(state.read::<200>(state_end), &expected);
        assert_eq!(scratch.read::<576>(s_end), &[0; 576]);
    }
    std::println!("KECCAK_BOUNDS: 8 guarded placements; readonly constants: PASS");
    Ok(())
}
