extern crate std;
use crate::{constants::ROUND_CONSTANTS, kernel::compress};

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "windows"),
    feature = "win64-probe"
))]
const _: unsafe extern "win64" fn(&mut [u8; 3264], &[u64; 80]) = compress;

const AVAILABLE: bool = cfg!(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "aarch64", target_feature = "neon")
));
const WIDTH: usize = if cfg!(target_arch = "x86_64") { 4 } else { 2 };

fn prepare(seed: &mut u64, case: usize) -> ([u8; 3264], [u8; 256]) {
    let mut packed = [0xa5; 3264];
    let mut expected = [0; 256];
    for lane in 0..4 {
        let mut state = [0; 64];
        let mut block = [0; 128];
        for byte in state.iter_mut().chain(&mut block) {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *byte = seed.to_le_bytes()[0];
        }
        if case < 2 {
            state.fill(if case == 0 { 0 } else { 255 });
            block.fill(if case == 0 { 0 } else { 255 });
        }
        for (word, bytes) in state[..64].as_chunks::<8>().0.iter().enumerate() {
            packed[word * 32 + lane * 8..word * 32 + lane * 8 + 8]
                .copy_from_slice(&u64::from_be_bytes(*bytes).to_le_bytes());
        }
        for (word, bytes) in block[..128].as_chunks::<8>().0.iter().enumerate() {
            packed[256 + word * 32 + lane * 8..264 + word * 32 + lane * 8]
                .copy_from_slice(&u64::from_be_bytes(*bytes).to_le_bytes());
        }
        if lane < WIDTH {
            let output = reference(state, &block);
            for (word, bytes) in output[..64].as_chunks::<8>().0.iter().enumerate() {
                expected[word * 32 + lane * 8..word * 32 + lane * 8 + 8]
                    .copy_from_slice(&u64::from_be_bytes(*bytes).to_le_bytes());
            }
        }
    }
    (packed, expected)
}
fn check(scratch: &[u8; 3264], expected: &[u8; 256]) {
    assert_eq!(
        &scratch[2816..3072],
        expected,
        "lane result or inactive lane corruption"
    );
    assert_eq!(&scratch[..2816], &[0; 2816], "input/schedule residue");
    assert_eq!(&scratch[3072..], &[0; 192], "temporary residue");
}

#[test]
#[cfg_attr(
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    )),
    ignore = "requires matching AVX2 or little-endian NEON hardware/emulator"
)]
fn compression_and_return_registers() {
    assert!(core::hint::black_box(AVAILABLE));
    let mut seed = 0x1234_5678_99ab_cdef;
    for case in 0..1024 {
        let (mut scratch, expected) = prepare(&mut seed, case);
        #[cfg(target_arch = "x86_64")]
        {
            let mut snapshot = [0xa5; 312];
            // SAFETY: Explicit ISA-gated test with exact live disjoint borrows.
            unsafe { observe(&mut scratch, &mut snapshot) };
            assert_eq!(&snapshot[..152], &[0; 152], "x86 working-register residue");
            #[cfg(any(target_os = "windows", feature = "win64-probe"))]
            assert_eq!(&snapshot[152..], &[255; 160], "Win64 XMM6..15 corruption");
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut snapshot = [0xa5; 160];
            // SAFETY: Same ISA condition and exact fixed output extent.
            unsafe { observe(&mut scratch, &mut snapshot) };
            assert_eq!(&snapshot[..96], &[0; 96], "Arm working-register residue");
            assert_eq!(&snapshot[96..], &[255; 64], "Arm D8..15 corruption");
        }
        check(&scratch, &expected);
    }
    #[repr(C, align(16))]
    struct Constants {
        prefix: u64,
        values: [u64; 80],
    }
    let constants = Constants {
        prefix: 0,
        values: ROUND_CONSTANTS,
    };
    assert_eq!(constants.values.as_ptr() as usize % 16, 8);
    for offset in 1..32 {
        let (original, expected) = prepare(&mut seed, 1024);
        let mut backing = [0x39; 3295];
        let Ok(scratch) = <&mut [u8; 3264]>::try_from(&mut backing[offset..offset + 3264]) else {
            panic!("fixed test bounds")
        };
        *scratch = original;
        // SAFETY: Same ISA gate; byte-aligned scratch, u64-aligned constants.
        unsafe { compress(scratch, &constants.values) };
        check(scratch, &expected);
        assert!(
            backing[..offset]
                .iter()
                .chain(&backing[offset + 3264..])
                .all(|b| *b == 0x39)
        );
    }
    std::println!("BATCH512_CLEANUP: 1024 independent batches; 31 unaligned placements; PASS");
}

#[cfg(all(
    target_arch = "x86_64",
    not(any(target_os = "windows", feature = "win64-probe"))
))]
#[target_feature(enable = "avx2")]
unsafe fn observe(scratch: &mut [u8; 3264], snapshot: &mut [u8; 312]) {
    // SAFETY: C/SysV call with two pointers; R12 preserves the snapshot. All
    // volatile clobbers declared. Record registers before any compiler code.
    unsafe {
        core::arch::asm!(
            "call {kernel}",
            "mov [r12], rax", "mov [r12 + 8], rcx", "mov [r12 + 16], rdx",
            "vmovdqu [r12 + 24], ymm0", "vmovdqu [r12 + 56], ymm1",
            "vmovdqu [r12 + 88], ymm2", "vmovdqu [r12 + 120], ymm3",
            kernel = sym compress, in("rdi") scratch.as_mut_ptr(),
            in("rsi") ROUND_CONSTANTS.as_ptr(), in("r12") snapshot.as_mut_ptr(),
            clobber_abi("C"),
        );
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "windows", feature = "win64-probe")
))]
#[target_feature(enable = "avx2")]
unsafe fn observe(scratch: &mut [u8; 3264], snapshot: &mut [u8; 312]) {
    // SAFETY: Win64 arguments RCX/RDX, 32-byte shadow space, R12-preserved
    // snapshot. Caller XMM6..15 canaries explicitly declared altered.
    unsafe {
        core::arch::asm!(
            "vpcmpeqd xmm6, xmm6, xmm6", "vpcmpeqd xmm7, xmm7, xmm7",
            "vpcmpeqd xmm8, xmm8, xmm8", "vpcmpeqd xmm9, xmm9, xmm9",
            "vpcmpeqd xmm10, xmm10, xmm10", "vpcmpeqd xmm11, xmm11, xmm11",
            "vpcmpeqd xmm12, xmm12, xmm12", "vpcmpeqd xmm13, xmm13, xmm13",
            "vpcmpeqd xmm14, xmm14, xmm14", "vpcmpeqd xmm15, xmm15, xmm15",
            "sub rsp, 32", "call {kernel}", "add rsp, 32",
            "mov [r12], rax", "mov [r12 + 8], rcx", "mov [r12 + 16], rdx",
            "vmovdqu [r12 + 24], ymm0", "vmovdqu [r12 + 56], ymm1",
            "vmovdqu [r12 + 88], ymm2", "vmovdqu [r12 + 120], ymm3",
            "vmovdqu [r12 + 152], xmm6", "vmovdqu [r12 + 168], xmm7",
            "vmovdqu [r12 + 184], xmm8", "vmovdqu [r12 + 200], xmm9",
            "vmovdqu [r12 + 216], xmm10", "vmovdqu [r12 + 232], xmm11",
            "vmovdqu [r12 + 248], xmm12", "vmovdqu [r12 + 264], xmm13",
            "vmovdqu [r12 + 280], xmm14", "vmovdqu [r12 + 296], xmm15",
            kernel = sym compress, in("rcx") scratch.as_mut_ptr(), in("rdx") ROUND_CONSTANTS.as_ptr(),
            in("r12") snapshot.as_mut_ptr(),
            out("xmm6") _, out("xmm7") _, out("xmm8") _, out("xmm9") _, out("xmm10") _,
            out("xmm11") _, out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            clobber_abi("win64"),
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn observe(scratch: &mut [u8; 3264], snapshot: &mut [u8; 160]) {
    // SAFETY: ABI-preserved X20 holds the exact snapshot across the C call.
    // Record all working registers and preserved D8..15 immediately at return.
    unsafe {
        core::arch::asm!(
            "movi v8.16b, #255", "movi v9.16b, #255", "movi v10.16b, #255", "movi v11.16b, #255",
            "movi v12.16b, #255", "movi v13.16b, #255", "movi v14.16b, #255", "movi v15.16b, #255",
            "bl {kernel}",
            "stp x4, x5, [x20]", "stp x6, xzr, [x20, #16]",
            "stp q0, q1, [x20, #32]", "stp q2, q3, [x20, #64]",
            "stp d8, d9, [x20, #96]", "stp d10, d11, [x20, #112]",
            "stp d12, d13, [x20, #128]", "stp d14, d15, [x20, #144]",
            kernel = sym compress, in("x0") scratch.as_mut_ptr(), in("x1") ROUND_CONSTANTS.as_ptr(),
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
        all(target_arch = "aarch64", target_feature = "neon")
    )),
    ignore = "requires matching AVX2 or little-endian NEON hardware/emulator"
)]
fn guarded_bounds() -> std::io::Result<()> {
    use crate::guard_pages::Pages;
    assert!(core::hint::black_box(AVAILABLE));
    let mut seed = 0x2543_125a_b975_ddef;
    for placement in 0..4 {
        let mut scratch = Pages::new()?;
        let mut constants = Pages::new()?;
        let s_end = placement & 1 != 0;
        let c_end = placement & 2 != 0;
        let (initial, expected) = prepare(&mut seed, 100);
        *scratch.bytes::<3264>(s_end) = initial;
        for (part, word) in constants
            .bytes::<640>(c_end)
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(ROUND_CONSTANTS)
        {
            *part = word.to_ne_bytes();
        }
        constants.readonly()?;
        let bytes = constants.read::<640>(c_end);
        assert_eq!(bytes.as_ptr().align_offset(core::mem::align_of::<u64>()), 0);
        // SAFETY: Exact aligned initialized read-only 80-word allocation.
        let words = unsafe { &*bytes.as_ptr().cast::<[u64; 80]>() };
        // SAFETY: ISA gate, disjoint fixed regions with inaccessible neighbors.
        unsafe { compress(scratch.bytes(s_end), words) };
        check(scratch.read(s_end), &expected);
    }
    std::println!("BATCH512_BOUNDS: 4 guarded placements; readonly constants: PASS");
    Ok(())
}

pub(super) fn reference(mut bytes: [u8; 64], block: &[u8; 128]) -> [u8; 64] {
    let mut state = [0_u64; 8];
    for (word, part) in state.iter_mut().zip(bytes[..64].as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*part);
    }
    let mut schedule = [0_u64; 80];
    for (word, part) in schedule.iter_mut().zip(block[..128].as_chunks::<8>().0) {
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
