extern crate std;
use crate::{constants::HARDENED_CONSTANTS as ROUND_CONSTANTS, kernel::compress};

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "windows"),
    feature = "win64-probe"
))]
const _: unsafe extern "win64" fn(&mut [u8; 864], &[u32; 80]) = compress;

const AVAILABLE: bool = cfg!(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "aarch64", target_feature = "neon")
));
const WIDTH: usize = if cfg!(target_arch = "x86_64") { 8 } else { 4 };

fn prepare(seed: &mut u64, case: usize) -> ([u8; 864], [u8; 128]) {
    let mut packed = [0xa5; 864];
    let mut expected = [0; 128];
    for lane in 0..8 {
        let mut state = [0; 16];
        let mut block = [0; 64];
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
        for (word, bytes) in state.as_chunks::<4>().0.iter().enumerate() {
            packed[word * 32 + lane * 4..word * 32 + lane * 4 + 4].copy_from_slice(bytes);
        }
        for (word, bytes) in block.as_chunks::<4>().0.iter().enumerate() {
            packed[128 + word * 32 + lane * 4..132 + word * 32 + lane * 4].copy_from_slice(bytes);
        }
        if lane < WIDTH {
            for (word, bytes) in reference(state, &block)
                .as_chunks::<4>()
                .0
                .iter()
                .enumerate()
            {
                expected[word * 32 + lane * 4..word * 32 + lane * 4 + 4].copy_from_slice(bytes);
            }
        }
    }
    (packed, expected)
}
fn check(scratch: &[u8; 864], expected: &[u8; 128]) {
    assert_eq!(
        &scratch[640..768],
        expected,
        "lane result or inactive lane corruption"
    );
    assert_eq!(&scratch[..640], &[0; 640], "input/message residue");
    assert_eq!(&scratch[768..], &[0; 96], "temporary residue");
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
        prefix: u32,
        values: [u32; 80],
    }
    let constants = Constants {
        prefix: 0,
        values: ROUND_CONSTANTS,
    };
    assert_eq!(constants.values.as_ptr() as usize % 16, 4);
    for offset in 1..32 {
        let (original, expected) = prepare(&mut seed, 1024);
        let mut backing = [0x39; 895];
        let Ok(scratch) = <&mut [u8; 864]>::try_from(&mut backing[offset..offset + 864]) else {
            panic!("fixed test bounds")
        };
        *scratch = original;
        // SAFETY: Same ISA gate; byte-aligned scratch, u32-aligned constants.
        unsafe { compress(scratch, &constants.values) };
        check(scratch, &expected);
        assert!(
            backing[..offset]
                .iter()
                .chain(&backing[offset + 864..])
                .all(|b| *b == 0x39)
        );
    }
    std::println!("MD5_CLEANUP: 1024 independent batches; 31 unaligned placements; PASS");
}

#[cfg(all(
    target_arch = "x86_64",
    not(any(target_os = "windows", feature = "win64-probe"))
))]
#[target_feature(enable = "avx2")]
unsafe fn observe(scratch: &mut [u8; 864], snapshot: &mut [u8; 312]) {
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
unsafe fn observe(scratch: &mut [u8; 864], snapshot: &mut [u8; 312]) {
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
unsafe fn observe(scratch: &mut [u8; 864], snapshot: &mut [u8; 160]) {
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
        *scratch.bytes::<864>(s_end) = initial;
        for (part, word) in constants
            .bytes::<320>(c_end)
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(ROUND_CONSTANTS)
        {
            *part = word.to_ne_bytes();
        }
        constants.readonly()?;
        let bytes = constants.read::<320>(c_end);
        assert_eq!(bytes.as_ptr().align_offset(core::mem::align_of::<u32>()), 0);
        // SAFETY: Exact aligned initialized read-only 80-word allocation.
        let words = unsafe { &*bytes.as_ptr().cast::<[u32; 80]>() };
        // SAFETY: ISA gate, disjoint fixed regions with inaccessible neighbors.
        unsafe { compress(scratch.bytes(s_end), words) };
        check(scratch.read(s_end), &expected);
    }
    std::println!("MD5_BOUNDS: 4 guarded placements; readonly constants: PASS");
    Ok(())
}

fn reference(mut bytes: [u8; 16], block: &[u8; 64]) -> [u8; 16] {
    let initial =
        core::array::from_fn::<_, 4, _>(|i| u32::from_le_bytes(bytes.as_chunks::<4>().0[i]));
    let words =
        core::array::from_fn::<_, 16, _>(|i| u32::from_le_bytes(block.as_chunks::<4>().0[i]));
    let [mut a, mut b, mut c, mut d] = initial;
    for i in 0..64 {
        let (f, g, shift) = match i {
            0..=15 => ((b & c) | (!b & d), i, [7, 12, 17, 22][i % 4]),
            16..=31 => ((b & d) | (c & !d), (5 * i + 1) % 16, [5, 9, 14, 20][i % 4]),
            32..=47 => (b ^ c ^ d, (3 * i + 5) % 16, [4, 11, 16, 23][i % 4]),
            _ => (c ^ (b | !d), (7 * i) % 16, [6, 10, 15, 21][i % 4]),
        };
        // RFC 1321 sine construction, independent of the production table.
        let constant = (((i + 1) as f64).sin().abs() * 4_294_967_296.0) as u32;
        let next = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(words[g])
                .wrapping_add(constant)
                .rotate_left(shift),
        );
        (a, b, c, d) = (d, next, b, c);
    }
    for ((out, original), last) in bytes
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(initial)
        .zip([a, b, c, d])
    {
        *out = original.wrapping_add(last).to_le_bytes();
    }
    bytes
}

#[test]
fn independent_oracle_matches_rfc_abc() {
    assert_eq!(&ROUND_CONSTANTS[..64], &crate::constants::CONSTANTS);
    for (i, constant) in ROUND_CONSTANTS[..64].iter().enumerate() {
        assert_eq!(
            *constant,
            (((i + 1) as f64).sin().abs() * 4_294_967_296.0) as u32
        );
    }
    let mut state = [0; 16];
    for (dst, word) in state.as_chunks_mut::<4>().0.iter_mut().zip([
        0x67452301_u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
    ]) {
        *dst = word.to_le_bytes();
    }
    let mut block = [0; 64];
    block[..4].copy_from_slice(b"abc\x80");
    block[56] = 24;
    assert_eq!(
        reference(state, &block),
        [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
            0x7f, 0x72
        ]
    );
}
