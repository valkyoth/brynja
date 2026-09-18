extern crate std;
use crate::kernel::compress;

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "windows"),
    feature = "win64-probe"
))]
const _: unsafe extern "win64" fn(&mut [u8; 20], &[u8; 64], &mut [u8; 320]) = compress;

const AVAILABLE: bool = cfg!(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sha",
        target_feature = "sse2"
    ),
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha2"
    )
));

fn reference(bytes: [u8; 20], block: &[u8; 64]) -> [u8; 20] {
    let mut state = [0_u32; 5];
    for (v, b) in state.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *v = u32::from_be_bytes(*b);
    }
    let mut w = [0_u32; 80];
    for (v, b) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *v = u32::from_be_bytes(*b);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = state;
    for (t, word) in w.into_iter().enumerate() {
        let (f, k) = match t {
            0..20 => ((b & c) | (!b & d), 0x5a827999_u32),
            20..40 => (b ^ c ^ d, 0x6ed9eba1),
            40..60 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        (a, b, c, d, e) = (
            a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word),
            a,
            b.rotate_left(30),
            c,
            d,
        );
    }
    let mut out = [0; 20];
    for ((dst, initial), last) in out
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(state)
        .zip([a, b, c, d, e])
    {
        *dst = initial.wrapping_add(last).to_be_bytes();
    }
    out
}
fn input(seed: &mut u64, case: usize) -> ([u8; 20], [u8; 64]) {
    let mut state = [0; 20];
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
    (state, block)
}
#[test]
#[cfg_attr(
    not(any(
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "sha",
            target_feature = "sse2"
        ),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha2"
        )
    )),
    ignore = "requires native SHA/SSE2 or NEON/SHA2 emulator with matching build bundle"
)]
fn differential_and_registers() {
    assert!(core::hint::black_box(AVAILABLE));
    let iv = [
        0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54,
        0x76, 0xc3, 0xd2, 0xe1, 0xf0,
    ];
    let mut abc = [0; 64];
    abc[..4].copy_from_slice(b"abc\x80");
    abc[63] = 24;
    assert_eq!(
        reference(iv, &abc),
        [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
        ]
    );
    let mut seed = 0xb01d_4316_7c52_980f;
    for case in 0..1024 {
        let (mut state, block) = input(&mut seed, case);
        let expected = reference(state, &block);
        let saved = block;
        let mut schedule = [0xa5; 320];
        // SAFETY: Feature-gated test; disjoint exact initialized arrays.
        unsafe {
            observe(&mut state, &block, &mut schedule);
        }
        assert_eq!(state, expected);
        assert_eq!(block, saved);
        assert_eq!(schedule, [0; 320]);
    }
    for offset in 1..16 {
        let (state, block) = input(&mut seed, 17);
        let expected = reference(state, &block);
        let mut s = [0x39; 35];
        let mut b = [0x39; 79];
        let mut w = [0x39; 335];
        s[offset..offset + 20].copy_from_slice(&state);
        b[offset..offset + 64].copy_from_slice(&block);
        let Ok(state) = <&mut [u8; 20]>::try_from(&mut s[offset..offset + 20]) else {
            panic!("fixed bounds")
        };
        let Ok(block) = <&[u8; 64]>::try_from(&b[offset..offset + 64]) else {
            panic!("fixed bounds")
        };
        let Ok(schedule) = <&mut [u8; 320]>::try_from(&mut w[offset..offset + 320]) else {
            panic!("fixed bounds")
        };
        // SAFETY: Exact byte-aligned borrows; same ISA gate as above.
        unsafe {
            compress(state, block, schedule);
        }
        assert_eq!(*state, expected);
        assert_eq!(*schedule, [0; 320]);
        for (buffer, len) in [(&s[..], 20), (&b[..], 64), (&w[..], 320)] {
            assert!(
                buffer[..offset]
                    .iter()
                    .chain(&buffer[offset + len..])
                    .all(|b| *b == 0x39)
            );
        }
    }
    std::println!("SHA1_REGISTERS: 1024 independent compressions; 15 unaligned placements; PASS");
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2")]
unsafe fn observe(state: &mut [u8; 20], block: &[u8; 64], schedule: &mut [u8; 320]) {
    let mut snapshot = [0xa5_u8; 232];
    #[cfg(not(any(target_os = "windows", feature = "win64-probe")))]
    // SAFETY: SysV's three arguments, ABI clobbers and preserved R12 snapshot.
    unsafe {
        core::arch::asm!(
            "call {kernel}", "mov [r12], rax",
            "movdqu [r12+8], xmm0", "movdqu [r12+24], xmm1",
            "movdqu [r12+40], xmm2", "movdqu [r12+56], xmm3",
            kernel=sym compress, in("rdi") state.as_mut_ptr(), in("rsi") block.as_ptr(),
            in("rdx") schedule.as_mut_ptr(),in("r12") snapshot.as_mut_ptr(),clobber_abi("C"),
        );
    }
    #[cfg(any(target_os = "windows", feature = "win64-probe"))]
    // SAFETY: Win64 argument registers and shadow space; all altered registers
    // declared. Saved-caller canaries must survive the opaque function.
    unsafe {
        core::arch::asm!(
            "pcmpeqd xmm6,xmm6","pcmpeqd xmm7,xmm7","pcmpeqd xmm8,xmm8","pcmpeqd xmm9,xmm9",
            "pcmpeqd xmm10,xmm10","pcmpeqd xmm11,xmm11","pcmpeqd xmm12,xmm12","pcmpeqd xmm13,xmm13",
            "pcmpeqd xmm14,xmm14","pcmpeqd xmm15,xmm15",
            "sub rsp,32","call {kernel}","add rsp,32","mov [r12],rax",
            "movdqu [r12+8],xmm0","movdqu [r12+24],xmm1","movdqu [r12+40],xmm2","movdqu [r12+56],xmm3",
            "movdqu [r12+72],xmm6","movdqu [r12+88],xmm7","movdqu [r12+104],xmm8","movdqu [r12+120],xmm9",
            "movdqu [r12+136],xmm10","movdqu [r12+152],xmm11","movdqu [r12+168],xmm12","movdqu [r12+184],xmm13",
            "movdqu [r12+200],xmm14","movdqu [r12+216],xmm15",
            kernel=sym compress,in("rcx") state.as_mut_ptr(),in("rdx") block.as_ptr(),in("r8") schedule.as_mut_ptr(),
            in("r12") snapshot.as_mut_ptr(),out("xmm6") _,out("xmm7") _,out("xmm8") _,out("xmm9") _,
            out("xmm10") _,out("xmm11") _,out("xmm12") _,out("xmm13") _,out("xmm14") _,out("xmm15") _,clobber_abi("win64"),
        );
    }
    assert_eq!(&snapshot[..72], &[0; 72], "x86 register residue");
    #[cfg(any(target_os = "windows", feature = "win64-probe"))]
    assert_eq!(
        &snapshot[72..],
        &[255; 160],
        "Win64 preserved register corruption"
    );
}

#[cfg(target_arch = "x86")]
#[target_feature(enable = "sha,sse2")]
unsafe fn observe(state: &mut [u8; 20], block: &[u8; 64], schedule: &mut [u8; 320]) {
    let mut snapshot = [0xa5_u8; 68];
    // SAFETY: i686 C stack arguments with padding and complete caller clobbers;
    // EDI preserves the snapshot pointer. No output depends on argument registers.
    unsafe {
        core::arch::asm!(
            "sub esp,4","push edx","push ecx","push eax","call {kernel}","add esp,16",
            "mov [edi],eax","movdqu [edi+4],xmm0","movdqu [edi+20],xmm1",
            "movdqu [edi+36],xmm2","movdqu [edi+52],xmm3",
            kernel=sym compress,in("eax") state.as_mut_ptr(),in("ecx") block.as_ptr(),
            in("edx") schedule.as_mut_ptr(),in("edi") snapshot.as_mut_ptr(),clobber_abi("C"),
        );
    }
    assert_eq!(snapshot, [0; 68], "i686 register residue");
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,sha2")]
unsafe fn observe(state: &mut [u8; 20], block: &[u8; 64], schedule: &mut [u8; 320]) {
    let mut snapshot = [0xa5_u8; 192];
    // SAFETY: Three AAPCS arguments, preserved X20 snapshot and D8..15 canaries.
    // Registers are recorded before any compiler-generated code can alter them.
    unsafe {
        core::arch::asm!(
            "movi v8.16b,#255","movi v9.16b,#255","movi v10.16b,#255","movi v11.16b,#255",
            "movi v12.16b,#255","movi v13.16b,#255","movi v14.16b,#255","movi v15.16b,#255",
            "bl {kernel}","stp x4,x5,[x20]","stp x6,xzr,[x20,#16]",
            "stp q0,q1,[x20,#32]","stp q2,q3,[x20,#64]","stp q4,q5,[x20,#96]",
            "stp d8,d9,[x20,#128]","stp d10,d11,[x20,#144]","stp d12,d13,[x20,#160]","stp d14,d15,[x20,#176]",
            kernel=sym compress,in("x0") state.as_mut_ptr(),in("x1") block.as_ptr(),in("x2") schedule.as_mut_ptr(),
            in("x20") snapshot.as_mut_ptr(),out("v8") _,out("v9") _,out("v10") _,out("v11") _,
            out("v12") _,out("v13") _,out("v14") _,out("v15") _,clobber_abi("C"),
        );
    }
    assert_eq!(&snapshot[..128], &[0; 128], "Arm register residue");
    assert_eq!(
        &snapshot[128..],
        &[255; 64],
        "Arm preserved register corruption"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(
    not(any(
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "sha",
            target_feature = "sse2"
        ),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "sha2"
        )
    )),
    ignore = "requires matching SHA/SSE2 or NEON/SHA2 features"
)]
fn guarded_bounds() -> std::io::Result<()> {
    use crate::guard_pages::Pages;
    assert!(core::hint::black_box(AVAILABLE));
    let mut seed = 0x8792_4135_aab3_1001;
    for placement in 0..8 {
        let mut s = Pages::new()?;
        let mut b = Pages::new()?;
        let mut w = Pages::new()?;
        let se = placement & 1 != 0;
        let be = placement & 2 != 0;
        let we = placement & 4 != 0;
        let (state, block) = input(&mut seed, 21);
        let expected = reference(state, &block);
        *s.bytes::<20>(se) = state;
        *b.bytes::<64>(be) = block;
        w.bytes::<320>(we).fill(0xa5);
        b.readonly()?;
        // SAFETY: Feature gate and three disjoint exact live regions with guard pages.
        unsafe {
            compress(s.bytes(se), b.read(be), w.bytes(we));
        }
        assert_eq!(*s.read(se), expected);
        assert_eq!(*b.read(be), block);
        assert_eq!(*w.read::<320>(we), [0; 320]);
    }
    std::println!("SHA1_BOUNDS: 8 guarded placements; readonly input: PASS");
    Ok(())
}
