extern crate std;
use super::{keccak::ROUND_CONSTANTS, kernel::scalar};
#[path = "../../src/guard_memory.rs"]
mod guard;
mod reference;

unsafe fn observe(
    state: &mut [u8; 200],
    columns: &mut [u8; 40],
    theta: &mut [u8; 40],
    rearranged: &mut [u8; 200],
    snapshot: &mut [u64; 9],
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Linux SysV fixed pointers; immediate snapshot before Rust code.
    unsafe {
        core::arch::asm!(
            "call r13",
            "mov [r12 + 8], rax", "mov [r12 + 16], rcx", "mov [r12 + 24], rdx",
            "mov [r12 + 32], r10", "mov [r12 + 40], r11",
            in("r13") scalar as super::Kernel, in("r12") snapshot.as_mut_ptr(),
            in("rdi") state.as_mut_ptr(), in("rsi") columns.as_mut_ptr(),
            in("rdx") theta.as_mut_ptr(), in("rcx") rearranged.as_mut_ptr(),
            in("r8") ROUND_CONSTANTS.as_ptr(), clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 fixed pointers; immediate snapshot before Rust code.
    unsafe {
        core::arch::asm!(
            "blr x21",
            "stp x4, x5, [x20, #8]", "stp x6, x7, [x20, #24]",
            "stp x8, x9, [x20, #40]", "str x10, [x20, #56]",
            in("x21") scalar as super::Kernel, in("x20") snapshot.as_mut_ptr(),
            in("x0") state.as_mut_ptr(), in("x1") columns.as_mut_ptr(),
            in("x2") theta.as_mut_ptr(), in("x3") rearranged.as_mut_ptr(),
            in("x4") ROUND_CONSTANTS.as_ptr(), clobber_abi("C"),
        );
    }
}
fn random(seed: &mut u64, bytes: &mut [u8]) {
    for byte in bytes {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *byte = seed.to_le_bytes()[0];
    }
}
#[test]
fn differential_and_return_registers() {
    let mut seed = 0xdead_beef_1020_3040;
    for case in 0..1024 {
        let mut s = [0xa5; 264];
        let mut c = [0xa5; 104];
        let mut d = [0xa5; 104];
        let mut b = [0xa5; 264];
        let offset = 16 + case % 32;
        let state: &mut [u8; 200] = (&mut s[offset..offset + 200])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let columns: &mut [u8; 40] = (&mut c[offset..offset + 40])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let theta: &mut [u8; 40] = (&mut d[offset..offset + 40])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let rearranged: &mut [u8; 200] = (&mut b[offset..offset + 200])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        random(&mut seed, state);
        random(&mut seed, columns);
        random(&mut seed, theta);
        random(&mut seed, rearranged);
        if case < 2 {
            state.fill(if case == 0 { 0 } else { 255 });
        }
        let expected = reference::permute(state);
        let mut snapshot = [u64::MAX; 9];
        // SAFETY: Disjoint fixed live arrays; no instruction extension needed.
        unsafe { observe(state, columns, theta, rearranged, &mut snapshot) };
        assert_eq!(state, &expected);
        assert_eq!(columns, &[0; 40]);
        assert_eq!(theta, &[0; 40]);
        assert_eq!(rearranged, &[0; 200]);
        let end = if cfg!(target_arch = "x86_64") { 6 } else { 8 };
        assert_eq!(snapshot[0], u64::MAX);
        assert!(snapshot[1..end].iter().all(|x| *x == 0), "register residue");
        assert!(snapshot[end..].iter().all(|x| *x == u64::MAX));
        for (buffer, width) in [(&s[..], 200), (&c[..], 40), (&d[..], 40), (&b[..], 200)] {
            assert!(
                buffer[..offset]
                    .iter()
                    .chain(&buffer[offset + width..])
                    .all(|x| *x == 0xa5)
            );
        }
    }
    std::println!(
        "KECCAK_SCALAR: 1024 independent states; 32 unaligned placements; return-register cleanup PASS"
    );
}
#[test]
fn fixed_memory_bounds() -> std::io::Result<()> {
    let mut seed = 0x1234_5678_abcd_ef01;
    for bits in 0..32 {
        let mut state = guard::Pages::new()?;
        let mut columns = guard::Pages::new()?;
        let mut theta = guard::Pages::new()?;
        let mut rearranged = guard::Pages::new()?;
        let mut constants = guard::Pages::new()?;
        let (s, c, d, b, k) = (
            bits & 1 != 0,
            bits & 2 != 0,
            bits & 4 != 0,
            bits & 8 != 0,
            bits & 16 != 0,
        );
        random(&mut seed, state.bytes::<200>(s));
        random(&mut seed, columns.bytes::<40>(c));
        random(&mut seed, theta.bytes::<40>(d));
        random(&mut seed, rearranged.bytes::<200>(b));
        for (bytes, value) in constants
            .bytes::<192>(k)
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(ROUND_CONSTANTS)
        {
            *bytes = value.to_ne_bytes();
        }
        let expected = reference::permute(state.read::<200>(s));
        constants.readonly()?;
        let table = constants.read::<192>(k);
        assert_eq!(table.as_ptr().align_offset(8), 0);
        // SAFETY: Disjoint page-bounded arrays and aligned read-only u64 table.
        unsafe {
            scalar(
                state.bytes::<200>(s),
                columns.bytes::<40>(c),
                theta.bytes::<40>(d),
                rearranged.bytes::<200>(b),
                &*table.as_ptr().cast::<[u64; 24]>(),
            )
        };
        assert_eq!(state.read::<200>(s), &expected);
        assert_eq!(columns.read::<40>(c), &[0; 40]);
        assert_eq!(theta.read::<40>(d), &[0; 40]);
        assert_eq!(rearranged.read::<200>(b), &[0; 200]);
    }
    std::println!("KECCAK_SCALAR_BOUNDS: 32 placements; readonly constants PASS");
    Ok(())
}
