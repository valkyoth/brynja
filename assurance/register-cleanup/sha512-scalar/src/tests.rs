extern crate std;
use super::{compress64::ROUND_CONSTANTS, kernel::scalar};
#[path = "../../src/guard_memory.rs"]
mod guard;
mod reference;

unsafe fn observe(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut [u8; 640],
    snapshot: &mut [u64; 12],
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Linux SysV arguments. Snapshot and function pointers are preserved
    // in callee-saved registers; all secret-working registers are sampled first.
    unsafe {
        core::arch::asm!(
            "call r13",
            "mov [r12 + 8], rax", "mov [r12 + 16], rcx", "mov [r12 + 24], rdx",
            "mov [r12 + 32], r8", "mov [r12 + 40], r9", "mov [r12 + 48], r10", "mov [r12 + 56], r11",
            in("r13") scalar as super::Kernel, in("r12") snapshot.as_mut_ptr(),
            in("rdi") state.as_mut_ptr(), in("rsi") block.as_ptr(),
            in("rdx") scratch.as_mut_ptr(), in("rcx") ROUND_CONSTANTS.as_ptr(),
            clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 fixed arguments and immediate observation before Rust runs.
    unsafe {
        core::arch::asm!(
            "blr x21",
            "stp x4, x5, [x20, #8]", "stp x6, x7, [x20, #24]",
            "stp x8, x9, [x20, #40]", "stp x10, x11, [x20, #56]",
            in("x21") scalar as super::Kernel, in("x20") snapshot.as_mut_ptr(),
            in("x0") state.as_mut_ptr(), in("x1") block.as_ptr(),
            in("x2") scratch.as_mut_ptr(), in("x3") ROUND_CONSTANTS.as_ptr(),
            clobber_abi("C"),
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
    assert_eq!(ROUND_CONSTANTS, reference::constants());
    for case in 0..1024 {
        let mut backing = [0xa5; 128];
        let mut message = [0xa5; 192];
        let mut work = [0xa5; 704];
        let offset = 16 + case % 32;
        let state: &mut [u8; 64] = (&mut backing[offset..offset + 64])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let block: &mut [u8; 128] = (&mut message[offset..offset + 128])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let scratch: &mut [u8; 640] = (&mut work[offset..offset + 640])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        random(&mut seed, state);
        random(&mut seed, block);
        random(&mut seed, scratch);
        if case < 2 {
            state.fill(if case == 0 { 0 } else { 255 });
            block.fill(if case == 0 { 0 } else { 255 });
        }
        let original = *block;
        let expected = reference::compress(*state, block);
        let mut snapshot = [u64::MAX; 12];
        // SAFETY: Fixed disjoint operands; no instruction extensions required.
        unsafe { observe(state, block, scratch, &mut snapshot) };
        assert_eq!(state, &expected);
        assert_eq!(block, &original);
        assert!(scratch.iter().all(|x| *x == 0), "scratch residue");
        let end = if cfg!(target_arch = "x86_64") { 8 } else { 9 };
        assert_eq!(snapshot[0], u64::MAX);
        assert!(
            snapshot[1..end].iter().all(|x| *x == 0),
            "working-register residue"
        );
        assert!(snapshot[end..].iter().all(|x| *x == u64::MAX));
        for (buffer, width) in [(&backing[..], 64), (&message[..], 128), (&work[..], 640)] {
            assert!(
                buffer[..offset]
                    .iter()
                    .chain(&buffer[offset + width..])
                    .all(|x| *x == 0xa5)
            );
        }
    }
    std::println!(
        "SHA512_SCALAR: 1024 independent pairs; 32 unaligned placements; return-register cleanup PASS"
    );
}

#[test]
fn fixed_memory_bounds() -> std::io::Result<()> {
    let mut seed = 0x1234_5678_abcd_ef01;
    for bits in 0..16 {
        let mut state = guard::Pages::new()?;
        let mut block = guard::Pages::new()?;
        let mut scratch = guard::Pages::new()?;
        let mut constants = guard::Pages::new()?;
        let (s, b, w, k) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0);
        random(&mut seed, state.bytes::<64>(s));
        random(&mut seed, block.bytes::<128>(b));
        random(&mut seed, scratch.bytes::<640>(w));
        for (bytes, value) in constants
            .bytes::<640>(k)
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(ROUND_CONSTANTS)
        {
            *bytes = value.to_ne_bytes();
        }
        let expected = reference::compress(*state.read::<64>(s), block.read::<128>(b));
        block.readonly()?;
        constants.readonly()?;
        let table = constants.read::<640>(k);
        assert_eq!(table.as_ptr().align_offset(8), 0);
        // SAFETY: Disjoint fixed buffers at page edges; initialized aligned
        // u64 table and input are read-only, with inaccessible neighbor pages.
        unsafe {
            scalar(
                state.bytes::<64>(s),
                block.read::<128>(b),
                scratch.bytes::<640>(w),
                &*table.as_ptr().cast::<[u64; 80]>(),
            )
        };
        assert_eq!(state.read::<64>(s), &expected);
        assert!(scratch.read::<640>(w).iter().all(|x| *x == 0));
    }
    std::println!("SHA512_SCALAR_BOUNDS: 16 placements; readonly input/table PASS");
    Ok(())
}
