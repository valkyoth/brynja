extern crate std;
use super::kernel::scalar;

#[path = "../../src/guard_memory.rs"]
mod guard;
mod reference;

unsafe fn observe(
    state: &mut [u8; 20],
    block: &[u8; 64],
    schedule: &mut [u8; 320],
    snapshot: &mut [u64; 12],
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Linux SysV arguments. R12/R13 preserve observer pointers. R14 is
    // a public offset only; the ABI restores its caller-owned incoming value.
    unsafe {
        core::arch::asm!(
            "call r13",
            "mov [r12 + 8], rax", "mov [r12 + 16], rcx", "mov [r12 + 24], rdx",
            "mov [r12 + 32], r8", "mov [r12 + 40], r9", "mov [r12 + 48], r10", "mov [r12 + 56], r11",
            in("r13") scalar as super::Kernel, in("r12") snapshot.as_mut_ptr(),
            in("rdi") state.as_mut_ptr(), in("rsi") block.as_ptr(), in("rdx") schedule.as_mut_ptr(),
            clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 arguments. Capture X4-X12 immediately after raw return.
    unsafe {
        core::arch::asm!(
            "blr x21",
            "stp x4, x5, [x20, #8]", "stp x6, x7, [x20, #24]",
            "stp x8, x9, [x20, #40]", "stp x10, x11, [x20, #56]", "str x12, [x20, #72]",
            in("x21") scalar as super::Kernel, in("x20") snapshot.as_mut_ptr(),
            in("x0") state.as_mut_ptr(), in("x1") block.as_ptr(), in("x2") schedule.as_mut_ptr(),
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
    let mut seed = 0x1234_5678_fedc_ba98;
    for case in 0..1024 {
        let mut backing = [0xa5; 96];
        let mut message = [0xa5; 128];
        let mut scratch = [0xa5; 384];
        let offset = 16 + case % 32;
        let state: &mut [u8; 20] = (&mut backing[offset..offset + 20])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let block: &mut [u8; 64] = (&mut message[offset..offset + 64])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let schedule: &mut [u8; 320] = (&mut scratch[offset..offset + 320])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        random(&mut seed, state);
        random(&mut seed, block);
        random(&mut seed, schedule);
        if case < 2 {
            state.fill(if case == 0 { 0 } else { 255 });
            block.fill(if case == 0 { 0 } else { 255 });
        }
        let original = *block;
        let expected = reference::compress(*state, block);
        let mut snapshot = [u64::MAX; 12];
        // SAFETY: Fixed disjoint byte operands, baseline ISA only.
        unsafe { observe(state, block, schedule, &mut snapshot) };
        assert_eq!(state, &expected);
        assert_eq!(block, &original);
        assert!(schedule.iter().all(|x| *x == 0), "schedule residue");
        let end = if cfg!(target_arch = "x86_64") { 8 } else { 10 };
        assert_eq!(snapshot[0], u64::MAX);
        assert!(
            snapshot[1..end].iter().all(|x| *x == 0),
            "working-register residue"
        );
        assert!(snapshot[end..].iter().all(|x| *x == u64::MAX));
        for (buffer, width) in [(&backing[..], 20), (&message[..], 64), (&scratch[..], 320)] {
            assert!(
                buffer[..offset]
                    .iter()
                    .chain(&buffer[offset + width..])
                    .all(|x| *x == 0xa5)
            );
        }
    }
    std::println!(
        "SHA1_SCALAR: 1024 independent pairs; 32 unaligned placements; return-register cleanup PASS"
    );
}

#[test]
fn fixed_memory_bounds() -> std::io::Result<()> {
    let mut seed = 0xdead_beef_cafe_feed;
    for bits in 0..8 {
        let mut state = guard::Pages::new()?;
        let mut block = guard::Pages::new()?;
        let mut schedule = guard::Pages::new()?;
        let (s, b, w) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
        random(&mut seed, state.bytes::<20>(s));
        random(&mut seed, block.bytes::<64>(b));
        random(&mut seed, schedule.bytes::<320>(w));
        let expected = reference::compress(*state.read::<20>(s), block.read::<64>(b));
        block.readonly()?;
        // SAFETY: Fixed disjoint objects at independently selected page edges.
        unsafe {
            scalar(
                state.bytes::<20>(s),
                block.read::<64>(b),
                schedule.bytes::<320>(w),
            )
        };
        assert_eq!(state.read::<20>(s), &expected);
        assert!(schedule.read::<320>(w).iter().all(|x| *x == 0));
    }
    std::println!("SHA1_SCALAR_BOUNDS: 8 placements; readonly input PASS");
    Ok(())
}
