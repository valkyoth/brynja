extern crate std;
use super::{CONSTANTS, kernel::scalar};
const SHIFTS: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

#[path = "../../src/guard_memory.rs"]
mod guard;
mod reference;

unsafe fn observe(state: &mut [u8; 16], block: &[u8; 64], snapshot: &mut [u64; 10]) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Fixed SysV arguments; R12 preserves the snapshot, R13 the function.
    // Only volatile registers are sampled; R14 is public/callee-preserved.
    unsafe {
        core::arch::asm!(
            "call r13",
            "mov [r12 + 8], rax", "mov [r12 + 16], rcx", "mov [r12 + 24], rdx",
            "mov [r12 + 32], r8", "mov [r12 + 40], r9", "mov [r12 + 48], r10",
            "mov [r12 + 56], r11",
            in("r13") scalar as super::Kernel, in("r12") snapshot.as_mut_ptr(),
            in("rdi") state.as_mut_ptr(), in("rsi") block.as_ptr(),
            in("rdx") CONSTANTS.as_ptr(), in("rcx") SHIFTS.as_ptr(),
            clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Fixed AAPCS64 arguments. X20/X21 preserve observer pointers.
    // X4-X11 and memory are captured before any compiler instructions execute.
    unsafe {
        core::arch::asm!(
            "blr x21",
            "stp x4, x5, [x20, #8]", "stp x6, x7, [x20, #24]",
            "stp x8, x9, [x20, #40]", "stp x10, x11, [x20, #56]",
            in("x21") scalar as super::Kernel, in("x20") snapshot.as_mut_ptr(),
            in("x0") state.as_mut_ptr(), in("x1") block.as_ptr(),
            in("x2") CONSTANTS.as_ptr(), in("x3") SHIFTS.as_ptr(),
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
    let mut seed = 0x3210_7654_ba98_fedc;
    for case in 0..1024 {
        let mut backing = [0xa5; 80];
        let mut message = [0xa5; 128];
        let offset = 16 + case % 32;
        let state: &mut [u8; 16] = (&mut backing[offset..offset + 16])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let block: &mut [u8; 64] = (&mut message[offset..offset + 64])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        random(&mut seed, state);
        random(&mut seed, block);
        if case < 2 {
            state.fill(if case == 0 { 0 } else { 255 });
            block.fill(if case == 0 { 0 } else { 255 });
        }
        let original = *block;
        let expected = reference::compress(*state, block);
        let mut snapshot = [u64::MAX; 10];
        // SAFETY: Native baseline ISA, fixed live disjoint input/output/tables.
        unsafe { observe(state, block, &mut snapshot) };
        assert_eq!(state, &expected);
        assert_eq!(block, &original);
        let end = if cfg!(target_arch = "x86_64") { 8 } else { 9 };
        assert_eq!(snapshot[0], u64::MAX);
        assert!(
            snapshot[1..end].iter().all(|x| *x == 0),
            "working-register residue"
        );
        assert!(snapshot[end..].iter().all(|x| *x == u64::MAX));
        assert!(
            backing[..offset]
                .iter()
                .chain(&backing[offset + 16..])
                .all(|x| *x == 0xa5)
        );
        assert!(
            message[..offset]
                .iter()
                .chain(&message[offset + 64..])
                .all(|x| *x == 0xa5)
        );
    }
    std::println!(
        "MD5_SCALAR: 1024 independent pairs; 32 unaligned placements; return-register cleanup PASS"
    );
}

#[test]
fn fixed_memory_bounds() -> std::io::Result<()> {
    let mut seed = 0xfedc_ba98_7654_3210;
    for bits in 0..16 {
        let mut state = guard::Pages::new()?;
        let mut block = guard::Pages::new()?;
        let mut constants = guard::Pages::new()?;
        let mut shifts = guard::Pages::new()?;
        let (s, b, c, r) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0);
        random(&mut seed, state.bytes::<16>(s));
        random(&mut seed, block.bytes::<64>(b));
        for (out, value) in constants
            .bytes::<256>(c)
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(CONSTANTS)
        {
            *out = value.to_ne_bytes();
        }
        for (out, value) in shifts
            .bytes::<64>(r)
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(SHIFTS)
        {
            *out = value.to_ne_bytes();
        }
        let expected = reference::compress(*state.read::<16>(s), block.read::<64>(b));
        block.readonly()?;
        constants.readonly()?;
        shifts.readonly()?;
        let constants = constants.read::<256>(c);
        let shifts = shifts.read::<64>(r);
        assert_eq!(constants.as_ptr().align_offset(4), 0);
        assert_eq!(shifts.as_ptr().align_offset(4), 0);
        // SAFETY: Page-aligned ends are multiples of four; exact initialized
        // integer tables, all operands disjoint with inaccessible neighbors.
        unsafe {
            scalar(
                state.bytes::<16>(s),
                block.read::<64>(b),
                &*constants.as_ptr().cast::<[u32; 64]>(),
                &*shifts.as_ptr().cast::<[u32; 16]>(),
            )
        };
        assert_eq!(state.read::<16>(s), &expected);
    }
    std::println!("MD5_SCALAR_BOUNDS: 16 placements; readonly input and tables PASS");
    Ok(())
}
