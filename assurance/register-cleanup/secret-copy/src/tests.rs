extern crate std;
use super::transfer;
#[path = "../../src/guard_memory.rs"]
mod guard;

unsafe fn observe(destination: *mut u8, source: *const u8, length: usize, snapshot: &mut [u64; 5]) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SysV fixed pointers/count; immediate caller-clobbered snapshot.
    unsafe {
        core::arch::asm!(
            "call r13",
            "mov [r12 + 8], rax", "mov [r12 + 16], rcx", "mov [r12 + 24], rdx",
            in("r13") transfer::copy_bytes as super::Kernel, in("r12") snapshot.as_mut_ptr(),
            in("rdi") destination, in("rsi") source, in("rdx") length, clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 pointers/count; record before any Rust statement runs.
    unsafe {
        core::arch::asm!(
            "blr x21",
            "stp x4, x5, [x20, #8]", "str x6, [x20, #24]",
            in("x21") transfer::copy_bytes as super::Kernel, in("x20") snapshot.as_mut_ptr(),
            in("x0") destination, in("x1") source, in("x2") length, clobber_abi("C"),
        );
    }
}
#[test]
fn alignment_length_and_return_registers() {
    let mut input = [0; 4176];
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let original = input;
    let lengths = (0..=256).chain([511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097]);
    let mut cases = 0;
    for length in lengths {
        for offset in 0..32 {
            let mut output = [0xa5; 4176];
            let start = 16 + offset;
            // Independent source/destination alignments, including opposite sides.
            let from = 47 - offset;
            let source = &input[from..from + length];
            let destination = &mut output[start..start + length];
            let mut snapshot = [u64::MAX; 5];
            // SAFETY: Exact disjoint live buffers; count bounded by both slices.
            unsafe {
                observe(
                    destination.as_mut_ptr(),
                    source.as_ptr(),
                    length,
                    &mut snapshot,
                )
            };
            assert_eq!(destination, source);
            assert_eq!(snapshot, [u64::MAX, 0, 0, 0, u64::MAX]);
            assert!(
                output[..start]
                    .iter()
                    .chain(&output[start + length..])
                    .all(|x| *x == 0xa5)
            );
            assert_eq!(input, original);
            cases += 1;
        }
    }
    assert_eq!(cases, 8512);
    std::println!("SECRET_COPY: 8512 length/alignment cases; return-register cleanup PASS");
}
#[test]
fn guarded_bounds_and_empty_null() -> std::io::Result<()> {
    let mut input = guard::Pages::new()?;
    let mut output = guard::Pages::new()?;
    for (i, byte) in input.bytes::<4096>(false).iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    input.readonly()?;
    for length in (0..=256).chain([511, 512, 513, 1023, 1024, 1025, 4095, 4096]) {
        for mode in 0..4 {
            let source = input.read::<4096>(mode & 1 != 0);
            let source = if mode & 1 != 0 {
                &source[4096 - length..]
            } else {
                &source[..length]
            };
            let backing = output.bytes::<4096>(mode & 2 != 0);
            backing.fill(0xa5);
            let start = if mode & 2 != 0 { 4096 - length } else { 0 };
            // SAFETY: Each exact slice sits at a guarded page edge; source read-only.
            unsafe { transfer::copy_bytes(backing[start..].as_mut_ptr(), source.as_ptr(), length) };
            assert_eq!(&backing[start..start + length], source);
            assert!(
                backing[..start]
                    .iter()
                    .chain(&backing[start + length..])
                    .all(|x| *x == 0xa5)
            );
        }
    }
    let mut snapshot = [u64::MAX; 5];
    // SAFETY: Empty transfer must not dereference either null pointer.
    unsafe { observe(core::ptr::null_mut(), core::ptr::null(), 0, &mut snapshot) };
    assert_eq!(snapshot, [u64::MAX, 0, 0, 0, u64::MAX]);
    std::println!(
        "SECRET_COPY_BOUNDS: four independent placements; readonly source; null-empty PASS"
    );
    Ok(())
}
#[test]
fn checked_transfer_preserves_mismatch_and_zero_length() {
    for (source, destination) in [(0, 1), (1, 0), (7, 8), (8, 7), (15, 16), (16, 15)] {
        let mut bytes = [0xa5; 32];
        assert_eq!(
            transfer::copy(&mut bytes[..destination], &[0x5a; 32][..source]),
            Err(super::SecretMemoryError::InsufficientCapacity)
        );
        assert_eq!(bytes, [0xa5; 32]);
    }
    assert_eq!(transfer::copy(&mut [], &[]), Ok(()));
    let mut output = [0xa5; 17];
    assert_eq!(transfer::copy(&mut output, &[0x37; 17]), Ok(()));
    assert_eq!(output, [0x37; 17]);
}
