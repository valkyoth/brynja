extern crate std;
use super::difference;
#[path = "../../src/guard_memory.rs"]
mod guard;

unsafe fn observe(output: *mut u8, left: *const u8, right: *const u8, snapshot: &mut [u64; 5]) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SysV three live bytes; immediate RAX/flags snapshot before Rust resumes.
    unsafe {
        core::arch::asm!(
            "call r13", "mov [r12 + 8], rax", "pushfq", "pop r11", "mov [r12 + 24], r11",
            in("r13") difference::accumulate_byte as super::Kernel,
            in("r12") snapshot.as_mut_ptr(), in("rdi") output, in("rsi") left,
            in("rdx") right, clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 live byte pointers; snapshot X4/X5/NZCV before Rust resumes.
    unsafe {
        core::arch::asm!(
            "blr x21", "str x4, [x20, #8]", "str x5, [x20, #16]",
            "mrs x9, nzcv", "str x9, [x20, #24]",
            in("x21") difference::accumulate_byte as super::Kernel,
            in("x20") snapshot.as_mut_ptr(), in("x0") output, in("x1") left,
            in("x2") right, clobber_abi("C"),
        );
    }
}

#[test]
fn exhaustive_difference_and_normal_return_cleanup() {
    for left in 0..=u8::MAX {
        for right in 0..=u8::MAX {
            for initial in [0, 1, 0x80, 0xff] {
                let mut region = [0xa5, initial, 0x69];
                let mut snapshot = [u64::MAX; 5];
                // SAFETY: Live disjoint output and shared inputs.
                unsafe { observe(&mut region[1], &left, &right, &mut snapshot) };
                assert_eq!(region, [0xa5, initial | (left ^ right), 0x69]);
                assert_eq!(snapshot[0], u64::MAX);
                assert_eq!(snapshot[1], 0);
                assert_eq!(snapshot[4], u64::MAX);
                #[cfg(target_arch = "x86_64")]
                assert_eq!(snapshot[3] & 0x8c5, 0x44);
                #[cfg(target_arch = "aarch64")]
                {
                    assert_eq!(snapshot[2], 0);
                    assert_eq!(snapshot[3] & 0xf000_0000, 0x6000_0000);
                }
            }
        }
    }
    std::println!("SECRET_DIFFERENCE: 262144 pairs/accumulators; cleanup PASS");
}

#[test]
fn readonly_and_writable_guarded_byte_edges() -> std::io::Result<()> {
    let mut left = guard::Pages::new()?;
    let mut right = guard::Pages::new()?;
    let mut output = guard::Pages::new()?;
    for end in [false, true] {
        left.bytes::<1>(end)[0] = 0xa5;
        right.bytes::<1>(end)[0] = 0x69;
    }
    left.readonly()?;
    right.readonly()?;
    for l in [false, true] {
        for r in [false, true] {
            for o in [false, true] {
                let destination = output.bytes::<1>(o);
                destination[0] = 0x10;
                // SAFETY: Single readable/writable byte at independently guarded edges.
                unsafe {
                    difference::accumulate_byte(
                        destination.as_mut_ptr(),
                        left.read::<1>(l).as_ptr(),
                        right.read::<1>(r).as_ptr(),
                    )
                };
                assert_eq!(destination, &[0x10 | (0xa5 ^ 0x69)]);
                // SAFETY: Shared inputs may alias; destination remains disjoint.
                unsafe {
                    difference::accumulate_byte(
                        destination.as_mut_ptr(),
                        left.read::<1>(l).as_ptr(),
                        left.read::<1>(l).as_ptr(),
                    )
                };
                assert_eq!(destination, &[0x10 | (0xa5 ^ 0x69)]);
            }
        }
    }
    std::println!("SECRET_DIFFERENCE_BOUNDS: guarded edges and read-only aliases PASS");
    Ok(())
}
