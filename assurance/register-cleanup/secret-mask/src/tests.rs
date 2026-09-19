extern crate std;
use super::mask;
#[path = "../../src/guard_memory.rs"]
mod guard;

unsafe fn observe(byte: *mut u8, keep: u8, set: u8, snapshot: &mut [u64; 3]) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SysV byte pointer/public masks; immediate caller-clobbered snapshot.
    unsafe {
        core::arch::asm!(
            "call r13", "mov [r12 + 8], rax",
            in("r13") mask::mask_byte as super::Kernel, in("r12") snapshot.as_mut_ptr(),
            in("rdi") byte, in("esi") u32::from(keep), in("edx") u32::from(set), clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 byte pointer/public masks; snapshot before Rust resumes.
    unsafe {
        core::arch::asm!(
            "blr x21", "str x4, [x20, #8]",
            in("x21") mask::mask_byte as super::Kernel, in("x20") snapshot.as_mut_ptr(),
            in("x0") byte, in("w1") u32::from(keep), in("w2") u32::from(set), clobber_abi("C"),
        );
    }
}

#[test]
fn all_byte_and_mask_values_preserve_canaries_and_erase_working_register() {
    let mut cases = 0;
    for input in 0..=u8::MAX {
        for value in 0..=u8::MAX {
            for (keep, set) in [(value, 0), (0xff, value), (value, value.rotate_left(1))] {
                let mut region = [0xa5, input, 0x69];
                let mut snapshot = [u64::MAX; 3];
                // SAFETY: Exact exclusively borrowed middle byte; both neighbors live.
                unsafe { observe(&mut region[1], keep, set, &mut snapshot) };
                assert_eq!(region, [0xa5, (input & keep) | set, 0x69]);
                assert_eq!(snapshot, [u64::MAX, 0, u64::MAX]);
                region[1] = input;
                brynja_core::apply_secret_byte_mask(&mut region[1], keep, set);
                assert_eq!(region, [0xa5, (input & keep) | set, 0x69]);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 196608);
    std::println!("SECRET_MASK: 196608 input/mask cases; working-register cleanup PASS");
}

#[test]
fn guard_page_edges_require_exact_byte_access() -> std::io::Result<()> {
    let mut pages = guard::Pages::new()?;
    for end in [false, true] {
        for input in 0..=u8::MAX {
            let byte = pages.bytes::<1>(end);
            byte[0] = input;
            // SAFETY: Single writable byte abutting a protected page.
            unsafe { mask::mask_byte(byte.as_mut_ptr(), 0xa5, 0x42) };
            assert_eq!(byte[0], (input & 0xa5) | 0x42);
            assert_eq!(pages.read::<1>(end)[0], (input & 0xa5) | 0x42);
        }
    }
    pages.readonly()?;
    std::println!("SECRET_MASK_BOUNDS: both guarded byte edges PASS");
    Ok(())
}
