extern crate std;
use super::predicate;
#[path = "../../src/guard_memory.rs"]
mod guard;

unsafe fn observe(byte: *const u8, mask: u8, snapshot: &mut [u64; 5]) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SysV borrowed byte/public mask; immediate register/flags snapshot.
    unsafe {
        core::arch::asm!(
            "call r13", "mov [r12 + 8], r10", "mov [r12 + 16], rax",
            "pushfq", "pop r11", "mov [r12 + 24], r11",
            in("r13") predicate::mask_is_zero as super::Kernel,
            in("r12") snapshot.as_mut_ptr(), in("rdi") byte,
            in("esi") u32::from(mask), clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 shared byte/public mask; snapshot before Rust resumes.
    unsafe {
        core::arch::asm!(
            "blr x21", "str x4, [x20, #8]", "str x0, [x20, #16]",
            "mrs x9, nzcv", "str x9, [x20, #24]",
            in("x21") predicate::mask_is_zero as super::Kernel,
            in("x20") snapshot.as_mut_ptr(), in("x0") byte,
            in("w1") u32::from(mask), clobber_abi("C"),
        );
    }
}

#[test]
fn exhaustive_predicates_erase_original_and_retain_only_boolean() {
    for byte in 0..=u8::MAX {
        for mask in 0..=u8::MAX {
            let region = [0xa5, byte, 0x69];
            let mut snapshot = [u64::MAX; 5];
            // SAFETY: Exactly one shared live byte, with live neighboring bytes.
            unsafe { observe(&region[1], mask, &mut snapshot) };
            assert_eq!(snapshot[0], u64::MAX);
            assert_eq!(snapshot[1], 0);
            assert_eq!(snapshot[2], u64::from(byte & mask == 0));
            assert_eq!(snapshot[4], u64::MAX);
            #[cfg(target_arch = "x86_64")]
            assert_eq!(snapshot[3] & 0x8c5, 0x44); // OF/SF/ZF/PF/CF after xor.
            #[cfg(target_arch = "aarch64")]
            assert_eq!(snapshot[3] & 0xf000_0000, 0x6000_0000);
            assert_eq!(region, [0xa5, byte, 0x69]);
            assert_eq!(
                brynja_core::secret_byte_mask_is_zero(&region[1], mask),
                byte & mask == 0
            );
        }
    }
    std::println!("SECRET_PREDICATE: 65536 byte/mask cases; cleanup and normalized result PASS");
}

#[test]
fn guarded_readonly_edges_allow_only_one_byte_load() -> std::io::Result<()> {
    let mut pages = guard::Pages::new()?;
    pages.bytes::<1>(false)[0] = 0x81;
    pages.bytes::<1>(true)[0] = 0x7e;
    pages.readonly()?;
    for end in [false, true] {
        let byte = pages.read::<1>(end);
        for mask in 0..=u8::MAX {
            // SAFETY: Read-only single byte adjacent to an inaccessible page.
            let result = unsafe { predicate::mask_is_zero(byte.as_ptr(), mask) };
            assert_eq!(result, u32::from(byte[0] & mask == 0));
            assert_eq!(byte[0], if end { 0x7e } else { 0x81 });
        }
    }
    std::println!("SECRET_PREDICATE_BOUNDS: both read-only guarded edges PASS");
    Ok(())
}
