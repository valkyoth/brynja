extern crate std;
use super::xor;
#[path = "../../src/guard_memory.rs"]
mod guard;

unsafe fn observe(
    destination: *mut u8,
    source: *const u8,
    right: u32,
    left: u32,
    mask: u32,
    snapshot: &mut [u64; 4],
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SysV borrowed pointers/public metadata; snapshot before Rust resumes.
    unsafe {
        core::arch::asm!(
            "call r13", "mov [r12 + 8], rax", "mov [r12 + 16], rcx",
            in("r13") xor::xor_bits as super::Kernel, in("r12") snapshot.as_mut_ptr(),
            in("rdi") destination, in("rsi") source, in("edx") right, in("ecx") left, in("r8d") mask,
            clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: AAPCS64 borrowed pointers/public metadata; immediate working-register snapshot.
    unsafe {
        core::arch::asm!(
            "blr x21", "str x5, [x20, #8]", "str x6, [x20, #16]",
            in("x21") xor::xor_bits as super::Kernel, in("x20") snapshot.as_mut_ptr(),
            in("x0") destination, in("x1") source, in("w2") right, in("w3") left, in("w4") mask,
            clobber_abi("C"),
        );
    }
}

#[test]
fn every_bit_range_and_source_value_matches_and_clears() -> Result<(), super::SecretBitRangeError> {
    let mut cases = 0;
    for source in 0..=u8::MAX {
        for count in 1_u8..=8 {
            for right in 0..=8 - count {
                for left in 0..=8 - count {
                    for initial in [0, !source] {
                        let mask = (1_u32 << count) - 1;
                        let expected = initial
                            ^ u8::try_from(((u32::from(source) >> right) & mask) << left)
                                .unwrap_or(0);
                        let mut region = [0xa5, initial, 0x69];
                        let mut snapshot = [u64::MAX; 4];
                        // SAFETY: Disjoint bytes and enumerated valid public metadata.
                        unsafe {
                            observe(
                                &mut region[1],
                                &source,
                                u32::from(right),
                                u32::from(left),
                                mask,
                                &mut snapshot,
                            )
                        };
                        assert_eq!(region, [0xa5, expected, 0x69]);
                        assert_eq!(snapshot, [u64::MAX, 0, 0, u64::MAX]);
                        region[1] = initial;
                        brynja_core::xor_secret_byte_bits(
                            &mut region[1],
                            &source,
                            right,
                            count,
                            left,
                        )?;
                        assert_eq!(region, [0xa5, expected, 0x69]);
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 104448);
    std::println!("SECRET_XOR: 104448 input/range cases; working-register cleanup PASS");
    Ok(())
}

#[test]
fn guarded_source_and_destination_require_exact_byte_access() -> std::io::Result<()> {
    let mut source = guard::Pages::new()?;
    let mut destination = guard::Pages::new()?;
    source.bytes::<1>(false)[0] = 0x96;
    source.bytes::<1>(true)[0] = 0x69;
    source.readonly()?;
    for source_end in [false, true] {
        for destination_end in [false, true] {
            for initial in 0..=u8::MAX {
                let out = destination.bytes::<1>(destination_end);
                out[0] = initial;
                let input = source.read::<1>(source_end);
                // SAFETY: Separate guarded source/destination bytes, source is read-only.
                unsafe { xor::xor_bits(out.as_mut_ptr(), input.as_ptr(), 1, 2, 15) };
                assert_eq!(out[0], initial ^ ((input[0] >> 1) & 15) << 2);
            }
        }
    }
    std::println!("SECRET_XOR_BOUNDS: all guarded byte-edge pairs PASS");
    Ok(())
}
