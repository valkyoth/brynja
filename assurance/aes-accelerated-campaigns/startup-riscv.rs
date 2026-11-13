//! Package-external startup boundary; no production inlining changes.
#![forbid(unsafe_code)]
#[cfg(feature = "facade")]
use brynja::crypto::aes::execution::{Authority, Health, Kernel};
#[cfg(feature = "direct")]
use brynja_crypto::aes::execution::{Authority, Health, Kernel};
use std::hint::black_box;

#[cfg(feature = "facade")]
use brynja::crypto::aes::execution::{Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey};
#[cfg(feature = "direct")]
use brynja_crypto::aes::execution::{Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey};

#[inline(never)]
fn startup(kernel: Kernel) -> Option<Authority> {
    Authority::new(kernel).ok()
}

fn main() {
    // Test all three enum values through an opaque package-external boundary.
    assert!(startup(black_box(Kernel::X86AesNi)).is_none());
    assert!(startup(black_box(Kernel::ArmAes)).is_none());
    let owner = startup(black_box(Kernel::RiscVScalarAes)).expect("evidence-only RISC-V bundle");
    let report = owner.report();
    assert_eq!(report.generation, 2);
    // A corrupted-answer executable must retain a quarantined owner, not fail
    // pre-admission, become healthy, or silently select a different backend.
    let corrupt = std::env::args().nth(1);
    assert!(corrupt.is_none() || corrupt.as_deref() == Some("expect-quarantined"));
    if corrupt.is_some() {
        assert_eq!(report.health, Health::Quarantined);
        assert!(owner.session().is_err());
        println!("AES_RISCV_STARTUP_QUARANTINED");
    } else {
        assert_eq!(report.health, Health::Healthy);
        assert!(owner.session().is_ok());
        // Keep round kernels shared with real caller-key operations under LTO;
        // a startup-only executable could specialize them to public KAT data.
        macro_rules! exercise {
            ($key:ident, $k:literal, $s:literal) => {{
                let raw = black_box([0x5a; $k]);
                let plain = black_box([0x6b; 16]);
                let mut schedule = [0; $s];
                let mut output = [0; 16];
                let key = $key::new(black_box(&owner), &raw, &mut schedule).unwrap();
                let mut cipher = [0; 16];
                cipher.copy_from_slice(key.encrypt_block(&plain, &mut output).unwrap().expose());
                assert_eq!(
                    key.decrypt_block(&cipher, &mut output).unwrap().expose(),
                    &plain
                );
                key.clear();
                assert_eq!(schedule, [0; $s]);
                assert_eq!(output, [0; 16]);
            }};
        }
        exercise!(Aes128ExpandedKey, 16, 176);
        exercise!(Aes192ExpandedKey, 24, 208);
        exercise!(Aes256ExpandedKey, 32, 240);
        owner.quarantine();
        assert_eq!(owner.report().generation, 3);
        assert!(owner.session().is_err());
        println!("AES_RISCV_STARTUP_PASS");
    }
}
