//! Package-external hosted startup, with no public detector injection.
#![forbid(unsafe_code)]
#[cfg(feature = "facade")]
use brynja::crypto::aes::execution::{Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey};
#[cfg(feature = "direct")]
use brynja_crypto::aes::execution::{Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey};
use brynja_crypto_cpu_std::aes::{
    Authority, Error, Health, Kernel, KernelError, Mode, Route, Unavailable,
};
use std::hint::black_box;

#[inline(never)]
fn startup(kernel: Kernel, mode: Mode) -> Result<Authority, Error> {
    Authority::new(kernel, mode)
}

fn main() {
    let corrupt = std::env::args().nth(1);
    assert!(
        corrupt.is_none()
            || matches!(
                corrupt.as_deref(),
                Some("expect-quarantined" | "expect-unavailable")
            )
    );
    for kernel in [Kernel::X86AesNi, Kernel::ArmAes] {
        let owner = startup(black_box(kernel), black_box(Mode::Portable)).unwrap();
        assert_eq!(owner.report().route, Route::PortableRequested);
        assert_eq!(owner.report().health, None);
        assert!(owner.kernel_authority().unwrap().is_none());
    }
    assert_eq!(
        startup(black_box(Kernel::X86AesNi), black_box(Mode::Require)).err(),
        Some(Error::Unavailable(Unavailable::WrongArchitecture))
    );
    let fallback = startup(black_box(Kernel::X86AesNi), black_box(Mode::Prefer)).unwrap();
    assert_eq!(
        fallback.report().route,
        Route::PortableFallback(Unavailable::WrongArchitecture)
    );
    assert_eq!(fallback.report().health, None);
    assert!(fallback.kernel_authority().unwrap().is_none());
    if corrupt.as_deref() == Some("expect-unavailable") {
        for _ in 0..2 {
            assert_eq!(
                startup(black_box(Kernel::ArmAes), black_box(Mode::Require)).err(),
                Some(Error::Unavailable(Unavailable::MissingFeaturesOrOsState))
            );
            let owner = startup(black_box(Kernel::ArmAes), black_box(Mode::Prefer)).unwrap();
            assert_eq!(
                owner.report().route,
                Route::PortableFallback(Unavailable::MissingFeaturesOrOsState)
            );
            assert_eq!(owner.report().health, None);
            assert!(owner.kernel_authority().unwrap().is_none());
        }
        println!("AES_ARM_HOSTED_STARTUP_UNAVAILABLE");
        return;
    }
    for mode in [Mode::Require, Mode::Prefer] {
        let owner = startup(black_box(Kernel::ArmAes), black_box(mode)).unwrap();
        assert_eq!(owner.report().route, Route::Accelerated);
        if corrupt.is_some() {
            assert_eq!(owner.report().health, Some(Health::Quarantined));
            assert_eq!(
                owner.kernel_authority().err(),
                Some(Error::Kernel(KernelError::Quarantined))
            );
            continue;
        }
        assert_eq!(owner.report().health, Some(Health::Healthy));
        let authority = owner
            .kernel_authority()
            .unwrap()
            .expect("required ARM acceleration");
        assert_eq!(authority.report().generation, 2);
        macro_rules! exercise {
            ($key:ident, $k:literal, $s:literal) => {{
                let raw = black_box([0x5a; $k]);
                let plain = black_box([0x6b; 16]);
                let mut schedule = [0; $s];
                let mut output = [0; 16];
                let key = $key::new(black_box(authority), &raw, &mut schedule).unwrap();
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
        assert_eq!(owner.report().route, Route::Accelerated);
        assert_eq!(
            owner.kernel_authority().err(),
            Some(Error::Kernel(KernelError::Quarantined))
        );
    }
    println!(
        "{}",
        if corrupt.is_some() {
            "AES_ARM_HOSTED_STARTUP_QUARANTINED"
        } else {
            "AES_ARM_HOSTED_STARTUP_PASS"
        }
    );
}
