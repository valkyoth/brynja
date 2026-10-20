//! Explicit hardware differential and fail-closed lifecycle coverage.
#![cfg(feature = "hardened-execution")]
#[macro_use]
#[allow(dead_code)]
mod support;
mod bit_support;
use bit_support::BitCase;
use brynja_mac_hmac::{
    execution::{self, Authority, Kernel},
    *,
};

fn supported_architecture() -> bool {
    cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
}

fn exercise<A: BitCase + for<'a> execution::Algorithm<'a>>(kernel: Kernel) {
    let authority = require_ok!(Authority::new(kernel));
    for key_len in [0, 1, A::BLOCK_BYTES, A::BLOCK_BYTES.saturating_add(1), 257] {
        let key = vec![0x5a; key_len];
        for len in [0, 1, 55, 56, 111, 112, 128, 145, 513] {
            let message = vec![0x69; len];
            let mut expected = vec![0; A::TAG_BYTES];
            let _ = require_ok!(Hmac::<A>::authenticate(&key, &message, &mut expected));
            let mut accelerated = require_ok!(execution::Hmac::<A>::from_static(&authority, &key));
            assert_eq!(accelerated.kernel(), kernel);
            require_ok!(accelerated.update(&message));
            require_ok!(accelerated.update(&[]));
            let mut actual = vec![0; A::TAG_BYTES];
            let _: Tag<'_, A> = require_ok!(accelerated.finalize_tag(&mut actual));
            assert_eq!(actual, expected);
            let mut verify = require_ok!(execution::Hmac::<A>::from_static(&authority, &key));
            require_ok!(verify.update(&message));
            assert!(require_ok!(verify.verify(&expected)).expose_public());
            for valid in 1..=7 {
                let tail = if A::LOW_BITS { 1 } else { 0x80 };
                let mut bytes = message.clone();
                bytes.push(tail);
                let bits = require_some!(A::input(&bytes, valid));
                let _ = require_ok!(Hmac::<A>::authenticate_bits(&key, bits, &mut expected));
                let mut mac = require_ok!(execution::Hmac::<A>::from_static(&authority, &key));
                require_ok!(mac.update(&message));
                let last = [tail];
                let last_bits = require_some!(A::input(&last, valid));
                {
                    let secret: SecretTag<'_, A> =
                        require_ok!(mac.finalize_bits_secret(last_bits, &mut actual));
                    assert_eq!(secret.expose(), expected);
                    assert_eq!(secret.bit_len(), A::TAG_BITS);
                }
                assert!(actual.iter().all(|byte| *byte == 0));
                let mac = require_ok!(execution::Hmac::<A>::from_static_with_tag_length(
                    &authority, &key, 16
                ));
                assert!(
                    require_ok!(mac.verify_bits(bits, require_some!(expected.get(..16))))
                        .expose_public()
                );
            }
        }
    }
    // A rejected public destination is unchanged; a secret destination is cleared.
    let mut short = [0xa5; 1];
    let mac = require_ok!(execution::Hmac::<A>::from_static(&authority, b"key"));
    assert!(matches!(
        mac.finalize_tag(&mut short),
        Err(Error::TagLength)
    ));
    assert_eq!(short, [0xa5]);
    let mac = require_ok!(execution::Hmac::<A>::from_static(&authority, b"key"));
    assert!(matches!(
        mac.finalize_secret(&mut short),
        Err(Error::TagLength)
    ));
    assert_eq!(short, [0]);
    // Revocation must affect even empty updates and consume both retained states.
    let mut mac = require_ok!(execution::Hmac::<A>::from_static(&authority, b"key"));
    let public = require_ok!(execution::Hmac::<A>::from_static(&authority, b"key"));
    let secret = require_ok!(execution::Hmac::<A>::from_static(&authority, b"key"));
    authority.quarantine();
    assert!(matches!(mac.update(&[]), Err(Error::Backend(_))));
    assert_eq!(mac.update(b"no fallback"), Err(Error::ExecutionFailed));
    let mut output = vec![0xa5; A::TAG_BYTES];
    assert!(matches!(
        public.finalize_tag(&mut output),
        Err(Error::Backend(_))
    ));
    assert!(output.iter().all(|byte| *byte == 0xa5));
    assert!(matches!(
        secret.finalize_secret(&mut output),
        Err(Error::Backend(_))
    ));
    assert!(output.iter().all(|byte| *byte == 0));
    output.fill(0xa5);
    assert!(matches!(
        mac.finalize_secret(&mut output),
        Err(Error::ExecutionFailed)
    ));
    assert!(output.iter().all(|byte| *byte == 0));
    assert!(execution::Hmac::<A>::from_static(&authority, b"key").is_err());
}

#[test]
#[ignore = "requires real SHA-256 instructions and complete build-wide target features"]
fn native_sha256() {
    assert!(supported_architecture());
    #[cfg(target_arch = "x86_64")]
    let kernel = Kernel::X86Sha256;
    #[cfg(target_arch = "aarch64")]
    let kernel = Kernel::ArmSha256;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        exercise::<Sha224>(kernel);
        exercise::<Sha256>(kernel);
        let authority = require_ok!(Authority::new(kernel));
        assert!(execution::Hmac::<Sha512>::from_static(&authority, b"key").is_err());
        assert!(execution::Hmac::<Sha3_256>::from_static(&authority, b"key").is_err());
        assert!(matches!(
            execution::Hmac::<Sha512T<0>>::from_static(&authority, b"key"),
            Err(Error::AlgorithmParameter)
        ));
        assert!(matches!(
            execution::Hmac::<Sha256>::from_static_with_tag_length(&authority, b"key", 1),
            Err(Error::TagLength)
        ));
    }
}

#[test]
#[ignore = "requires real SHA-512 instructions (or explicitly identified emulation) and target features"]
fn native_sha512() {
    assert!(supported_architecture());
    #[cfg(target_arch = "x86_64")]
    let kernel = Kernel::X86Sha512;
    #[cfg(target_arch = "aarch64")]
    let kernel = Kernel::ArmSha512;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        exercise::<Sha384>(kernel);
        exercise::<Sha512>(kernel);
        exercise::<Sha512_224>(kernel);
        exercise::<Sha512_256>(kernel);
        exercise::<Sha512T<129>>(kernel);
        exercise::<Sha512T<511>>(kernel);
    }
}

#[test]
#[ignore = "requires real Keccak route instructions and complete build-wide target features"]
fn native_keccak() {
    assert!(supported_architecture());
    #[cfg(target_arch = "x86_64")]
    let kernel = Kernel::X86Keccak;
    #[cfg(target_arch = "aarch64")]
    let kernel = Kernel::ArmKeccak;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        exercise::<Sha3_224>(kernel);
        exercise::<Sha3_256>(kernel);
        exercise::<Sha3_384>(kernel);
        exercise::<Sha3_512>(kernel);
    }
}

#[test]
fn no_compiled_authority_means_no_acceleration() {
    #[cfg(all(target_arch = "x86_64", not(target_feature = "sha")))]
    assert!(Authority::new(Kernel::X86Sha256).is_err());
    #[cfg(all(target_arch = "aarch64", not(target_feature = "sha2")))]
    assert!(Authority::new(Kernel::ArmSha256).is_err());
}
