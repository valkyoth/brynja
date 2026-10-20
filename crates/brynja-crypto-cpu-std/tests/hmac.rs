//! Hosted HMAC selection is explicit; accelerated failures cannot become fallback.
#![cfg(feature = "hmac-execution")]
use brynja_crypto_cpu_std::execution::{Authority, HmacError, Kernel, Mode, Route};
use brynja_mac_hmac::{self as mac, execution::Algorithm};

#[test]
fn portable_selection_does_not_process_keys() -> Result<(), HmacError> {
    for kernel in [Kernel::ArmSha256, Kernel::ArmSha512, Kernel::ArmKeccak] {
        let owner = Authority::new(kernel, Mode::Portable).map_err(HmacError::Hosted)?;
        assert_eq!(owner.report().route, Route::PortableRequested);
        assert!(owner.hmac::<mac::Sha256>(b"key")?.is_none());
        // No key/tag admission is claimed until the caller constructs portable HMAC.
        assert!(
            owner
                .hmac_with_tag_length::<mac::Sha512T<0>>(b"", 0)?
                .is_none()
        );
        owner.quarantine();
        assert!(owner.hmac::<mac::Sha3_256>(b"key")?.is_none());
    }
    Ok(())
}

#[test]
fn unsupported_host_never_mints_runtime_authority() {
    let wrong = if cfg!(target_arch = "aarch64") {
        Kernel::X86Sha256
    } else {
        Kernel::ArmSha256
    };
    let owner = Authority::new(wrong, Mode::Prefer);
    assert!(matches!(owner, Ok(ref value) if value.report().route != Route::Accelerated));
    assert!(Authority::new(wrong, Mode::Require).is_err());
}

fn compare<A: for<'a> Algorithm<'a>>(kernel: Kernel) -> Result<(), HmacError> {
    let owner = Authority::new(kernel, Mode::Require).map_err(HmacError::Hosted)?;
    assert_eq!(owner.report().route, Route::Accelerated);
    let key = [0x5a; 257];
    let mut expected = vec![0; A::TAG_BYTES];
    let _ = mac::Hmac::<A>::authenticate(&key, b"hosted message", &mut expected)
        .map_err(HmacError::Mac)?;
    let Some(mut stream) = owner.hmac::<A>(&key)? else {
        return Err(HmacError::Mac(mac::Error::ExecutionFailed));
    };
    stream.update(b"hosted ").map_err(HmacError::Mac)?;
    stream.update(b"message").map_err(HmacError::Mac)?;
    let mut actual = vec![0; A::TAG_BYTES];
    let tag = stream.finalize_tag(&mut actual).map_err(HmacError::Mac)?;
    assert_eq!(tag.as_bytes(), expected);
    assert_eq!(tag.bit_len(), A::TAG_BITS);
    let Some(mut verify) = owner.hmac_with_tag_length::<A>(&key, 16)? else {
        return Err(HmacError::Mac(mac::Error::ExecutionFailed));
    };
    verify.update(b"hosted message").map_err(HmacError::Mac)?;
    let candidate = expected
        .get(..16)
        .ok_or(HmacError::Mac(mac::Error::TagLength))?;
    assert!(
        verify
            .verify(candidate)
            .map_err(HmacError::Mac)?
            .expose_public()
    );
    let Some(mut live) = owner.hmac::<A>(&key)? else {
        return Err(HmacError::Mac(mac::Error::ExecutionFailed));
    };
    owner.quarantine();
    assert!(matches!(owner.hmac::<A>(&key), Err(HmacError::Hosted(_))));
    assert!(matches!(live.update(&[]), Err(mac::Error::Backend(_))));
    assert_eq!(
        live.update(b"never fallback"),
        Err(mac::Error::ExecutionFailed)
    );
    actual.fill(0xa5);
    assert!(live.finalize_secret(&mut actual).is_err());
    assert!(actual.iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
#[ignore = "requires a reviewed native AArch64 host with SHA2/SHA3/SHA512 availability"]
fn native_hosted_all_identities() -> Result<(), HmacError> {
    compare::<mac::Sha224>(Kernel::ArmSha256)?;
    compare::<mac::Sha256>(Kernel::ArmSha256)?;
    compare::<mac::Sha384>(Kernel::ArmSha512)?;
    compare::<mac::Sha512>(Kernel::ArmSha512)?;
    compare::<mac::Sha512_224>(Kernel::ArmSha512)?;
    compare::<mac::Sha512_256>(Kernel::ArmSha512)?;
    compare::<mac::Sha512T<129>>(Kernel::ArmSha512)?;
    compare::<mac::Sha512T<511>>(Kernel::ArmSha512)?;
    compare::<mac::Sha3_224>(Kernel::ArmKeccak)?;
    compare::<mac::Sha3_256>(Kernel::ArmKeccak)?;
    compare::<mac::Sha3_384>(Kernel::ArmKeccak)?;
    compare::<mac::Sha3_512>(Kernel::ArmKeccak)?;
    let owner = Authority::new(Kernel::ArmSha256, Mode::Prefer).map_err(HmacError::Hosted)?;
    assert!(matches!(
        owner.hmac::<mac::Sha3_256>(b"key"),
        Err(HmacError::Mac(_))
    ));
    assert!(matches!(
        owner.hmac_with_tag_length::<mac::Sha256>(b"key", 1),
        Err(HmacError::Mac(mac::Error::TagLength))
    ));
    owner.quarantine();
    assert!(matches!(
        owner.hmac::<mac::Sha256>(b"key"),
        Err(HmacError::Hosted(_))
    ));
    Ok(())
}
