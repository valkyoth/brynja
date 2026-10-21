//! Hosted HMAC selection is explicit; accelerated failures cannot become fallback.
#![cfg(feature = "hmac-execution")]
use brynja_crypto_cpu_std::execution::{Authority, HmacError, HmacSelection, Kernel, Mode, Route};
use brynja_mac_hmac::{self as mac, execution::Algorithm};

#[test]
fn portable_selection_does_not_process_keys() -> Result<(), HmacError> {
    for kernel in [Kernel::ArmSha256, Kernel::ArmSha512, Kernel::ArmKeccak] {
        let owner = Authority::new(kernel, Mode::Portable).map_err(HmacError::Hosted)?;
        assert_eq!(owner.report().route, Route::PortableRequested);
        assert!(matches!(
            owner.hmac::<mac::Sha256>(b"key")?,
            HmacSelection::Portable(_)
        ));
        assert!(matches!(
            owner.hmac_with_tag_length::<mac::Sha512T<0>>(b"", 0),
            Err(HmacError::Mac(mac::Error::AlgorithmParameter))
        ));
        for width in [0, 1, 15, 33, usize::MAX] {
            assert!(matches!(
                owner.hmac_with_tag_length::<mac::Sha256>(b"", width),
                Err(HmacError::Mac(mac::Error::TagLength))
            ));
        }
        assert!(matches!(
            owner.hmac_with_tag_length::<mac::Sha512T<129>>(b"", 17),
            Err(HmacError::Mac(mac::Error::TagLength))
        ));
        for width in [None, Some(16), Some(17), Some(32)] {
            let selected = match width {
                None => owner.hmac::<mac::Sha256>(b"unprocessed selection key")?,
                Some(n) => {
                    owner.hmac_with_tag_length::<mac::Sha256>(b"unprocessed selection key", n)?
                }
            };
            let HmacSelection::Portable(policy) = selected else {
                return Err(HmacError::Mac(mac::Error::ExecutionFailed));
            };
            let mut actual = vec![0; width.unwrap_or(32)];
            let mut expected = actual.clone();
            let stream = policy.start(b"actual key").map_err(HmacError::Mac)?;
            let reference = match width {
                None => mac::Hmac::<mac::Sha256>::new(b"actual key"),
                Some(n) => mac::Hmac::<mac::Sha256>::with_tag_length(b"actual key", n),
            }
            .map_err(HmacError::Mac)?;
            let _ = stream.finalize_tag(&mut actual).map_err(HmacError::Mac)?;
            let _ = reference
                .finalize_tag(&mut expected)
                .map_err(HmacError::Mac)?;
            assert_eq!(actual, expected);
        }
        let HmacSelection::Portable(policy) = owner.hmac::<mac::Sha512T<129>>(b"")? else {
            return Err(HmacError::Mac(mac::Error::ExecutionFailed));
        };
        let mut partial = [0; 17];
        assert_eq!(
            policy
                .start(b"key")
                .map_err(HmacError::Mac)?
                .finalize_tag(&mut partial)
                .map_err(HmacError::Mac)?
                .bit_len(),
            129
        );
        owner.quarantine();
        assert!(matches!(
            owner.hmac::<mac::Sha3_256>(b"key")?,
            HmacSelection::Portable(_)
        ));
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
    if cfg!(target_arch = "x86_64") {
        // Current-core features do not establish the hosted migration contract.
        for kernel in [Kernel::X86Sha256, Kernel::X86Sha512, Kernel::X86Keccak] {
            assert!(matches!(Authority::new(kernel, Mode::Prefer),
                Ok(ref owner) if matches!(owner.report().route, Route::PortableFallback(_))
                    && matches!(owner.hmac::<mac::Sha256>(b"key"), Ok(HmacSelection::Portable(_)))));
            assert!(matches!(
                Authority::new(kernel, Mode::Require),
                Err(brynja_crypto_cpu_std::execution::Error::Unavailable(_))
            ));
        }
    }
}

fn compare<A: for<'a> Algorithm<'a>>(kernel: Kernel, mode: Mode) -> Result<(), HmacError> {
    let owner = Authority::new(kernel, mode).map_err(HmacError::Hosted)?;
    assert_eq!(owner.report().route, Route::Accelerated);
    let key = [0x5a; 257];
    let mut expected = vec![0; A::TAG_BYTES];
    let _ = mac::Hmac::<A>::authenticate(&key, b"hosted message", &mut expected)
        .map_err(HmacError::Mac)?;
    let HmacSelection::Accelerated(mut stream) = owner.hmac::<A>(&key)? else {
        return Err(HmacError::Mac(mac::Error::ExecutionFailed));
    };
    stream.update(b"hosted ").map_err(HmacError::Mac)?;
    stream.update(b"message").map_err(HmacError::Mac)?;
    let mut actual = vec![0; A::TAG_BYTES];
    let tag = stream.finalize_tag(&mut actual).map_err(HmacError::Mac)?;
    assert_eq!(tag.as_bytes(), expected);
    assert_eq!(tag.bit_len(), A::TAG_BITS);
    let HmacSelection::Accelerated(mut verify) = owner.hmac_with_tag_length::<A>(&key, 16)? else {
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
    let HmacSelection::Accelerated(mut reject) = owner.hmac_with_tag_length::<A>(&key, 16)? else {
        return Err(HmacError::Mac(mac::Error::ExecutionFailed));
    };
    reject.update(b"hosted message").map_err(HmacError::Mac)?;
    let mut changed = candidate.to_vec();
    let first = changed
        .first_mut()
        .ok_or(HmacError::Mac(mac::Error::TagLength))?;
    *first ^= 1;
    assert!(
        !reject
            .verify(&changed)
            .map_err(HmacError::Mac)?
            .expose_public()
    );
    // Invalid policy is an error on an admitted route, even under Prefer.
    assert!(matches!(
        owner.hmac_with_tag_length::<A>(&key, 1),
        Err(HmacError::Mac(mac::Error::TagLength))
    ));
    for secret in [false, true] {
        let HmacSelection::Accelerated(stream) = owner.hmac::<A>(&key)? else {
            return Err(HmacError::Mac(mac::Error::ExecutionFailed));
        };
        let wrong_length = A::TAG_BYTES
            .checked_add(1)
            .ok_or(HmacError::Mac(mac::Error::ExecutionFailed))?;
        let mut wrong = vec![0x77; wrong_length];
        let result = if secret {
            stream.finalize_secret(&mut wrong).map(|_| ())
        } else {
            stream.finalize_tag(&mut wrong).map(|_| ())
        };
        assert_eq!(result, Err(mac::Error::TagLength));
        assert!(
            wrong
                .iter()
                .all(|byte| *byte == if secret { 0 } else { 0x77 })
        );
    }
    let HmacSelection::Accelerated(mut live) = owner.hmac::<A>(&key)? else {
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
#[ignore = "requires explicit native route selection; run scripts/hmac/check-hmac-hosted-native.py"]
fn native_hosted_all_identities() -> Result<(), HmacError> {
    let route = std::env::var("BRYNJA_HMAC_HOSTED_KERNEL")
        .map_err(|_| HmacError::Mac(mac::Error::ExecutionFailed))?;
    // Generic x86 hosted authority deliberately cannot establish migration.
    if !cfg!(target_arch = "aarch64") {
        return Err(HmacError::Mac(mac::Error::ExecutionFailed));
    }
    let (kernel, count) = match route.as_str() {
        "sha256" => (Kernel::ArmSha256, 2),
        "sha512" => (Kernel::ArmSha512, 6),
        "keccak" => (Kernel::ArmKeccak, 4),
        _ => return Err(HmacError::Mac(mac::Error::ExecutionFailed)),
    };
    for mode in [Mode::Require, Mode::Prefer] {
        match route.as_str() {
            "sha256" => {
                compare::<mac::Sha224>(kernel, mode)?;
                compare::<mac::Sha256>(kernel, mode)?;
            }
            "sha512" => {
                compare::<mac::Sha384>(kernel, mode)?;
                compare::<mac::Sha512>(kernel, mode)?;
                compare::<mac::Sha512_224>(kernel, mode)?;
                compare::<mac::Sha512_256>(kernel, mode)?;
                compare::<mac::Sha512T<129>>(kernel, mode)?;
                compare::<mac::Sha512T<511>>(kernel, mode)?;
            }
            "keccak" => {
                compare::<mac::Sha3_224>(kernel, mode)?;
                compare::<mac::Sha3_256>(kernel, mode)?;
                compare::<mac::Sha3_384>(kernel, mode)?;
                compare::<mac::Sha3_512>(kernel, mode)?;
            }
            _ => return Err(HmacError::Mac(mac::Error::ExecutionFailed)),
        }
        let owner = Authority::new(kernel, mode).map_err(HmacError::Hosted)?;
        if route == "keccak" {
            assert!(matches!(
                owner.hmac::<mac::Sha256>(b"key"),
                Err(HmacError::Mac(_))
            ));
        } else {
            assert!(matches!(
                owner.hmac::<mac::Sha3_256>(b"key"),
                Err(HmacError::Mac(_))
            ));
        }
    }
    println!("HMAC_NATIVE_HOSTED: {route} {count} identities; Require and Prefer");
    Ok(())
}
