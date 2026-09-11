use super::*;

#[test]
fn wrong_architecture_keccak_never_acquires_hosted_authority() {
    for (kernel, matching_architecture) in [
        (host::Kernel::ArmKeccak, cfg!(target_arch = "aarch64")),
        (host::Kernel::X86Keccak, cfg!(target_arch = "x86_64")),
    ] {
        if matching_architecture {
            continue;
        }
        assert!(matches!(
            host::Authority::new(kernel, Mode::Require),
            Err(host::Error::Unavailable(Unavailable::WrongArchitecture))
        ));
        let preferred = host::Authority::new(kernel, Mode::Prefer);
        assert!(matches!(preferred, Ok(owner) if owner.report().route
            == Route::PortableFallback(Unavailable::WrongArchitecture)));
    }
}

#[test]
fn hosted_sponge_error_never_authorizes_portable_fallback() {
    for error in [
        host::Error::Kernel(host::KernelError::Quarantined),
        host::Error::Kernel(host::KernelError::NotReady),
        host::Error::Unavailable(Unavailable::MissingMigrationGuarantee),
    ] {
        assert!(
            matches!(execution_from_session(Err(error)), Err(Error::Hosted(actual)) if actual == error)
        );
    }
}

#[test]
fn portable_sponge_all_constructors_and_selection() -> Result<(), Box<dyn std::error::Error>> {
    let owner = Sponge::new(Mode::Portable)?;
    assert_eq!(owner.report().route, Route::PortableRequested);
    assert_eq!(
        owner.sha3_224()?.finalize()?.digest,
        brynja_hash_sha3::sha3_224(b"").map_err(|_| "SHA3-224")?
    );
    assert_eq!(
        owner.sha3_256()?.finalize()?.digest,
        brynja_hash_sha3::sha3_256(b"").map_err(|_| "SHA3-256")?
    );
    assert_eq!(
        owner.sha3_384()?.finalize()?.digest,
        brynja_hash_sha3::sha3_384(b"").map_err(|_| "SHA3-384")?
    );
    assert_eq!(
        owner.sha3_512()?.finalize()?.digest,
        brynja_hash_sha3::sha3_512(b"").map_err(|_| "SHA3-512")?
    );
    let empty = Public::new(b"");
    let bits =
        PublicBits::new(brynja_hash_sha3::Fips202BitString::new(b"", 0).map_err(|_| "bits")?);
    let mut expected = [0; 8];
    let mut actual = [0; 8];
    owner.shake128()?.finalize_xof()?.squeeze(&mut expected)?;
    owner
        .cshake128(empty, empty)?
        .finalize_xof()?
        .squeeze(&mut actual)?;
    assert_eq!(actual, expected);
    owner
        .cshake128_bits(bits, bits)?
        .finalize_xof()?
        .squeeze(&mut actual)?;
    assert_eq!(actual, expected);
    owner.shake256()?.finalize_xof()?.squeeze(&mut expected)?;
    owner
        .cshake256(empty, empty)?
        .finalize_xof()?
        .squeeze(&mut actual)?;
    assert_eq!(actual, expected);
    owner
        .cshake256_bits(bits, bits)?
        .finalize_xof()?
        .squeeze(&mut actual)?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn hosted_preference_and_quarantine_never_silently_change_route()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = Sponge::new(Mode::Prefer)?;
    let route = owner.report().route;
    let mut reader = owner
        .cshake128(Public::new(b""), Public::new(b"S"))?
        .finalize_xof()?;
    let mut output = [0xa5; 8];
    owner.quarantine();
    if route == Route::Accelerated {
        assert!(reader.squeeze(&mut output).is_err());
        assert!(owner.execution().is_err());
        assert_eq!(output, [0xa5; 8]);
    } else {
        assert!(matches!(route, Route::PortableFallback(_)));
        assert!(Sponge::new(Mode::Require).is_err());
        reader.squeeze(&mut output)?;
    }
    Ok(())
}
