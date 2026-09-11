//! Public ownership, output, and failure contracts for selectable KMAC execution.
#![cfg(feature = "hardened-execution")]
use brynja_mac_kmac::{Fips202BitString, KmacError, KmacPublicDeclassification, execution as cpu};

#[test]
fn portable_execution_tags_match_and_outputs_are_transactional() -> Result<(), KmacError> {
    let key = [0x42; 32];
    let mut expected = [0; 257];
    let _tag = brynja_mac_kmac::kmac256(&key, b"message", b"domain", &mut expected)?;
    let mut state = cpu::Kmac256::new(cpu::Mode::Portable, &key, b"domain")?;
    assert!(state.report().is_none());
    state.update(b"mes")?;
    state.update(b"sage")?;
    let mut actual = [0xa5; 257];
    let mut scratch = [0x5a; 300];
    assert_eq!(
        state
            .finalize_tag_with_scratch(&mut actual, &mut scratch)?
            .as_bytes(),
        expected
    );
    assert_eq!(scratch, [0; 300]);
    let state = cpu::Kmac256::new(cpu::Mode::Portable, &key, b"")?;
    let mut scratch = [0x5a; 2];
    assert!(
        state
            .finalize_tag_with_scratch(&mut actual, &mut scratch)
            .is_err()
    );
    assert_eq!(actual, expected);
    assert_eq!(scratch, [0; 2]);
    Ok(())
}

#[test]
fn secret_errors_and_drop_clear_entire_destinations() -> Result<(), KmacError> {
    let key = [0x42; 32];
    let mut short = [0xa5; 1];
    assert!(
        cpu::Kmac256::new(cpu::Mode::Portable, &key, b"")?
            .finalize_secret(&mut short)
            .is_err()
    );
    assert_eq!(short, [0]);
    let mut output = [0xa5; 32];
    let bad = cpu::Kmac128::new(cpu::Mode::Portable, &key, b"")?.finalize_secret_bits(
        Fips202BitString::new(&[], 0).map_err(|_| KmacError::InvalidBitString)?,
        &mut output,
        9,
    );
    assert!(bad.is_err());
    drop(bad);
    assert_eq!(output, [0; 32]);
    let secret = cpu::Kmac128::new(cpu::Mode::Portable, &key, b"")?.finalize_secret(&mut output)?;
    assert_ne!(secret.expose(), &[0; 32]);
    drop(secret);
    assert_eq!(output, [0; 32]);
    Ok(())
}

#[test]
fn preferred_absence_is_portable_and_required_absence_fails() -> Result<(), KmacError> {
    let key = [0x42; 32];
    assert!(
        cpu::Kmac128::new(cpu::Mode::Prefer(None), &key, b"")?
            .report()
            .is_none()
    );
    assert!(matches!(
        cpu::Kmac128::new(cpu::Mode::Require(None), &key, b""),
        Err(KmacError::AccelerationUnavailable)
    ));
    assert!(matches!(
        cpu::Kmac128::new(cpu::Mode::Portable, &[], b""),
        Err(KmacError::KeyTooShort)
    ));
    Ok(())
}

#[test]
fn xof_reader_retains_source_and_cannot_be_reopened() -> Result<(), KmacError> {
    let key = [0x42; 32];
    let mut state = cpu::KmacXof128::new(cpu::Mode::Portable, &key, b"")?;
    state.update(b"message")?;
    let mut reader = state.finalize_xof()?;
    let mut output = [0xa5; 257];
    let secret = reader.squeeze_secret(&mut output)?;
    let mut expected = [0; 257];
    let reference = brynja_mac_kmac::kmacxof128_secret(&key, b"message", b"", &mut expected)?;
    assert_eq!(secret.expose(), reference.expose());
    drop(secret);
    assert_eq!(output, [0; 257]);
    assert_eq!(reader.output_bytes(), 257);
    drop(reader);
    assert_eq!(state.update(b""), Err(KmacError::StateConsumed));
    assert!(state.finalize_xof().is_err());
    let mut state = cpu::KmacXof128::new(cpu::Mode::Portable, &key, b"")?;
    core::mem::forget(state.finalize_xof()?);
    assert!(state.finalize_xof().is_err());
    assert_eq!(state.update(b""), Err(KmacError::StateConsumed));
    Ok(())
}

#[test]
fn failed_xof_public_read_preserves_output_and_terminates() -> Result<(), KmacError> {
    let key = [0x42; 32];
    let mut state = cpu::KmacXof256::new(cpu::Mode::Portable, &key, b"")?;
    let mut reader = state.finalize_xof()?;
    let mut output = [0xa5; 169];
    assert!(
        reader
            .squeeze_public(&mut output, KmacPublicDeclassification::acknowledge())
            .is_err()
    );
    assert_eq!(output, [0xa5; 169]);
    assert!(reader.squeeze_secret(&mut output).is_err());
    assert_eq!(output, [0; 169]);
    Ok(())
}

#[test]
fn verification_rejects_content_length_and_domain_substitution() -> Result<(), KmacError> {
    let key = [0x42; 32];
    let mut tag = [0; 32];
    let _tag = cpu::Kmac128::new(cpu::Mode::Portable, &key, b"domain")?.finalize_tag(&mut tag)?;
    assert!(
        cpu::Kmac128::new(cpu::Mode::Portable, &key, b"domain")?
            .verify(&tag)?
            .expose_public()
    );
    assert!(
        !cpu::Kmac128::new(cpu::Mode::Portable, &key, b"other")?
            .verify(&tag)?
            .expose_public()
    );
    let candidate = Fips202BitString::new(&tag, 8).map_err(|_| KmacError::InvalidBitString)?;
    assert!(
        cpu::Kmac128::new(cpu::Mode::Portable, &key, b"domain")?
            .verify_exact(candidate, 255)
            .is_err()
    );
    tag[0] ^= 1;
    assert!(
        !cpu::Kmac128::new(cpu::Mode::Portable, &key, b"domain")?
            .verify(&tag)?
            .expose_public()
    );
    tag[0] ^= 1;
    tag[31] ^= 1;
    assert!(
        !cpu::Kmac128::new(cpu::Mode::Portable, &key, b"domain")?
            .verify(&tag)?
            .expose_public()
    );
    Ok(())
}

#[test]
fn unwind_clears_secret_output_and_source_stays_terminal() -> Result<(), KmacError> {
    let key = [0x42; 32];
    let mut state = cpu::KmacXof128::new(cpu::Mode::Portable, &key, b"")?;
    let mut output = [0xa5; 32];
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut reader = state.finalize_xof()?;
        let _secret = reader.squeeze_secret(&mut output)?;
        std::panic::resume_unwind(Box::new("test unwind"));
        #[allow(unreachable_code)]
        Ok::<(), KmacError>(())
    }));
    assert!(outcome.is_err());
    assert_eq!(output, [0; 32]);
    assert_eq!(state.update(b""), Err(KmacError::StateConsumed));
    Ok(())
}
