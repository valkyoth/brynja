use super::*;

#[test]
fn prefix_encoding_errors_do_not_claim_length_overflow() -> Result<(), crate::Fips202BitsError> {
    let empty = Fips202BitString::new(&[], 0)?;
    let name = Fips202BitString::new(b"N", 8)?;
    for rate in [0, 1, 135, 137, 167, 169, usize::MAX] {
        let mut called = false;
        let result = absorb_cshake_prefix(rate, name, empty, |_| {
            called = true;
            Ok(())
        })
        .map_err(|()| prefix_error(None));
        assert_eq!(result, Err(Error::PrefixEncoding));
        assert!(!called);
    }
    for error in [
        Error::LengthOverflow,
        Error::Backend(brynja_crypto_cpu::static_execution::Error::Quarantined),
    ] {
        let mut captured = None;
        let result = absorb_cshake_prefix(168, name, empty, |_| {
            captured = Some(error);
            Err(())
        })
        .map_err(|()| prefix_error(captured));
        assert_eq!(result, Err(error));
    }
    Ok(())
}

#[test]
fn prefix_and_padding_faults_preserve_typed_errors() {
    for budget in 0..3 {
        // Large N forces multiple setup permutations; no owner may escape on error.
        assert!(matches!(
            Cshake128::new(
                Execution::fault_after(budget),
                Public::new(&[1; 700]),
                Public::new(b"S")
            ),
            Err(Error::Backend(
                brynja_crypto_cpu::static_execution::Error::Quarantined
            ))
        ));
    }
    let state = Cshake256::new(
        Execution::fault_after(1),
        Public::new(&[]),
        Public::new(b"S"),
    );
    assert!(matches!(
        state.and_then(Cshake256::finalize_xof),
        Err(Error::Backend(_))
    ));
}

#[test]
fn cshake_faults_keep_public_output_atomic() {
    let mut output = [0xa5; 500];
    let mut scratch = [0; 500];
    let result = Cshake128::hash_with_scratch(
        Execution::fault_after(3),
        Public::new(b"X"),
        Public::new(&[]),
        Public::new(b"S"),
        &mut output,
        &mut scratch,
    );
    assert!(matches!(result, Err(Error::Backend(_))));
    assert_eq!(output, [0xa5; 500]);
}

#[test]
fn setup_counts_and_small_scratch_are_exact() -> Result<(), Error> {
    let mut state = Cshake128::new(Execution::portable(), Public::new(&[]), Public::new(b"S"))?;
    assert_eq!(state.setup_bytes(), 168);
    assert_eq!(state.message_bytes(), 0);
    assert_eq!(state.report().absorb_permutations, 1);
    assert_eq!(
        state.check_additional_bytes(u128::MAX),
        Err(Error::LengthOverflow)
    );
    state.update(Public::new(b"abc"))?;
    assert_eq!(state.message_bytes(), 3);
    let mut reader = state.finalize_xof()?;
    let mut output = [0xa5; 169];
    assert_eq!(reader.squeeze(&mut output), Err(Error::ScratchTooSmall));
    assert_eq!(reader.output_bytes(), 0);
    assert_eq!(output, [0xa5; 169]);
    reader.squeeze_with_scratch(&mut output, &mut [0; 169])?;
    assert_eq!(reader.output_bytes(), 169);
    Ok(())
}
