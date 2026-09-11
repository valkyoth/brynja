//! Public execution ownership, framing, and fail-closed output contracts.
#![cfg(feature = "hardened-execution")]
use brynja_hash_tuple::{
    self as tuple, Fips202BitString, Fips202Output, TupleHashError as Error,
    TupleHashPublicDeclassification as Public, execution as cpu,
};

fn bits(bytes: &[u8], valid: u8) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bytes, valid).map_err(|_| Error::InvalidBitString)
}

#[test]
fn all_fixed_profiles_match_portable_for_bit_items_and_customization() -> Result<(), Error> {
    macro_rules! case {
        ($ordinary:ident, $hardened:ident) => {
            for valid in 1..=8 {
                let custom = bits(&[5], 3)?;
                let partial = bits(&[1], valid)?;
                let large = [0x95; 1025];
                let mut reference = tuple::$ordinary::new_bits(custom)?;
                let mut ordinary = cpu::$ordinary::new_bits(cpu::Mode::Portable, custom)?;
                let mut hardened = cpu::$hardened::new_bits(cpu::Mode::Prefer(None), custom)?;
                for item in [partial, bits(&large, 8)?, bits(&[], 0)?, partial] {
                    reference.push_item_bits(item)?;
                    ordinary.push_item_bits(item)?;
                    hardened.push_item_bits(item)?;
                }
                assert_eq!(ordinary.item_count(), 4);
                let mut expected = [0; 259];
                reference.finalize_bits(
                    Fips202Output::new(&mut expected, valid)
                        .map_err(|_| Error::InvalidBitString)?,
                )?;
                let mut actual = [0xa5; 259];
                let mut scratch = [0x5a; 300];
                ordinary.finalize_bits(&mut actual, valid, &mut scratch)?;
                assert_eq!(actual, expected);
                assert_eq!(scratch, [0; 300]);
                let secret = hardened.finalize_secret_bits(&mut actual, valid)?;
                assert_eq!(secret.expose(), expected);
                drop(secret);
                assert_eq!(actual, [0; 259]);
            }
        };
    }
    case!(TupleHash128, HardenedTupleHash128);
    case!(TupleHash256, HardenedTupleHash256);
    Ok(())
}

#[test]
fn all_xof_profiles_match_irregular_and_mixed_secret_public_output() -> Result<(), Error> {
    macro_rules! case {
        ($ordinary:ident, $hardened:ident) => {
            let mut reference = tuple::$ordinary::new(b"partition")?;
            let mut ordinary = cpu::$ordinary::new(cpu::Mode::Portable, b"partition")?;
            let mut hardened = cpu::$hardened::new(cpu::Mode::Portable, b"partition")?;
            for item in [bits(&[5], 3)?, bits(&[0xa5; 340], 8)?] {
                reference.push_item_bits(item)?;
                ordinary.push_item_bits(item)?;
                hardened.push_item_bits(item)?;
            }
            let mut expected = [0; 341];
            reference.finalize_xof()?.squeeze_final_bits(
                Fips202Output::new(&mut expected, 5).map_err(|_| Error::InvalidBitString)?,
            )?;
            let mut actual = [0xa5; 341];
            let mut reader = ordinary.finalize_xof()?;
            reader.squeeze(&mut actual[..7])?;
            reader.squeeze_with_scratch(&mut actual[7..340], &mut [0; 333])?;
            reader.squeeze_final_bits(&mut actual[340..], 5, &mut [0; 1])?;
            assert_eq!(actual, expected);
            let mut reader = hardened.finalize_xof()?;
            let secret = reader.squeeze_secret(&mut actual[..167])?;
            assert_eq!(secret.expose(), &expected[..167]);
            drop(secret);
            reader.squeeze_public_with_scratch(
                &mut actual[167..340],
                &mut [0; 173],
                Public::acknowledge(),
            )?;
            assert_eq!(reader.output_bits(), 340 * 8);
            let secret = reader.squeeze_final_bits_secret(&mut actual[340..], 5)?;
            assert_eq!(secret.expose(), &expected[340..]);
            drop(secret);
            assert_eq!(&actual[..167], &[0; 167]);
            assert_eq!(&actual[167..340], &expected[167..340]);
            assert_eq!(actual[340], 0);
            assert_eq!(ordinary.push_item(b"again"), Err(Error::StateConsumed));
            assert!(hardened.finalize_xof().is_err());
        };
    }
    case!(TupleHashXof128, HardenedTupleHashXof128);
    case!(TupleHashXof256, HardenedTupleHashXof256);
    Ok(())
}

#[test]
fn fragmented_item_bits_preserve_exact_tuple_boundaries() -> Result<(), Error> {
    let mut expected = [0; 32];
    tuple::tuple_hash128(&[&[0b1010_1101, 0x76], b"", b"tail"], b"", &mut expected)?;
    let mut state = cpu::TupleHash128::new(cpu::Mode::Portable, b"")?;
    let mut writer = state.begin_item(16)?;
    writer.update_bits(bits(&[0b101], 3)?)?;
    writer.update_bits(bits(&[0b10101], 5)?)?;
    writer.update(&[])?;
    writer.update(&[0x76])?;
    assert_eq!(writer.remaining_bits(), 0);
    writer.finish()?;
    state.begin_item(0)?.finish()?;
    state.push_item(b"tail")?;
    let mut actual = [0xa5; 32];
    state.finalize(&mut actual)?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn unfinished_overlong_dropped_and_forgotten_items_never_reopen() -> Result<(), Error> {
    for case in 0..4 {
        let mut state = cpu::HardenedTupleHash128::new(cpu::Mode::Portable, b"")?;
        let mut writer = state.begin_item(8)?;
        match case {
            0 => assert_eq!(writer.finish(), Err(Error::IncompleteItem)),
            1 => {
                assert_eq!(writer.update(b"too long"), Err(Error::MessageTooLong));
                drop(writer);
            }
            2 => drop(writer),
            _ => core::mem::forget(writer),
        }
        let mut output = [0xa5; 32];
        assert!(state.finalize_secret(&mut output).is_err());
        assert_eq!(output, [0; 32]);
    }
    Ok(())
}

#[test]
fn invalid_output_is_atomic_and_required_absence_is_an_error() -> Result<(), Error> {
    assert!(matches!(
        cpu::TupleHash128::new(cpu::Mode::Require(None), b""),
        Err(Error::AccelerationUnavailable)
    ));
    for valid in [0, 9, 255] {
        let mut output = [0xa5; 32];
        let mut scratch = [0x5a; 40];
        assert!(
            cpu::TupleHash128::new(cpu::Mode::Portable, b"")?
                .finalize_bits(&mut output, valid, &mut scratch)
                .is_err()
        );
        assert_eq!(output, [0xa5; 32]);
        assert_eq!(scratch, [0; 40]);
        assert!(
            cpu::HardenedTupleHash256::new(cpu::Mode::Portable, b"")?
                .finalize_secret_bits(&mut output, valid)
                .is_err()
        );
        assert_eq!(output, [0; 32]);
    }
    let mut state = cpu::HardenedTupleHashXof128::new(cpu::Mode::Portable, b"")?;
    let mut reader = state.finalize_xof()?;
    let mut output = [0xa5; 169];
    assert!(
        reader
            .squeeze_public(&mut output, Public::acknowledge())
            .is_err()
    );
    assert_eq!(output, [0xa5; 169]);
    assert!(reader.squeeze_secret(&mut output).is_err());
    assert_eq!(output, [0; 169]);
    Ok(())
}

#[test]
fn unwind_and_forgotten_reader_leave_the_parent_terminal() -> Result<(), Error> {
    let mut state = cpu::HardenedTupleHashXof128::new(cpu::Mode::Portable, b"")?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut writer = state.begin_item(16)?;
        writer.update(b"x")?;
        std::panic::resume_unwind(Box::new("writer unwind"));
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    }));
    assert!(outcome.is_err());
    assert!(state.finalize_xof().is_err());
    let mut state = cpu::TupleHashXof256::new(cpu::Mode::Portable, b"")?;
    core::mem::forget(state.finalize_xof()?);
    assert!(state.push_item(b"again").is_err());
    assert!(state.finalize_xof().is_err());
    Ok(())
}
