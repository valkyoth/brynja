//! Public hardened FIPS 202 lifecycle and differential acceptance.

use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, HardenedFips202Construction, HardenedFips202State,
    HardenedSha3_224, HardenedSha3_256, HardenedSha3_384, HardenedSha3_512, HardenedSha3Error,
    HardenedShake128, HardenedShake128Reader, HardenedShake256, HardenedShake256Reader,
    Sha3PublicDeclassification, sha3_224, sha3_224_bits, sha3_256, sha3_256_bits, sha3_384,
    sha3_384_bits, sha3_512, sha3_512_bits, shake128, shake128_bits, shake256, shake256_bits,
};

macro_rules! fixed_public_matches {
    ($state:ty, $ordinary:ident, $length:expr) => {{
        let mut state = <$state>::new();
        state.update(b"a")?;
        state.update(b"bc")?;
        let mut output = [0_u8; $length];
        state.finalize_public(&mut output, Sha3PublicDeclassification::acknowledge())?;
        let expected = $ordinary(b"abc").map_err(|_| HardenedSha3Error::MessageTooLong)?;
        assert_eq!(output.as_slice(), expected.as_ref());
        Ok::<(), HardenedSha3Error>(())
    }};
}

macro_rules! fixed_secret_matches {
    ($state:ty, $ordinary:ident, $length:expr) => {{
        let mut destination = [0xa5_u8; $length];
        {
            let mut state = <$state>::new();
            state.update(b"abc")?;
            let output = state.finalize_secret(&mut destination)?;
            let expected = $ordinary(b"abc").map_err(|_| HardenedSha3Error::MessageTooLong)?;
            assert_eq!(output.expose(), expected.as_ref());
        }
        assert_eq!(destination, [0_u8; $length]);
        Ok::<(), HardenedSha3Error>(())
    }};
}

#[test]
fn every_fixed_identity_matches_the_ordinary_algorithm() -> Result<(), HardenedSha3Error> {
    fixed_public_matches!(HardenedSha3_224, sha3_224, 28)?;
    fixed_public_matches!(HardenedSha3_256, sha3_256, 32)?;
    fixed_public_matches!(HardenedSha3_384, sha3_384, 48)?;
    fixed_public_matches!(HardenedSha3_512, sha3_512, 64)?;
    Ok(())
}

#[test]
fn every_fixed_secret_output_transfers_and_clears() -> Result<(), HardenedSha3Error> {
    fixed_secret_matches!(HardenedSha3_224, sha3_224, 28)?;
    fixed_secret_matches!(HardenedSha3_256, sha3_256, 32)?;
    fixed_secret_matches!(HardenedSha3_384, sha3_384, 48)?;
    fixed_secret_matches!(HardenedSha3_512, sha3_512, 64)?;
    Ok(())
}

macro_rules! fixed_boundaries {
    ($state:ty, $ordinary:ident, $output:expr) => {{
        let mut input = [0_u8; 340];
        for (index, byte) in input.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or_default();
        }
        for length in [
            0, 1, 71, 72, 73, 103, 104, 105, 135, 136, 137, 143, 144, 145, 167, 168, 169, 339,
        ] {
            let message = input
                .get(..length)
                .ok_or(HardenedSha3Error::MessageTooLong)?;
            let expected = $ordinary(message).map_err(|_| HardenedSha3Error::MessageTooLong)?;
            let mut state = <$state>::new();
            for chunk in message.chunks(19) {
                state.update(chunk)?;
            }
            let mut output = [0_u8; $output];
            state.finalize_public(&mut output, Sha3PublicDeclassification::acknowledge())?;
            assert_eq!(output.as_slice(), expected.as_ref());
        }
        Ok::<(), HardenedSha3Error>(())
    }};
}

#[test]
fn every_rate_and_multiblock_boundary_matches() -> Result<(), HardenedSha3Error> {
    fixed_boundaries!(HardenedSha3_224, sha3_224, 28)?;
    fixed_boundaries!(HardenedSha3_256, sha3_256, 32)?;
    fixed_boundaries!(HardenedSha3_384, sha3_384, 48)?;
    fixed_boundaries!(HardenedSha3_512, sha3_512, 64)?;
    Ok(())
}

#[test]
fn fixed_output_failure_is_atomic_by_classification() {
    let mut public = [0xa5_u8; 31];
    assert_eq!(
        HardenedSha3_256::new()
            .finalize_public(&mut public, Sha3PublicDeclassification::acknowledge()),
        Err(HardenedSha3Error::OutputLength)
    );
    assert_eq!(public, [0xa5; 31]);

    let mut secret = [0xa5_u8; 31];
    assert_eq!(
        HardenedSha3_256::new()
            .finalize_secret(&mut secret)
            .map(drop),
        Err(HardenedSha3Error::OutputLength)
    );
    assert_eq!(secret, [0; 31]);
}

macro_rules! fixed_bits_match {
    ($state:ty, $ordinary:ident, $input:expr, $output:expr) => {{
        let expected = $ordinary($input).map_err(|_| HardenedSha3Error::MessageTooLong)?;
        let mut actual = [0_u8; $output];
        <$state>::new().finalize_bits_public(
            $input,
            &mut actual,
            Sha3PublicDeclassification::acknowledge(),
        )?;
        assert_eq!(actual.as_slice(), expected.as_ref());
        Ok::<(), HardenedSha3Error>(())
    }};
}

#[test]
fn every_partial_bit_width_matches_every_fixed_identity() -> Result<(), HardenedSha3Error> {
    let tails = [0x01, 0x03, 0x05, 0x0d, 0x15, 0x35, 0x75];
    for (offset, valid) in (1_u8..=7).enumerate() {
        let tail = tails.get(offset).copied().unwrap_or_default();
        let bytes = [0x61, 0x62, tail];
        let input =
            Fips202BitString::new(&bytes, valid).map_err(|_| HardenedSha3Error::MessageTooLong)?;
        fixed_bits_match!(HardenedSha3_224, sha3_224_bits, input, 28)?;
        fixed_bits_match!(HardenedSha3_256, sha3_256_bits, input, 32)?;
        fixed_bits_match!(HardenedSha3_384, sha3_384_bits, input, 48)?;
        fixed_bits_match!(HardenedSha3_512, sha3_512_bits, input, 64)?;
    }
    Ok(())
}

macro_rules! xof_matches {
    ($state:ty, $ordinary:ident) => {{
        let mut expected = [0_u8; 401];
        $ordinary(b"abc", &mut expected).map_err(|_| HardenedSha3Error::MessageTooLong)?;
        let mut state = <$state>::new();
        state.update(b"a")?;
        state.update(b"bc")?;
        let mut reader = state.finalize_xof();
        let mut actual = [0_u8; 401];
        let (first, rest) = actual.split_at_mut(3);
        reader.squeeze_public(first, Sha3PublicDeclassification::acknowledge())?;
        let (second, third) = rest.split_at_mut(170);
        reader.squeeze_public(second, Sha3PublicDeclassification::acknowledge())?;
        reader.squeeze_public(third, Sha3PublicDeclassification::acknowledge())?;
        assert_eq!(actual, expected);
        Ok::<(), HardenedSha3Error>(())
    }};
}

#[test]
fn both_xofs_match_across_irregular_absorb_and_squeeze_boundaries() -> Result<(), HardenedSha3Error>
{
    xof_matches!(HardenedShake128, shake128)?;
    xof_matches!(HardenedShake256, shake256)?;
    Ok(())
}

#[test]
fn xof_secret_fragments_transfer_and_clear_independently() -> Result<(), HardenedSha3Error> {
    let mut expected = [0_u8; 377];
    shake128(b"private input", &mut expected).map_err(|_| HardenedSha3Error::MessageTooLong)?;
    let mut state = HardenedShake128::new();
    state.update(b"private input")?;
    let mut reader = state.finalize_xof();
    let mut first = [0xa5_u8; 167];
    let mut second = [0xa5_u8; 210];
    {
        let output = reader.squeeze_secret(&mut first)?;
        assert_eq!(output.expose(), &expected[..167]);
    }
    assert_eq!(first, [0; 167]);
    {
        let output = reader.squeeze_secret(&mut second)?;
        assert_eq!(output.expose(), &expected[167..]);
    }
    assert_eq!(second, [0; 210]);
    Ok(())
}

#[test]
fn zero_length_secret_xof_output_is_a_valid_empty_owner() -> Result<(), HardenedSha3Error> {
    let mut reader = HardenedShake256::new().finalize_xof();
    let mut empty = [];
    let output = reader.squeeze_secret(&mut empty)?;
    assert!(output.expose().is_empty());
    assert_eq!(reader.output_bytes(), 0);
    Ok(())
}

#[test]
fn bit_input_and_bit_output_match_both_ordinary_xofs() -> Result<(), HardenedSha3Error> {
    let bytes = [0x13];
    let input = Fips202BitString::new(&bytes, 5).map_err(|_| HardenedSha3Error::MessageTooLong)?;
    compare_bit_xof_128(input)?;
    compare_bit_xof_256(input)?;
    Ok(())
}

#[test]
fn every_partial_secret_xof_width_matches_and_clears() -> Result<(), HardenedSha3Error> {
    let input_bytes = [0x13];
    let input =
        Fips202BitString::new(&input_bytes, 5).map_err(|_| HardenedSha3Error::MessageTooLong)?;
    for valid in 1_u8..=7 {
        let mut expected128 = [0_u8; 13];
        let expected_output = Fips202Output::new(&mut expected128, valid)
            .map_err(|_| HardenedSha3Error::OutputLength)?;
        shake128_bits(input, expected_output).map_err(|_| HardenedSha3Error::OutputTooLong)?;
        let mut actual128 = [0xa5_u8; 13];
        {
            let destination = Fips202Output::new(&mut actual128, valid)
                .map_err(|_| HardenedSha3Error::OutputLength)?;
            let output = HardenedShake128::new()
                .finalize_bits_xof(input)?
                .squeeze_final_bits_secret(destination)?;
            assert_eq!(output.expose(), expected128);
        }
        assert_eq!(actual128, [0; 13]);

        let mut expected256 = [0_u8; 17];
        let expected_output = Fips202Output::new(&mut expected256, valid)
            .map_err(|_| HardenedSha3Error::OutputLength)?;
        shake256_bits(input, expected_output).map_err(|_| HardenedSha3Error::OutputTooLong)?;
        let mut actual256 = [0xa5_u8; 17];
        {
            let destination = Fips202Output::new(&mut actual256, valid)
                .map_err(|_| HardenedSha3Error::OutputLength)?;
            let output = HardenedShake256::new()
                .finalize_bits_xof(input)?
                .squeeze_final_bits_secret(destination)?;
            assert_eq!(output.expose(), expected256);
        }
        assert_eq!(actual256, [0; 17]);
    }
    Ok(())
}

fn compare_bit_xof_128(input: Fips202BitString<'_>) -> Result<(), HardenedSha3Error> {
    let mut expected = [0_u8; 170];
    let destination =
        Fips202Output::new(&mut expected, 3).map_err(|_| HardenedSha3Error::OutputLength)?;
    shake128_bits(input, destination).map_err(|_| HardenedSha3Error::OutputTooLong)?;
    let mut actual = [0xa5_u8; 170];
    let destination =
        Fips202Output::new(&mut actual, 3).map_err(|_| HardenedSha3Error::OutputLength)?;
    HardenedShake128::new()
        .finalize_bits_xof(input)?
        .squeeze_final_bits_public(destination, Sha3PublicDeclassification::acknowledge())?;
    assert_eq!(actual, expected);
    Ok(())
}

fn compare_bit_xof_256(input: Fips202BitString<'_>) -> Result<(), HardenedSha3Error> {
    let mut expected = [0_u8; 138];
    let destination =
        Fips202Output::new(&mut expected, 7).map_err(|_| HardenedSha3Error::OutputLength)?;
    shake256_bits(input, destination).map_err(|_| HardenedSha3Error::OutputTooLong)?;
    let mut actual = [0xa5_u8; 138];
    {
        let destination =
            Fips202Output::new(&mut actual, 7).map_err(|_| HardenedSha3Error::OutputLength)?;
        let output = HardenedShake256::new()
            .finalize_bits_xof(input)?
            .squeeze_final_bits_secret(destination)?;
        assert_eq!(output.expose(), expected);
    }
    assert_eq!(actual, [0; 138]);
    Ok(())
}

#[test]
fn sealed_capabilities_accept_only_registered_public_types() {
    fn state<State: HardenedFips202State>(_state: &State) {}
    fn construction<State: HardenedFips202Construction>(_state: &State) {}
    state(&HardenedSha3_224::new());
    state(&HardenedSha3_256::new());
    state(&HardenedSha3_384::new());
    state(&HardenedSha3_512::new());
    state(&HardenedShake128::new());
    state(&HardenedShake128::new().finalize_xof());
    state(&HardenedShake256::new());
    state(&HardenedShake256::new().finalize_xof());
    construction(&HardenedSha3_256::new());
    construction(&HardenedShake128::new());
}

#[test]
fn cancel_and_early_drop_cover_absorber_and_reader_lifecycles() -> Result<(), HardenedSha3Error> {
    let mut fixed = HardenedSha3_512::new();
    fixed.update(b"secret")?;
    fixed.cancel();
    let mut xof = HardenedShake128::new();
    xof.update(b"secret")?;
    xof.cancel();
    HardenedShake256::new().finalize_xof().cancel();
    drop(HardenedSha3_224::new());
    Ok(())
}

#[cfg(panic = "unwind")]
#[test]
fn recoverable_unwind_clears_typed_secret_destination() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let mut destination = [0xa5_u8; 64];
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut state = HardenedShake256::new();
        assert_eq!(state.update(b"secret material"), Ok(()));
        let mut reader = state.finalize_xof();
        let Ok(output) = reader.squeeze_secret(&mut destination) else {
            return;
        };
        assert_ne!(output.expose(), &[0; 64]);
        assert!(core::hint::black_box(false), "injected recoverable unwind");
    }));
    assert!(result.is_err());
    assert_eq!(destination, [0; 64]);
}

fn _reader_type_contracts(_reader128: HardenedShake128Reader, _reader256: HardenedShake256Reader) {}
