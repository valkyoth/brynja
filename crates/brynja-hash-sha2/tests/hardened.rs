//! Public hardened SHA-2 lifecycle and differential acceptance.

use brynja_hash_sha2::{
    BitString, HardenedSha2Error, HardenedSha2State, HardenedSha224, HardenedSha256,
    HardenedSha384, HardenedSha512, HardenedSha512_224, HardenedSha512_256, PublicDeclassification,
    sha224, sha224_bits, sha256, sha256_bits, sha384, sha384_bits, sha512, sha512_224,
    sha512_224_bits, sha512_256, sha512_256_bits, sha512_bits,
};

macro_rules! public_matches {
    ($state:ty, $ordinary:ident, $length:expr) => {{
        let mut state = <$state>::new();
        state.update(b"a")?;
        state.update(b"bc")?;
        let mut output = [0_u8; $length];
        state.finalize_public(&mut output, PublicDeclassification::acknowledge())?;
        let expected = $ordinary(b"abc").map_err(|_| HardenedSha2Error::MessageTooLong)?;
        assert_eq!(output.as_slice(), expected.as_ref());
        Ok::<(), HardenedSha2Error>(())
    }};
}

macro_rules! secret_matches {
    ($state:ty, $ordinary:ident, $length:expr) => {{
        let mut destination = [0xa5_u8; $length];
        {
            let mut state = <$state>::new();
            state.update(b"abc")?;
            let owner = state.finalize_secret(&mut destination)?;
            let expected = $ordinary(b"abc").map_err(|_| HardenedSha2Error::MessageTooLong)?;
            assert_eq!(owner.expose(), expected.as_ref());
        }
        assert_eq!(destination, [0_u8; $length]);
        Ok::<(), HardenedSha2Error>(())
    }};
}

#[test]
fn every_hardened_identity_matches_the_ordinary_algorithm() -> Result<(), HardenedSha2Error> {
    public_matches!(HardenedSha224, sha224, 28)?;
    public_matches!(HardenedSha256, sha256, 32)?;
    public_matches!(HardenedSha384, sha384, 48)?;
    public_matches!(HardenedSha512, sha512, 64)?;
    public_matches!(HardenedSha512_224, sha512_224, 28)?;
    public_matches!(HardenedSha512_256, sha512_256, 32)?;
    Ok(())
}

macro_rules! boundary_matches {
    ($state:ty, $ordinary:ident, $input:expr, $length:expr, $output:expr) => {{
        let message = $input
            .get(..$length)
            .ok_or(HardenedSha2Error::MessageTooLong)?;
        let expected = $ordinary(message).map_err(|_| HardenedSha2Error::MessageTooLong)?;
        let mut state = <$state>::new();
        for chunk in message.chunks(17) {
            state.update(chunk)?;
        }
        let mut output = [0_u8; $output];
        state.finalize_public(&mut output, PublicDeclassification::acknowledge())?;
        assert_eq!(output.as_slice(), expected.as_ref());
        Ok::<(), HardenedSha2Error>(())
    }};
}

#[test]
fn padding_and_multiblock_boundaries_match_all_ordinary_states() -> Result<(), HardenedSha2Error> {
    let mut input = [0_u8; 260];
    for (index, byte) in input.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap_or_default();
    }
    for length in [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 260] {
        boundary_matches!(HardenedSha224, sha224, input, length, 28)?;
        boundary_matches!(HardenedSha256, sha256, input, length, 32)?;
        boundary_matches!(HardenedSha384, sha384, input, length, 48)?;
        boundary_matches!(HardenedSha512, sha512, input, length, 64)?;
        boundary_matches!(HardenedSha512_224, sha512_224, input, length, 28)?;
        boundary_matches!(HardenedSha512_256, sha512_256, input, length, 32)?;
    }
    Ok(())
}

#[test]
fn every_secret_output_transfers_and_executes_clearing_duty() -> Result<(), HardenedSha2Error> {
    secret_matches!(HardenedSha224, sha224, 28)?;
    secret_matches!(HardenedSha256, sha256, 32)?;
    secret_matches!(HardenedSha384, sha384, 48)?;
    secret_matches!(HardenedSha512, sha512, 64)?;
    secret_matches!(HardenedSha512_224, sha512_224, 28)?;
    secret_matches!(HardenedSha512_256, sha512_256, 32)?;
    Ok(())
}

#[test]
fn public_output_failure_is_unchanged_and_secret_failure_is_cleared() {
    let mut public = [0xa5_u8; 31];
    assert_eq!(
        HardenedSha256::new().finalize_public(&mut public, PublicDeclassification::acknowledge(),),
        Err(HardenedSha2Error::OutputLength)
    );
    assert_eq!(public, [0xa5; 31]);

    let mut secret = [0xa5_u8; 31];
    assert_eq!(
        HardenedSha256::new()
            .finalize_secret(&mut secret)
            .map(|owner| {
                drop(owner);
            }),
        Err(HardenedSha2Error::OutputLength)
    );
    assert_eq!(secret, [0; 31]);
}

#[test]
fn canonical_bit_tail_matches_the_ordinary_bit_api() -> Result<(), HardenedSha2Error> {
    let input =
        BitString::new(&[0x61, 0x62, 0x80], 1).map_err(|_| HardenedSha2Error::MessageTooLong)?;
    let mut expected = [0_u8; 32];
    let ordinary =
        brynja_hash_sha2::sha256_bits(input).map_err(|_| HardenedSha2Error::MessageTooLong)?;
    HardenedSha256::new().finalize_bits_public(
        input,
        &mut expected,
        PublicDeclassification::acknowledge(),
    )?;
    assert_eq!(expected.as_slice(), ordinary.as_ref());
    Ok(())
}

macro_rules! bit_matches {
    ($state:ty, $ordinary:ident, $input:expr, $output:expr) => {{
        let expected = $ordinary($input).map_err(|_| HardenedSha2Error::MessageTooLong)?;
        let mut output = [0_u8; $output];
        <$state>::new().finalize_bits_public(
            $input,
            &mut output,
            PublicDeclassification::acknowledge(),
        )?;
        assert_eq!(output.as_slice(), expected.as_ref());
        Ok::<(), HardenedSha2Error>(())
    }};
}

#[test]
fn every_partial_bit_width_matches_every_ordinary_identity() -> Result<(), HardenedSha2Error> {
    let tails = [0x80, 0x80, 0xa0, 0xa0, 0xa8, 0xac, 0xae];
    for (offset, valid) in (1_u8..=7).enumerate() {
        let tail = tails.get(offset).copied().unwrap_or_default();
        let bytes = [0x61, 0x62, tail];
        let input = BitString::new(&bytes, valid).map_err(|_| HardenedSha2Error::MessageTooLong)?;
        bit_matches!(HardenedSha224, sha224_bits, input, 28)?;
        bit_matches!(HardenedSha256, sha256_bits, input, 32)?;
        bit_matches!(HardenedSha384, sha384_bits, input, 48)?;
        bit_matches!(HardenedSha512, sha512_bits, input, 64)?;
        bit_matches!(HardenedSha512_224, sha512_224_bits, input, 28)?;
        bit_matches!(HardenedSha512_256, sha512_256_bits, input, 32)?;
    }
    Ok(())
}

#[test]
fn sealed_capability_accepts_all_six_registered_types() {
    fn require<State: HardenedSha2State>(_state: &State) {}
    require(&HardenedSha224::new());
    require(&HardenedSha256::new());
    require(&HardenedSha384::new());
    require(&HardenedSha512::new());
    require(&HardenedSha512_224::new());
    require(&HardenedSha512_256::new());
}

#[cfg(panic = "unwind")]
#[test]
fn recoverable_unwind_clears_typed_secret_destination() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let mut destination = [0xa5_u8; 32];
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut state = HardenedSha256::new();
        assert_eq!(state.update(b"secret material"), Ok(()));
        let owner = state.finalize_secret(&mut destination);
        let Ok(owner) = owner else {
            return;
        };
        assert_ne!(owner.expose(), &[0; 32]);
        assert!(core::hint::black_box(false), "injected recoverable unwind");
    }));
    assert!(result.is_err());
    assert_eq!(destination, [0; 32]);
}
