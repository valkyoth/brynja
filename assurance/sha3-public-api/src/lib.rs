//! Downstream-style complete portable FIPS 202 public API acceptance fixture.

#![no_std]

mod algorithms;
mod bit_api;
mod vectors;

use brynja::crypto as facade;
use brynja_hash_sha3 as leaf;

const REAL_TEXT: &[u8] = b"Brynja complete FIPS 202 consumer acceptance\n";
const REPRESENTATIVE_FILE: &[u8] = include_bytes!("../fixtures/representative.txt");
const A3_1600: [u8; 200] = [0xa3; 200];
pub(crate) const IRREGULAR_WIDTHS: [usize; 12] = [1, 7, 2, 31, 3, 72, 5, 104, 11, 136, 13, 17];

/// Closed failure from the complete-family portable acceptance fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AcceptanceError {
    /// An independently generated expected digest or XOF stream did not match.
    DigestMismatch,
    /// The main facade and reusable family package disagreed.
    FacadeMismatch,
    /// Irregular streaming differed from one-shot behavior.
    StreamingMismatch,
    /// Incremental XOF squeezing differed from one-shot behavior.
    SqueezeMismatch,
    /// Public checked-length behavior was not exact and transactional.
    ExhaustionMismatch,
    /// Distinct domain-separated identities collapsed to one output.
    DomainSeparationMismatch,
    /// One or more public implementation claims were absent.
    ImplementationClaimMissing,
    /// FIPS 202 input/output bit semantics differed across public layers.
    BitApiMismatch,
    /// The frozen fixture requested an impossible local buffer range.
    FixtureBounds,
}

/// Successful complete-family portable acceptance counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptanceReport {
    /// Number of distinct FIPS 202 identities checked.
    pub algorithms: usize,
    /// Number of fixed-output expected results checked.
    pub fixed_output_results: usize,
    /// Number of expected SHAKE streams checked.
    pub xof_results: usize,
    /// Number of incremental SHAKE streams checked.
    pub incremental_squeeze_results: usize,
    /// Number of package-external bit-domain paths checked.
    pub bit_domain_results: usize,
}

/// Runs complete v0.24.11 portable FIPS 202 downstream usability acceptance.
pub fn run() -> Result<AcceptanceReport, AcceptanceError> {
    check_claims()?;
    for (input, expected) in [
        (b"".as_slice(), &vectors::EMPTY),
        (b"abc".as_slice(), &vectors::ABC),
        (REAL_TEXT, &vectors::REAL_TEXT),
        (REPRESENTATIVE_FILE, &vectors::FILE),
        (A3_1600.as_slice(), &vectors::A3_1600),
    ] {
        algorithms::check_all(input, expected)?;
    }
    check_exact_rates()?;
    check_shake128(b"", 32, vectors::SHAKE128_EMPTY_32)?;
    check_shake128(&A3_1600, 32, vectors::SHAKE128_A3_32)?;
    check_shake128(b"abc", 343, vectors::SHAKE128_ABC_343)?;
    check_shake128(REPRESENTATIVE_FILE, 257, vectors::SHAKE128_FILE_257)?;
    check_shake256(b"", 64, vectors::SHAKE256_EMPTY_64)?;
    check_shake256(&A3_1600, 64, vectors::SHAKE256_A3_64)?;
    check_shake256(b"abc", 343, vectors::SHAKE256_ABC_343)?;
    check_shake256(REPRESENTATIVE_FILE, 257, vectors::SHAKE256_FILE_257)?;
    check_zero_output()?;
    check_exhaustion()?;
    check_domain_separation()?;
    let bit_domain_results = bit_api::check()?;
    Ok(AcceptanceReport {
        algorithms: 6,
        fixed_output_results: 24,
        xof_results: 10,
        incremental_squeeze_results: 20,
        bit_domain_results,
    })
}

fn check_claims() -> Result<(), AcceptanceError> {
    let leaf_claims = [
        leaf::SHA3_224_IMPLEMENTED,
        leaf::SHA3_256_IMPLEMENTED,
        leaf::SHA3_384_IMPLEMENTED,
        leaf::SHA3_512_IMPLEMENTED,
        leaf::SHAKE128_IMPLEMENTED,
        leaf::SHAKE256_IMPLEMENTED,
        leaf::FIPS202_BIT_INPUT_IMPLEMENTED,
        leaf::FIPS202_BIT_OUTPUT_IMPLEMENTED,
    ];
    let facade_claims = [
        facade::SHA3_224_IMPLEMENTED,
        facade::SHA3_256_IMPLEMENTED,
        facade::SHA3_384_IMPLEMENTED,
        facade::SHA3_512_IMPLEMENTED,
        facade::SHAKE128_IMPLEMENTED,
        facade::SHAKE256_IMPLEMENTED,
        facade::FIPS202_BIT_INPUT_IMPLEMENTED,
        facade::FIPS202_BIT_OUTPUT_IMPLEMENTED,
    ];
    if leaf_claims.iter().all(|claim| *claim) && facade_claims.iter().all(|claim| *claim) {
        Ok(())
    } else {
        Err(AcceptanceError::ImplementationClaimMissing)
    }
}

fn check_exact_rates() -> Result<(), AcceptanceError> {
    let input = patterned::<168>();
    let sha3_224 = leaf::sha3_224(input.get(..144).ok_or(AcceptanceError::FixtureBounds)?)
        .map_err(|_| AcceptanceError::DigestMismatch)?;
    let sha3_256 = leaf::sha3_256(input.get(..136).ok_or(AcceptanceError::FixtureBounds)?)
        .map_err(|_| AcceptanceError::DigestMismatch)?;
    let sha3_384 = leaf::sha3_384(input.get(..104).ok_or(AcceptanceError::FixtureBounds)?)
        .map_err(|_| AcceptanceError::DigestMismatch)?;
    let sha3_512 = leaf::sha3_512(input.get(..72).ok_or(AcceptanceError::FixtureBounds)?)
        .map_err(|_| AcceptanceError::DigestMismatch)?;
    if !algorithms::matches_hex(sha3_224.as_bytes(), vectors::SHA3_224_EXACT_RATE)
        || !algorithms::matches_hex(sha3_256.as_bytes(), vectors::SHA3_256_EXACT_RATE)
        || !algorithms::matches_hex(sha3_384.as_bytes(), vectors::SHA3_384_EXACT_RATE)
        || !algorithms::matches_hex(sha3_512.as_bytes(), vectors::SHA3_512_EXACT_RATE)
    {
        return Err(AcceptanceError::DigestMismatch);
    }
    check_shake128(&input, 64, vectors::SHAKE128_EXACT_RATE_64)?;
    check_shake256(
        input.get(..136).ok_or(AcceptanceError::FixtureBounds)?,
        64,
        vectors::SHAKE256_EXACT_RATE_64,
    )
}

fn check_shake128(input: &[u8], length: usize, expected: &[u8]) -> Result<(), AcceptanceError> {
    let mut leaf_output = [0_u8; 343];
    let leaf_slice = leaf_output
        .get_mut(..length)
        .ok_or(AcceptanceError::FixtureBounds)?;
    leaf::shake128(input, leaf_slice).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !algorithms::matches_hex(leaf_slice, expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    let mut facade_output = [0_u8; 343];
    let facade_slice = facade_output
        .get_mut(..length)
        .ok_or(AcceptanceError::FixtureBounds)?;
    facade::shake128(input, facade_slice).map_err(|_| AcceptanceError::FacadeMismatch)?;
    if facade_slice != leaf_slice {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut state = leaf::Shake128::new();
    algorithms::update_irregular(&mut state, input)?;
    let mut streamed = [0_u8; 343];
    let streamed = streamed
        .get_mut(..length)
        .ok_or(AcceptanceError::FixtureBounds)?;
    squeeze_128(&mut state.finalize_xof(), streamed)?;
    if streamed != leaf_slice {
        return Err(AcceptanceError::SqueezeMismatch);
    }
    let mut facade_state = facade::Shake128::new();
    algorithms::update_irregular(&mut facade_state, input)?;
    let mut facade_streamed = [0_u8; 343];
    let facade_streamed = facade_streamed
        .get_mut(..length)
        .ok_or(AcceptanceError::FixtureBounds)?;
    squeeze_128(&mut facade_state.finalize_xof(), facade_streamed)?;
    if facade_streamed != leaf_slice {
        return Err(AcceptanceError::SqueezeMismatch);
    }
    Ok(())
}

fn check_shake256(input: &[u8], length: usize, expected: &[u8]) -> Result<(), AcceptanceError> {
    let mut leaf_output = [0_u8; 343];
    let leaf_slice = leaf_output
        .get_mut(..length)
        .ok_or(AcceptanceError::FixtureBounds)?;
    leaf::shake256(input, leaf_slice).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !algorithms::matches_hex(leaf_slice, expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    let mut facade_output = [0_u8; 343];
    let facade_slice = facade_output
        .get_mut(..length)
        .ok_or(AcceptanceError::FixtureBounds)?;
    facade::shake256(input, facade_slice).map_err(|_| AcceptanceError::FacadeMismatch)?;
    if facade_slice != leaf_slice {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut state = leaf::Shake256::new();
    algorithms::update_irregular(&mut state, input)?;
    let mut streamed = [0_u8; 343];
    let streamed = streamed
        .get_mut(..length)
        .ok_or(AcceptanceError::FixtureBounds)?;
    squeeze_256(&mut state.finalize_xof(), streamed)?;
    if streamed != leaf_slice {
        return Err(AcceptanceError::SqueezeMismatch);
    }
    let mut facade_state = facade::Shake256::new();
    algorithms::update_irregular(&mut facade_state, input)?;
    let mut facade_streamed = [0_u8; 343];
    let facade_streamed = facade_streamed
        .get_mut(..length)
        .ok_or(AcceptanceError::FixtureBounds)?;
    squeeze_256(&mut facade_state.finalize_xof(), facade_streamed)?;
    if facade_streamed != leaf_slice {
        return Err(AcceptanceError::SqueezeMismatch);
    }
    Ok(())
}

fn squeeze_128(
    reader: &mut leaf::Shake128Reader,
    mut output: &mut [u8],
) -> Result<(), AcceptanceError> {
    for width in IRREGULAR_WIDTHS.iter().copied().cycle() {
        if output.is_empty() {
            break;
        }
        let take = core::cmp::min(width, output.len());
        let (chunk, remaining) = output.split_at_mut(take);
        reader
            .squeeze(chunk)
            .map_err(|_| AcceptanceError::SqueezeMismatch)?;
        output = remaining;
    }
    Ok(())
}

fn squeeze_256(
    reader: &mut leaf::Shake256Reader,
    mut output: &mut [u8],
) -> Result<(), AcceptanceError> {
    for width in IRREGULAR_WIDTHS.iter().copied().cycle() {
        if output.is_empty() {
            break;
        }
        let take = core::cmp::min(width, output.len());
        let (chunk, remaining) = output.split_at_mut(take);
        reader
            .squeeze(chunk)
            .map_err(|_| AcceptanceError::SqueezeMismatch)?;
        output = remaining;
    }
    Ok(())
}

fn check_zero_output() -> Result<(), AcceptanceError> {
    let mut empty = [];
    leaf::shake128(b"abc", &mut empty).map_err(|_| AcceptanceError::SqueezeMismatch)?;
    facade::shake256(b"abc", &mut empty).map_err(|_| AcceptanceError::SqueezeMismatch)?;
    let mut reader = leaf::Shake128::new().finalize_xof();
    reader
        .squeeze(&mut empty)
        .map_err(|_| AcceptanceError::SqueezeMismatch)?;
    if reader.output_bytes() != 0 {
        return Err(AcceptanceError::SqueezeMismatch);
    }
    Ok(())
}

fn check_exhaustion() -> Result<(), AcceptanceError> {
    let mut state128 = leaf::Shake128::new();
    state128
        .update(b"abc")
        .map_err(|_| AcceptanceError::ExhaustionMismatch)?;
    if state128.check_additional_bytes(u128::MAX) != Err(leaf::Shake128Error::MessageTooLong)
        || state128.message_bytes() != 3
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    let mut reader128 = state128.finalize_xof();
    let mut byte = [0_u8; 1];
    reader128
        .squeeze(&mut byte)
        .map_err(|_| AcceptanceError::ExhaustionMismatch)?;
    if reader128.check_additional_bytes(u128::MAX) != Err(leaf::Shake128Error::OutputTooLong)
        || reader128.output_bytes() != 1
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    let mut state256 = leaf::Shake256::new();
    state256
        .update(b"abc")
        .map_err(|_| AcceptanceError::ExhaustionMismatch)?;
    if state256.check_additional_bytes(u128::MAX) != Err(leaf::Shake256Error::MessageTooLong)
        || state256.message_bytes() != 3
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    let mut reader256 = state256.finalize_xof();
    reader256
        .squeeze(&mut byte)
        .map_err(|_| AcceptanceError::ExhaustionMismatch)?;
    if reader256.check_additional_bytes(u128::MAX) != Err(leaf::Shake256Error::OutputTooLong)
        || reader256.output_bytes() != 1
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    check_fixed_exhaustion()
}

fn check_fixed_exhaustion() -> Result<(), AcceptanceError> {
    macro_rules! check_state {
        ($state:ty, $error:path) => {{
            let mut state = <$state>::new();
            if state.check_additional_bytes(u128::MAX).is_err() {
                return Err(AcceptanceError::ExhaustionMismatch);
            }
            state
                .update(b"abc")
                .map_err(|_| AcceptanceError::ExhaustionMismatch)?;
            if state.check_additional_bytes(u128::MAX) != Err($error) || state.message_bytes() != 3
            {
                return Err(AcceptanceError::ExhaustionMismatch);
            }
        }};
    }
    check_state!(leaf::Sha3_224, leaf::Sha3_224Error::MessageTooLong);
    check_state!(leaf::Sha3_256, leaf::Sha3_256Error::MessageTooLong);
    check_state!(leaf::Sha3_384, leaf::Sha3_384Error::MessageTooLong);
    check_state!(leaf::Sha3_512, leaf::Sha3_512Error::MessageTooLong);
    Ok(())
}

fn check_domain_separation() -> Result<(), AcceptanceError> {
    let sha3_256 = leaf::sha3_256(b"").map_err(|_| AcceptanceError::DomainSeparationMismatch)?;
    let sha3_512 = leaf::sha3_512(b"").map_err(|_| AcceptanceError::DomainSeparationMismatch)?;
    let mut shake128 = [0_u8; 64];
    let mut shake256 = [0_u8; 64];
    leaf::shake128(b"", &mut shake128).map_err(|_| AcceptanceError::DomainSeparationMismatch)?;
    leaf::shake256(b"", &mut shake256).map_err(|_| AcceptanceError::DomainSeparationMismatch)?;
    let prefix = shake128.get(..32).ok_or(AcceptanceError::FixtureBounds)?;
    if sha3_256.as_ref() == prefix || sha3_512.as_ref() == shake256 || shake128 == shake256 {
        return Err(AcceptanceError::DomainSeparationMismatch);
    }
    Ok(())
}

fn patterned<const LENGTH: usize>() -> [u8; LENGTH] {
    let mut output = [0_u8; LENGTH];
    let mut value = 0_u8;
    for byte in &mut output {
        *byte = value;
        value = value.wrapping_add(1);
    }
    output
}
