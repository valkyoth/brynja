//! Public-only fixed-output checks for every SHA-3 identity.

use brynja::crypto as facade;
use brynja_hash_sha3 as leaf;

use crate::{AcceptanceError, IRREGULAR_WIDTHS, vectors::FixedExpected};

pub(crate) fn check_all(input: &[u8], expected: &FixedExpected) -> Result<(), AcceptanceError> {
    check_sha3_224(input, expected.sha3_224)?;
    check_sha3_256(input, expected.sha3_256)?;
    check_sha3_384(input, expected.sha3_384)?;
    check_sha3_512(input, expected.sha3_512)
}

fn check_sha3_224(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha3_224(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha3_224(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha3_224::new();
    let mut facade_state = facade::Sha3_224::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn check_sha3_256(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha3_256(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha3_256(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha3_256::new();
    let mut facade_state = facade::Sha3_256::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn check_sha3_384(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha3_384(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha3_384(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha3_384::new();
    let mut facade_state = facade::Sha3_384::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn check_sha3_512(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha3_512(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha3_512(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha3_512::new();
    let mut facade_state = facade::Sha3_512::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

pub(crate) fn update_irregular<S>(state: &mut S, mut input: &[u8]) -> Result<(), AcceptanceError>
where
    S: leaf::Update,
{
    for width in IRREGULAR_WIDTHS.iter().copied().cycle() {
        if input.is_empty() {
            break;
        }
        let take = core::cmp::min(width, input.len());
        let (chunk, remaining) = input.split_at(take);
        state
            .update(chunk)
            .map_err(|_| AcceptanceError::StreamingMismatch)?;
        input = remaining;
    }
    Ok(())
}

pub(crate) fn matches_hex(actual: &[u8], expected: &[u8]) -> bool {
    expected.len() == actual.len().saturating_mul(2)
        && actual
            .iter()
            .zip(expected.chunks_exact(2))
            .all(|(byte, pair)| match pair {
                [high, low] => {
                    let high = nibble(*high);
                    let low = nibble(*low);
                    high < 16 && low < 16 && *byte == high.saturating_mul(16).saturating_add(low)
                }
                _ => false,
            })
}

const fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0xff,
    }
}
