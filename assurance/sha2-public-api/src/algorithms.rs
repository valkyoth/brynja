//! Public-only one-shot and irregular-streaming checks for each identity.

use brynja::crypto as facade;
use brynja_hash_sha2 as leaf;

use crate::{AcceptanceError, IRREGULAR_WIDTHS, vectors::Expected};

pub(crate) fn check_all(input: &[u8], expected: &Expected) -> Result<(), AcceptanceError> {
    check_sha224(input, expected.sha224)?;
    check_sha256(input, expected.sha256)?;
    check_sha384(input, expected.sha384)?;
    check_sha512(input, expected.sha512)?;
    check_sha512_224(input, expected.sha512_224)?;
    check_sha512_256(input, expected.sha512_256)
}

fn check_sha224(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha224(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha224(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha224::new();
    let mut facade_state = facade::Sha224::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn check_sha256(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha256(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha256(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha256::new();
    let mut facade_state = facade::Sha256::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn check_sha384(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha384(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha384(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha384::new();
    let mut facade_state = facade::Sha384::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn check_sha512(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha512(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha512(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha512::new();
    let mut facade_state = facade::Sha512::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn check_sha512_224(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha512_224(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha512_224(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha512_224::new();
    let mut facade_state = facade::Sha512_224::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn check_sha512_256(input: &[u8], expected: &[u8]) -> Result<(), AcceptanceError> {
    let direct = leaf::sha512_256(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(direct.as_bytes(), expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    if facade::sha512_256(input).map_err(|_| AcceptanceError::FacadeMismatch)? != direct {
        return Err(AcceptanceError::FacadeMismatch);
    }
    let mut leaf_state = leaf::Sha512_256::new();
    let mut facade_state = facade::Sha512_256::new();
    update_irregular(&mut leaf_state, input)?;
    update_irregular(&mut facade_state, input)?;
    if leaf_state.finalize() != direct || facade_state.finalize() != direct {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn update_irregular<S>(state: &mut S, mut input: &[u8]) -> Result<(), AcceptanceError>
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

pub(crate) fn matches_hex<const N: usize>(digest: &[u8; N], expected: &[u8]) -> bool {
    expected.len() == N.saturating_mul(2)
        && digest
            .iter()
            .zip(expected.chunks_exact(2))
            .all(|(actual, pair)| match pair {
                [high, low] => {
                    let high = nibble(*high);
                    let low = nibble(*low);
                    high < 16 && low < 16 && *actual == high.saturating_mul(16).saturating_add(low)
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
