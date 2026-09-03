//! Package-external `no_std` acceptance for complete cSHAKE.

#![no_std]

use brynja::crypto as facade;
use brynja_crypto as crypto;
use brynja_hash_sha3 as leaf;

const EXPECTED: [u8; 32] = [
    0xc1, 0xc3, 0x69, 0x25, 0xb6, 0x40, 0x9a, 0x04, 0xf1, 0xb5, 0x04, 0xfc, 0xbc, 0xa9, 0xd8, 0x2b,
    0x40, 0x17, 0x27, 0x7c, 0xb5, 0xed, 0x2b, 0x20, 0x65, 0xfc, 0x1d, 0x38, 0x14, 0xd5, 0xaa, 0xf5,
];

/// Closed downstream acceptance failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AcceptanceError {
    /// One public layer rejected bounded input.
    Rejected,
    /// One public layer disagreed with the official example.
    Mismatch,
}

/// Exercises ordinary and hardened cSHAKE through every public layer.
pub fn exercise_all() -> Result<(), AcceptanceError> {
    let message = [0_u8, 1, 2, 3];
    let customization = b"Email Signature";
    let mut leaf_output = [0_u8; 32];
    let mut crypto_output = [0_u8; 32];
    let mut facade_output = [0_u8; 32];
    leaf::cshake128(&message, b"", customization, &mut leaf_output)
        .map_err(|_| AcceptanceError::Rejected)?;
    crypto::cshake128(&message, b"", customization, &mut crypto_output)
        .map_err(|_| AcceptanceError::Rejected)?;
    facade::cshake128(&message, b"", customization, &mut facade_output)
        .map_err(|_| AcceptanceError::Rejected)?;
    if leaf_output != EXPECTED || crypto_output != EXPECTED || facade_output != EXPECTED {
        return Err(AcceptanceError::Mismatch);
    }

    let mut leaf_secret = [0_u8; 32];
    let mut crypto_secret = [0_u8; 32];
    let mut facade_secret = [0_u8; 32];
    hardened_leaf(&message, customization, &mut leaf_secret)?;
    hardened_crypto(&message, customization, &mut crypto_secret)?;
    hardened_facade(&message, customization, &mut facade_secret)?;
    hardened_terminal_transitions()?;
    if leaf_secret != [0; 32] || crypto_secret != [0; 32] || facade_secret != [0; 32] {
        return Err(AcceptanceError::Mismatch);
    }
    Ok(())
}

fn hardened_terminal_transitions() -> Result<(), AcceptanceError> {
    let mut extracted = leaf::HardenedCshake128::new(b"KMAC", b"downstream extraction")
        .map_err(|_| AcceptanceError::Rejected)?;
    extracted
        .update(b"secret-derived state")
        .map_err(|_| AcceptanceError::Rejected)?;
    let reader = extracted
        .finalize_xof_erasing_source()
        .map_err(|_| AcceptanceError::Rejected)?;
    reader.cancel();
    if extracted.update(b"reuse") != Err(leaf::HardenedSha3Error::StateConsumed)
        || extracted.check_additional_bytes(0)
            != Err(leaf::HardenedSha3Error::StateConsumed)
        || !matches!(
            extracted.finalize_xof_erasing_source(),
            Err(leaf::HardenedSha3Error::StateConsumed)
        )
    {
        return Err(AcceptanceError::Mismatch);
    }

    let mut wiped = leaf::HardenedCshake256::new(b"KMAC", b"downstream wipe")
        .map_err(|_| AcceptanceError::Rejected)?;
    wiped.wipe_in_place();
    if wiped.check_additional_bits(0) != Err(leaf::HardenedSha3Error::StateConsumed)
        || wiped.update(b"reuse") != Err(leaf::HardenedSha3Error::StateConsumed)
        || !matches!(
            wiped.finalize_xof_erasing_source(),
            Err(leaf::HardenedSha3Error::StateConsumed)
        )
    {
        return Err(AcceptanceError::Mismatch);
    }
    Ok(())
}

fn hardened_leaf(
    message: &[u8],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), AcceptanceError> {
    let mut state = leaf::HardenedCshake128::new(b"", customization)
        .map_err(|_| AcceptanceError::Rejected)?;
    state.update(message).map_err(|_| AcceptanceError::Rejected)?;
    let secret = state
        .finalize_secret(output)
        .map_err(|_| AcceptanceError::Rejected)?;
    if secret.expose() != EXPECTED {
        return Err(AcceptanceError::Mismatch);
    }
    drop(secret);
    Ok(())
}

fn hardened_crypto(
    message: &[u8],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), AcceptanceError> {
    let mut state = crypto::HardenedCshake128::new(b"", customization)
        .map_err(|_| AcceptanceError::Rejected)?;
    state.update(message).map_err(|_| AcceptanceError::Rejected)?;
    let secret = state
        .finalize_secret(output)
        .map_err(|_| AcceptanceError::Rejected)?;
    if secret.expose() != EXPECTED {
        return Err(AcceptanceError::Mismatch);
    }
    drop(secret);
    Ok(())
}

fn hardened_facade(
    message: &[u8],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), AcceptanceError> {
    let mut state = facade::HardenedCshake128::new(b"", customization)
        .map_err(|_| AcceptanceError::Rejected)?;
    state.update(message).map_err(|_| AcceptanceError::Rejected)?;
    let secret = state
        .finalize_secret(output)
        .map_err(|_| AcceptanceError::Rejected)?;
    if secret.expose() != EXPECTED {
        return Err(AcceptanceError::Mismatch);
    }
    drop(secret);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_public_layer_is_usable() {
        assert_eq!(super::exercise_all(), Ok(()));
    }
}
