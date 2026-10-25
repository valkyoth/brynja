//! Independent typed public-result ABI probes; no key or input data.
use super::host::Error;

#[inline(never)]
pub fn rejected_tag() -> Result<(), brynja_legacy_hmac_std::VerificationError<Error>> {
    Err(brynja_legacy_hmac_std::VerificationError::Mismatch)
}

#[inline(never)]
pub fn accepted_tag() -> Result<(), brynja_legacy_hmac_std::VerificationError<Error>> {
    Ok(())
}

#[inline(never)]
pub fn invalid_result() -> Result<(), brynja_legacy_hmac_std::VerificationError<Error>> {
    Err(brynja_legacy_hmac_std::VerificationError::Operation(
        Error::Invariant,
    ))
}
