//! Independent typed public-result ABI probes; no key or input data.
use super::host::Error;

#[inline(never)]
pub fn rejected_tag() -> Result<bool, Error> {
    Ok(false)
}

#[inline(never)]
pub fn accepted_tag() -> Result<bool, Error> {
    Ok(true)
}

#[inline(never)]
pub fn invalid_result() -> Result<bool, Error> {
    Err(Error::Invariant)
}
