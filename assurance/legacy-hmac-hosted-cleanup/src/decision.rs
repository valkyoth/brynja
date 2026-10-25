//! Typed verification and host-result projections for compiler evidence.
use brynja_legacy_hmac::{Error, Verification, md5_batch::Report};

#[inline(never)]
pub fn candidates<'a>(
    value: &Option<&'a [Option<&'a [u8]>; 8]>,
) -> Option<&'a [Option<&'a [u8]>; 8]> {
    *value
}

#[inline(never)]
pub fn projection(value: &Result<(Verification, Report), Error>) -> Option<&Verification> {
    value.as_ref().ok().map(|(decision, _)| decision)
}

#[inline(never)]
pub fn expose(value: Verification) -> bool {
    value.expose_public()
}

#[inline(never)]
pub fn matched() -> Result<Option<bool>, super::host::Error> {
    Ok(Some(true))
}

#[inline(never)]
pub fn unmatched() -> Result<Option<bool>, super::host::Error> {
    Ok(Some(false))
}

#[inline(never)]
pub fn authenticated() -> Result<Option<bool>, super::host::Error> {
    Ok(None)
}
