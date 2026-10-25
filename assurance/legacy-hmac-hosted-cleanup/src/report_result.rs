//! Typed Result-to-report projections; compiler probes, not native evidence.
use brynja_legacy_hmac::{
    Error, Verification,
    md5_batch::{Report, SecretTags},
};

#[inline(never)]
pub fn verification(value: &Result<(Verification, Report), Error>) -> Option<&Report> {
    value.as_ref().ok().map(|(_, report)| report)
}

#[inline(never)]
pub fn authentication<'a>(
    value: &'a Result<(SecretTags<'_>, Report), Error>,
) -> Option<&'a Report> {
    value.as_ref().ok().map(|(_, report)| report)
}
