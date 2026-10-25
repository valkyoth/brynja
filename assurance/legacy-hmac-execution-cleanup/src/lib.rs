//! Actual accelerated legacy SHA-1 HMAC consumers; no instruction execution.
#![no_std]
#![forbid(unsafe_code)]

use brynja_legacy_hmac::{
    BitString, Error, LegacyUse,
    execution::{Sha1Executor, Sha1Hmac},
};

// Bind the compiler's Result ABI independently of the implementation under
// inspection. These contain no secret processing or instruction execution.
#[inline(never)]
pub fn hmac_ok() -> Result<(), Error> {
    Ok(())
}
#[inline(never)]
pub fn hmac_length() -> Result<(), Error> {
    Err(Error::MessageTooLong)
}
#[inline(never)]
pub fn hmac_fatal() -> Result<(), Error> {
    Err(Error::ExecutionFailed)
}
#[inline(never)]
pub fn stream_ok() -> Result<(), brynja_legacy_sha1::hardened_execution::Error> {
    Ok(())
}
#[inline(never)]
pub fn stream_length() -> Result<(), brynja_legacy_sha1::hardened_execution::Error> {
    Err(brynja_legacy_sha1::hardened_execution::Error::Hash(
        brynja_legacy_sha1::Sha1Error::MessageTooLong,
    ))
}
#[inline(never)]
pub fn owner_size() -> usize {
    core::mem::size_of::<Sha1Hmac<'static>>()
}

#[inline(never)]
pub fn stream_size() -> usize {
    core::mem::size_of::<brynja_legacy_sha1::hardened_execution::Stream<'static>>()
}
#[inline(never)]
pub fn start_rejection() -> Result<
    brynja_legacy_sha1::hardened_execution::Stream<'static>,
    brynja_legacy_sha1::hardened_execution::Error,
> {
    Err(brynja_legacy_sha1::hardened_execution::Error::Quarantined)
}
#[inline(never)]
pub fn constructor_tag_rejection() -> Result<Sha1Hmac<'static>, Error> {
    Err(Error::TagLength)
}
#[inline(never)]
pub fn constructor_authority_rejection() -> Result<Sha1Hmac<'static>, Error> {
    Err(Error::ExecutionUnavailable)
}
#[inline(never)]
pub fn portable_report() -> brynja_legacy_sha1::hardened_execution::Report {
    brynja_legacy_sha1::hardened_execution::Report {
        backend: None,
        health: brynja_legacy_sha1::Sha1BackendHealth::Healthy,
    }
}
#[inline(never)]
pub fn empty_iterator_cache()
-> Option<Option<brynja_legacy_sha1::hardened_execution::Stream<'static>>> {
    None
}

#[inline(never)]
pub fn construct<'a>(
    executor: &'a Sha1Executor,
    key: &[u8],
    bytes: usize,
) -> Result<Sha1Hmac<'a>, Error> {
    Sha1Hmac::with_tag_length(LegacyUse::acknowledge(), executor, key, bytes)
}
#[inline(never)]
pub fn cancel(state: Sha1Hmac<'_>) {
    state.cancel();
}
#[inline(never)]
pub fn update_cancel(mut state: Sha1Hmac<'_>, input: &[u8], observer: fn()) -> Result<(), Error> {
    state.update(input)?;
    observer();
    state.cancel();
    Ok(())
}
#[inline(never)]
pub fn update(state: &mut Sha1Hmac<'_>, input: &[u8]) -> Result<(), Error> {
    state.update(input)
}
#[inline(never)]
pub fn public(state: Sha1Hmac<'_>, output: &mut [u8]) -> Result<(), Error> {
    core::hint::black_box(state.finalize_tag(output)?.as_bytes());
    Ok(())
}
#[inline(never)]
pub fn secret(state: Sha1Hmac<'_>, output: &mut [u8]) -> Result<(), Error> {
    let tag = state.finalize_secret(output)?;
    core::hint::black_box(tag.expose());
    drop(tag);
    Ok(())
}
#[inline(never)]
pub fn verify(
    state: Sha1Hmac<'_>,
    candidate: &[u8],
) -> Result<(), brynja_legacy_hmac::VerificationError> {
    state.verify(candidate)
}
#[inline(never)]
pub fn public_bits(
    state: Sha1Hmac<'_>,
    input: BitString<'_>,
    output: &mut [u8],
) -> Result<(), Error> {
    core::hint::black_box(state.finalize_bits_tag(input, output)?.as_bytes());
    Ok(())
}
#[inline(never)]
pub fn secret_bits(
    state: Sha1Hmac<'_>,
    input: BitString<'_>,
    output: &mut [u8],
) -> Result<(), Error> {
    let tag = state.finalize_bits_secret(input, output)?;
    core::hint::black_box(tag.expose());
    drop(tag);
    Ok(())
}
#[inline(never)]
pub fn verify_bits(
    state: Sha1Hmac<'_>,
    input: BitString<'_>,
    candidate: &[u8],
) -> Result<(), brynja_legacy_hmac::VerificationError> {
    state.verify_bits(input, candidate)
}
