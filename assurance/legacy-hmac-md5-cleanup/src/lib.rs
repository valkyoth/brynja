//! Real MD5 batch consumers for emitted-code inspection, not CPU execution.
#![no_std]
#![forbid(unsafe_code)]

use brynja_legacy_hmac::{
    Error, LegacyUse,
    md5_batch::{Input, Md5Backend, Md5Batch, Md5BatchControl, Md5Executor, Report},
};

#[inline(never)]
pub fn select(executor: &Md5Executor, bytes: usize) -> Result<Md5Batch<'_>, Error> {
    Md5Batch::with_tag_length(LegacyUse::acknowledge(), executor, bytes)
}

// Independent ABI probes, not constructor implementation replicas.
#[inline(never)]
pub fn tag_rejection() -> Result<Md5Batch<'static>, Error> {
    Err(Error::TagLength)
}

#[inline(never)]
pub fn authority_rejection() -> Result<Md5Batch<'static>, Error> {
    Err(Error::ExecutionUnavailable)
}

#[inline(never)]
pub fn portable_backend() -> Option<Md5Backend> {
    None
}

#[inline(never)]
pub fn backend(executor: &Md5Executor) -> Option<Md5Backend> {
    executor.backend()
}

#[inline(never)]
pub fn public(
    selection: Md5Batch<'_>,
    inputs: &[Option<Input<'_>>; 8],
    output: &mut [[u8; 16]; 8],
    control: &mut Md5BatchControl<'_>,
) -> Result<Report, Error> {
    let (tags, report) = selection.authenticate(inputs, output, control)?;
    let _ = core::hint::black_box(tags);
    Ok(report)
}

#[inline(never)]
pub fn secret(
    selection: Md5Batch<'_>,
    inputs: &[Option<Input<'_>>; 8],
    output: &mut [[u8; 16]; 8],
    control: &mut Md5BatchControl<'_>,
) -> Result<Report, Error> {
    let (tags, report) = selection.authenticate_secret(inputs, output, control)?;
    core::hint::black_box(&tags);
    drop(tags);
    Ok(report)
}

#[inline(never)]
pub fn verify(
    selection: Md5Batch<'_>,
    inputs: &[Option<Input<'_>>; 8],
    candidates: &[Option<&[u8]>; 8],
    control: &mut Md5BatchControl<'_>,
) -> Result<(bool, Report), Error> {
    let (decision, report) = selection.verify(inputs, candidates, control)?;
    Ok((decision.expose_public(), report))
}
