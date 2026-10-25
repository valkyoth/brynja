//! Independent typed stream layout probes for temporary checkpoint ownership.
use brynja_legacy_sha1::hardened_execution::{Error, Stream};

#[inline(never)]
pub fn accepted(stream: Stream<'_>) -> Result<Stream<'_>, Error> {
    Ok(stream)
}

#[inline(never)]
pub fn rejected<'a>() -> Result<Stream<'a>, Error> {
    Err(Error::Quarantined)
}

#[inline(never)]
pub fn discard(stream: Stream<'_>) {
    drop(stream);
}
