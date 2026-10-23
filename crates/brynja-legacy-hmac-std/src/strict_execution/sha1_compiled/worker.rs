use super::{Cancellation, Error, LegacyUse, Request, Sha1Backend};
use brynja_legacy_hmac::{
    BitString,
    execution::{Sha1Executor, Sha1Hmac, Sha1Mode},
};

pub(super) fn probe() -> Result<Sha1Backend, Error> {
    let owner = Sha1Executor::for_compiled_target(Sha1Mode::Require)
        .map_err(|_| Error::Mac(brynja_legacy_hmac::Error::ExecutionUnavailable))?;
    owner.report().backend.ok_or(Error::Invariant)
}

fn checkpoint(owner: &Sha1Executor, cancel: &Cancellation) -> Result<(), Error> {
    #[cfg(test)]
    super::tests::checkpoint(owner);
    // Health/revalidation wins over cancellation. The temporary empty stream
    // contains no key; start() validates authority, not only cached metadata.
    drop(
        owner
            .start()
            .map_err(|_| Error::Mac(brynja_legacy_hmac::Error::ExecutionFailed))?,
    );
    super::super::worker::checkpoint(cancel)
}

pub(super) fn run(
    backend: Sha1Backend,
    bytes: usize,
    request: Request<'_>,
    candidate: Option<&[u8]>,
    cancel: &Cancellation,
    staging: &mut [u8],
    output: &mut [u8],
) -> Result<Option<bool>, Error> {
    let owner = Sha1Executor::for_compiled_target(Sha1Mode::Require)
        .map_err(|_| Error::Mac(brynja_legacy_hmac::Error::ExecutionFailed))?;
    if owner.report().backend != Some(backend) {
        return Err(Error::Invariant);
    }
    checkpoint(&owner, cancel)?;
    let _ = BitString::new(request.tail.bytes, request.tail.valid_bits)
        .map_err(|_| Error::InvalidBits)?;
    let split = if request.tail.valid_bits == 8 || request.tail.bytes.is_empty() {
        request.tail.bytes.len()
    } else {
        request
            .tail
            .bytes
            .len()
            .checked_sub(1)
            .ok_or(Error::InvalidBits)?
    };
    let (complete, partial) = request
        .tail
        .bytes
        .split_at_checked(split)
        .ok_or(Error::Invariant)?;
    let tail = BitString::new(
        partial,
        if partial.is_empty() {
            0
        } else {
            request.tail.valid_bits
        },
    )
    .map_err(|_| Error::InvalidBits)?;
    let mut state = Sha1Hmac::with_tag_length(LegacyUse::acknowledge(), &owner, request.key, bytes)
        .map_err(Error::Mac)?;
    #[cfg(test)]
    super::super::tests::observe(&state, staging, output);
    for chunk in request
        .chunks
        .iter()
        .copied()
        .chain(core::iter::once(complete))
    {
        checkpoint(&owner, cancel)?;
        for part in chunk.chunks(4096) {
            checkpoint(&owner, cancel)?;
            state.update(part).map_err(Error::Mac)?;
        }
    }
    checkpoint(&owner, cancel)?;
    let result = if let Some(candidate) = candidate {
        Some(
            state
                .verify_bits(tail, candidate)
                .map_err(Error::Mac)?
                .expose_public(),
        )
    } else {
        let secret = state
            .finalize_bits_secret(tail, staging)
            .map_err(Error::Mac)?;
        checkpoint(&owner, cancel)?;
        brynja_core::copy_secret_region(output, secret.expose()).map_err(|_| Error::Invariant)?;
        #[cfg(test)]
        super::super::tests::after_write(cancel);
        None
    };
    checkpoint(&owner, cancel)?;
    Ok(result)
}
