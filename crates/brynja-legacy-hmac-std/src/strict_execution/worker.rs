use super::{Algorithm, Cancellation, Error, Request};
use brynja_legacy_hmac::{BitString, Hmac, LegacyUse};

fn checkpoint(cancel: &Cancellation) -> Result<(), Error> {
    #[cfg(test)]
    super::tests::checkpoint(cancel);
    cancel.check()
}

pub(super) fn run<A: Algorithm>(
    bytes: usize,
    request: Request<'_>,
    candidate: Option<&[u8]>,
    cancel: &Cancellation,
    staging: &mut [u8],
    destination: &mut [u8],
) -> Result<Option<bool>, Error> {
    checkpoint(cancel)?;
    // Inspect canonical secret contents only on the protected worker.
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
    let mut state = Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), request.key, bytes)
        .map_err(Error::Mac)?;
    #[cfg(test)]
    super::tests::observe(&state, staging, destination);
    for chunk in request
        .chunks
        .iter()
        .copied()
        .chain(core::iter::once(complete))
    {
        checkpoint(cancel)?;
        for part in chunk.chunks(4096) {
            checkpoint(cancel)?;
            state.update(part).map_err(Error::Mac)?;
        }
    }
    checkpoint(cancel)?;
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
        checkpoint(cancel)?;
        brynja_core::copy_secret_region(destination, secret.expose())
            .map_err(|_| Error::Invariant)?;
        #[cfg(test)]
        super::tests::after_write(cancel);
        None
    };
    checkpoint(cancel)?;
    Ok(result)
}
