use super::{Algorithm, Cancellation, Error, Request};
use brynja_legacy_hmac::{Hmac, LegacyUse};

pub(super) fn checkpoint(cancel: &Cancellation) -> Result<(), Error> {
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
    // Inspect canonical secret contents only on the resident worker.
    crate::common::split_tail!(request, complete, tail, Error);
    let mut state = Hmac::<A>::with_tag_length(LegacyUse::acknowledge(), request.key, bytes)
        .map_err(Error::Mac)?;
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
            crate::common::verification_decision(state.verify_bits(tail, candidate))
                .map_err(Error::Mac)?,
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
