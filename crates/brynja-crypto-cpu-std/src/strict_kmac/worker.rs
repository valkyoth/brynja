use super::{Algorithm, Bits, Cancellation, Error, Request};
use brynja_mac_kmac::{Fips202BitString, hardened_in_place as scoped};

// Workspaces, framing and comparison are created only after protected-stack entry.
pub(super) fn run(
    algorithm: Algorithm,
    request: Request<'_>,
    candidate: Option<Bits<'_>>,
    cancel: &Cancellation,
    staging: &mut [u8],
    destination: &mut [u8],
) -> Result<Option<bool>, Error> {
    checkpoint(cancel)?;
    let key = canonical(request.key)?;
    let customization = canonical(request.customization)?;
    let tail = canonical(request.tail)?;
    let candidate = candidate.map(canonical).transpose()?;
    let split = if tail.is_byte_aligned() {
        tail.as_bytes().len()
    } else {
        tail.as_bytes()
            .len()
            .checked_sub(1)
            .ok_or(Error::Invariant)?
    };
    let (complete, partial) = tail
        .as_bytes()
        .split_at_checked(split)
        .ok_or(Error::Invariant)?;
    let last = Fips202BitString::new(
        partial,
        if partial.is_empty() {
            0
        } else {
            tail.valid_bits_in_last_byte()
        },
    )
    .map_err(|_| Error::InvalidBits)?;
    let valid = if algorithm.output_bits() == 0 {
        0
    } else {
        let last = algorithm
            .output_bits()
            .checked_sub(1)
            .ok_or(Error::Invariant)?;
        u8::try_from((last % 8).checked_add(1).ok_or(Error::Invariant)?)
            .map_err(|_| Error::Invariant)?
    };
    #[cfg(test)]
    {
        super::tests::observe_storage(staging);
        super::tests::observe_storage(destination);
    }
    macro_rules! absorb {
        ($state:ident) => {
            for chunk in request
                .chunks
                .iter()
                .copied()
                .chain(core::iter::once(complete))
            {
                checkpoint(cancel)?;
                for part in chunk.chunks(4096) {
                    checkpoint(cancel)?;
                    $state.update(part).map_err(|_| Error::Invariant)?;
                }
            }
            checkpoint(cancel)?;
        };
    }
    macro_rules! fixed {
        ($workspace:expr) => {{
            let mut workspace = $workspace;
            #[cfg(test)]
            super::tests::observe_storage(&workspace);
            workspace
                .with_bits(key, customization, |mut state| {
                    absorb!(state);
                    let secret = state
                        .finalize_secret_bits(last, staging, valid)
                        .map_err(|_| Error::Invariant)?;
                    checkpoint(cancel)?;
                    transfer(destination, secret.expose())
                })
                .map_err(|_| Error::Invariant)?
        }};
    }
    macro_rules! xof {
        ($workspace:expr) => {{
            let mut workspace = $workspace;
            #[cfg(test)]
            super::tests::observe_storage(&workspace);
            workspace
                .with_bits(key, customization, |mut state| {
                    absorb!(state);
                    let mut reader = state
                        .finalize_bits_xof(last)
                        .map_err(|_| Error::Invariant)?;
                    let mut remaining = &mut *destination;
                    while remaining.len() > staging.len() {
                        checkpoint(cancel)?;
                        let (out, rest) = remaining
                            .split_at_mut_checked(staging.len())
                            .ok_or(Error::Invariant)?;
                        let secret = reader
                            .squeeze_secret(staging)
                            .map_err(|_| Error::Invariant)?;
                        transfer(out, secret.expose())?;
                        remaining = rest;
                    }
                    checkpoint(cancel)?;
                    let staged = staging.get_mut(..remaining.len()).ok_or(Error::Invariant)?;
                    let secret = reader
                        .squeeze_final_bits_secret(staged, valid)
                        .map_err(|_| Error::Invariant)?;
                    checkpoint(cancel)?;
                    transfer(remaining, secret.expose())
                })
                .map_err(|_| Error::Invariant)?
        }};
    }
    match algorithm {
        Algorithm::Kmac128(_) => fixed!(scoped::Kmac128Workspace::new()),
        Algorithm::Kmac256(_) => fixed!(scoped::Kmac256Workspace::new()),
        Algorithm::KmacXof128(_) => xof!(scoped::KmacXof128Workspace::new()),
        Algorithm::KmacXof256(_) => xof!(scoped::KmacXof256Workspace::new()),
    }?;
    checkpoint(cancel)?;
    let result = if let Some(candidate) = candidate {
        Some(compare(destination, candidate.as_bytes(), cancel)?)
    } else {
        None
    };
    checkpoint(cancel)?;
    Ok(result)
}
fn canonical(bits: Bits<'_>) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bits.bytes, bits.valid_bits).map_err(|_| Error::InvalidBits)
}
fn checkpoint(cancel: &Cancellation) -> Result<(), Error> {
    #[cfg(test)]
    super::tests::checkpoint(cancel);
    cancel.check()
}
fn transfer(destination: &mut [u8], source: &[u8]) -> Result<(), Error> {
    brynja_core::copy_secret_region(destination, source).map_err(|_| Error::Invariant)?;
    #[cfg(test)]
    super::tests::after_write();
    Ok(())
}
struct Difference([u8; 1]);
impl Drop for Difference {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(&mut self.0);
    }
}
fn compare(expected: &[u8], candidate: &[u8], cancel: &Cancellation) -> Result<bool, Error> {
    if expected.len() != candidate.len() {
        return Err(Error::Invariant);
    }
    let mut difference = Difference([0]);
    #[cfg(test)]
    super::tests::observe_storage(&difference);
    for (left, right) in expected.chunks(4096).zip(candidate.chunks(4096)) {
        checkpoint(cancel)?;
        for (left, right) in left.iter().zip(right) {
            brynja_core::accumulate_secret_byte_difference(&mut difference.0[0], left, right);
            #[cfg(test)]
            super::tests::compared_byte();
        }
    }
    // Only the explicitly declassified authentication bit leaves this worker.
    Ok(brynja_core::secret_difference_is_zero(&difference.0[0]).expose_public())
}
