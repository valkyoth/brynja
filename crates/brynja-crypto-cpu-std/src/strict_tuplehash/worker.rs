use super::{Algorithm, Bits, Cancellation, Error, Item};
use brynja_hash_tuple::{Fips202BitString, hardened_in_place as scoped};

// Only library-controlled protected workers call this function. Populated
// tuple state, item writers and framing scratch never cross the thread join.
pub(super) fn run(
    algorithm: Algorithm,
    items: &[Item<'_>],
    customization: Bits<'_>,
    cancel: &Cancellation,
    staging: &mut [u8],
    destination: &mut [u8],
) -> Result<(), Error> {
    checkpoint(cancel)?;
    let customization = Fips202BitString::new(customization.bytes, customization.valid_bits)
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
            for item in items {
                checkpoint(cancel)?;
                let declared = super::item_bits(item)?;
                #[cfg(test)]
                let declared = super::tests::declared_bits(declared);
                let tail = Fips202BitString::new(item.tail.bytes, item.tail.valid_bits)
                    .map_err(|_| Error::InvalidBits)?;
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
                let mut writer = $state.begin_item(declared).map_err(|_| Error::Invariant)?;
                for chunk in item
                    .chunks
                    .iter()
                    .copied()
                    .chain(core::iter::once(complete))
                {
                    checkpoint(cancel)?;
                    for part in chunk.chunks(4096) {
                        checkpoint(cancel)?;
                        writer.update(part).map_err(|_| Error::Invariant)?;
                    }
                }
                checkpoint(cancel)?;
                writer.update_bits(last).map_err(|_| Error::Invariant)?;
                writer.finish().map_err(|_| Error::Invariant)?;
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
                .with_bits(customization, |mut state| {
                    absorb!(state);
                    let staged = staging
                        .get_mut(..destination.len())
                        .ok_or(Error::Invariant)?;
                    let secret = state
                        .finalize_secret_bits(staged, valid)
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
                .with_bits(customization, |mut state| {
                    absorb!(state);
                    let mut reader = state.finalize_xof().map_err(|_| Error::Invariant)?;
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
        Algorithm::TupleHash128(_) => fixed!(scoped::TupleHash128Workspace::new()),
        Algorithm::TupleHash256(_) => fixed!(scoped::TupleHash256Workspace::new()),
        Algorithm::TupleHashXof128(_) => xof!(scoped::TupleHashXof128Workspace::new()),
        Algorithm::TupleHashXof256(_) => xof!(scoped::TupleHashXof256Workspace::new()),
    }?;
    checkpoint(cancel)
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
