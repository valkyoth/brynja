use super::{Algorithm, Bits, Cancellation, Error};
use brynja_hash_sha3::{Fips202BitString, Fips202Output, hardened_in_place as scoped};

// Only library-controlled protected workers call this function. Populated
// workspace and staging never move across the native thread boundary.
pub(super) fn run(
    algorithm: Algorithm,
    chunks: &[&[u8]],
    tail: Bits<'_>,
    name: Bits<'_>,
    customization: Bits<'_>,
    cancel: &Cancellation,
    destination: &mut [u8],
) -> Result<(), Error> {
    checkpoint(cancel)?;
    let tail = canonical(tail)?;
    let name = canonical(name)?;
    let customization = canonical(customization)?;
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
    let mut scratch = [0u8; 4096];
    #[cfg(test)]
    super::tests::observe_storage(&scratch);

    macro_rules! absorb {
        ($state:ident) => {
            for chunk in chunks.iter().copied().chain(core::iter::once(complete)) {
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
            workspace.with(|mut state| {
                absorb!(state);
                let staged = scratch
                    .get_mut(..destination.len())
                    .ok_or(Error::Invariant)?;
                let secret = state
                    .finalize_bits_secret(last, staged)
                    .map_err(|_| Error::Invariant)?;
                checkpoint(cancel)?;
                transfer(destination, secret.expose())
            })
        }};
    }
    macro_rules! squeeze {
        ($state:ident) => {{
            absorb!($state);
            let mut reader = $state
                .finalize_bits_xof(last)
                .map_err(|_| Error::Invariant)?;
            let mut remaining = destination;
            while remaining.len() > scratch.len() {
                checkpoint(cancel)?;
                let (out, rest) = remaining
                    .split_at_mut_checked(scratch.len())
                    .ok_or(Error::Invariant)?;
                let secret = reader
                    .squeeze_secret(&mut scratch)
                    .map_err(|_| Error::Invariant)?;
                transfer(out, secret.expose())?;
                remaining = rest;
            }
            checkpoint(cancel)?;
            let staged = scratch.get_mut(..remaining.len()).ok_or(Error::Invariant)?;
            let valid = if staged.is_empty() {
                0
            } else {
                let last = algorithm
                    .output_bits()
                    .checked_sub(1)
                    .ok_or(Error::Invariant)?;
                let valid = (last % 8).checked_add(1).ok_or(Error::Invariant)?;
                u8::try_from(valid).map_err(|_| Error::Invariant)?
            };
            let output = Fips202Output::new(staged, valid).map_err(|_| Error::Invariant)?;
            let secret = reader
                .squeeze_final_bits_secret(output)
                .map_err(|_| Error::Invariant)?;
            checkpoint(cancel)?;
            transfer(remaining, secret.expose())
        }};
    }
    macro_rules! xof {
        ($workspace:expr) => {{
            let mut workspace = $workspace;
            #[cfg(test)]
            super::tests::observe_storage(&workspace);
            workspace.with(|mut state| squeeze!(state))
        }};
        ($workspace:expr, customized) => {{
            let mut workspace = $workspace;
            #[cfg(test)]
            super::tests::observe_storage(&workspace);
            workspace
                .with_bits(name, customization, |mut state| squeeze!(state))
                .map_err(|_| Error::Invariant)?
        }};
    }
    let result = match algorithm {
        Algorithm::Sha3_224 => fixed!(scoped::Sha3_224Workspace::new()),
        Algorithm::Sha3_256 => fixed!(scoped::Sha3_256Workspace::new()),
        Algorithm::Sha3_384 => fixed!(scoped::Sha3_384Workspace::new()),
        Algorithm::Sha3_512 => fixed!(scoped::Sha3_512Workspace::new()),
        Algorithm::Shake128(_) => xof!(scoped::Shake128Workspace::new()),
        Algorithm::Shake256(_) => xof!(scoped::Shake256Workspace::new()),
        Algorithm::Cshake128(_) => xof!(scoped::Cshake128Workspace::new(), customized),
        Algorithm::Cshake256(_) => xof!(scoped::Cshake256Workspace::new(), customized),
    };
    result?;
    checkpoint(cancel)
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
