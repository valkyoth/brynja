use super::{Algorithm, Bits, Cancellation, Error, Kernel};
use brynja_crypto_cpu::static_execution::Authority;
use brynja_hash_sha3::{
    Fips202BitString,
    hardened_execution::{self as api, in_place as scoped},
};

pub(super) struct Request<'a> {
    pub algorithm: Algorithm,
    pub kernel: Kernel,
    pub chunks: &'a [&'a [u8]],
    pub tail: Bits<'a>,
    pub name: Bits<'a>,
    pub customization: Bits<'a>,
    pub cancel: &'a Cancellation,
    #[cfg(test)]
    pub fault: super::tests::Fault,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Boundary {
    Prefix,
    Update,
    Finalize,
    Output,
}

// Entered only from the preacquired protected worker. No populated authority,
// sponge, KAT scratch, or output stage may be constructed on the coordinator.
pub(super) fn probe(kernel: Kernel) -> Result<(), Error> {
    let owner = Authority::new(kernel).map_err(Error::Backend)?;
    let session = api::KeccakSession::from_static(&owner).map_err(Error::Backend)?;
    if session.report().kernel != kernel {
        return Err(Error::Invariant);
    }
    session.check().map_err(Error::Backend)
}
pub(super) fn run(request: Request<'_>, destination: &mut [u8]) -> Result<(), Error> {
    let Request {
        algorithm,
        kernel,
        chunks,
        tail,
        name,
        customization,
        cancel,
        #[cfg(test)]
        fault,
    } = request;
    cancel.check()?;
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
    let owner = Authority::new(kernel).map_err(Error::Backend)?;
    let session = api::KeccakSession::from_static(&owner).map_err(Error::Backend)?;
    if session.report().kernel != kernel {
        return Err(Error::Invariant);
    }
    let mut scratch = [0u8; 4096];
    #[cfg(test)]
    super::tests::observe(&scratch, destination, &owner, &session);
    let checkpoint = |point: Boundary| {
        let _ = point;
        #[cfg(test)]
        super::tests::inject(fault, point, &owner, cancel);
        owner.session().map_err(Error::Backend)?;
        cancel.check()
    };
    let transfer = |out: &mut [u8], source: &[u8]| {
        brynja_core::copy_secret_region(out, source).map_err(|_| Error::Invariant)?;
        checkpoint(Boundary::Output)
    };
    macro_rules! absorb {
        ($state:ident) => {
            // cSHAKE prefix setup has completed by callback entry. The public
            // customization budget bounds the non-interruptible prefix work.
            checkpoint(Boundary::Prefix)?;
            for chunk in chunks.iter().copied().chain(core::iter::once(complete)) {
                cancel.check()?;
                for part in chunk.chunks(4096) {
                    cancel.check()?;
                    $state.update(part).map_err(convert)?;
                    checkpoint(Boundary::Update)?;
                }
            }
            checkpoint(Boundary::Finalize)?;
        };
    }
    macro_rules! fixed {
        ($workspace:expr) => {{
            let mut workspace = $workspace.map_err(convert)?;
            #[cfg(test)]
            super::tests::observe_workspace(&workspace);
            workspace
                .with(|mut state| {
                    absorb!(state);
                    let staged = scratch
                        .get_mut(..destination.len())
                        .ok_or(Error::Invariant)?;
                    let secret = state.finalize_bits_secret(last, staged).map_err(convert)?;
                    cancel.check()?;
                    transfer(destination, secret.expose())
                })
                .map_err(convert)?
        }};
    }
    macro_rules! squeeze {
        ($state:ident) => {{
            absorb!($state);
            let mut reader = $state.finalize_bits_xof(last).map_err(convert)?;
            let mut remaining = destination;
            while remaining.len() > scratch.len() {
                cancel.check()?;
                let (out, rest) = remaining
                    .split_at_mut_checked(scratch.len())
                    .ok_or(Error::Invariant)?;
                let secret = reader.squeeze_secret(&mut scratch).map_err(convert)?;
                transfer(out, secret.expose())?;
                remaining = rest;
            }
            cancel.check()?;
            let staged = scratch.get_mut(..remaining.len()).ok_or(Error::Invariant)?;
            let valid = if staged.is_empty() {
                0
            } else {
                let last = algorithm
                    .output_bits()
                    .checked_sub(1)
                    .ok_or(Error::Invariant)?;
                u8::try_from((last % 8).checked_add(1).ok_or(Error::Invariant)?)
                    .map_err(|_| Error::Invariant)?
            };
            let secret = reader
                .squeeze_final_bits_secret(staged, valid)
                .map_err(convert)?;
            cancel.check()?;
            transfer(remaining, secret.expose())
        }};
    }
    macro_rules! xof {
        ($workspace:expr) => {{
            let mut workspace = $workspace.map_err(convert)?;
            #[cfg(test)]
            super::tests::observe_workspace(&workspace);
            workspace
                .with(|mut state| squeeze!(state))
                .map_err(convert)?
        }};
        ($workspace:expr, customized) => {{
            let mut workspace = $workspace.map_err(convert)?;
            #[cfg(test)]
            super::tests::observe_workspace(&workspace);
            workspace
                .with_bits(name, customization, |mut state| squeeze!(state))
                .map_err(convert)?
        }};
    }
    let result = match algorithm {
        Algorithm::Sha3_224 => fixed!(scoped::Sha3_224Workspace::new(session)),
        Algorithm::Sha3_256 => fixed!(scoped::Sha3_256Workspace::new(session)),
        Algorithm::Sha3_384 => fixed!(scoped::Sha3_384Workspace::new(session)),
        Algorithm::Sha3_512 => fixed!(scoped::Sha3_512Workspace::new(session)),
        Algorithm::Shake128(_) => xof!(scoped::Shake128Workspace::new(session)),
        Algorithm::Shake256(_) => xof!(scoped::Shake256Workspace::new(session)),
        Algorithm::Cshake128(_) => xof!(scoped::Cshake128Workspace::new(session), customized),
        Algorithm::Cshake256(_) => xof!(scoped::Cshake256Workspace::new(session), customized),
    };
    result?;
    owner.session().map_err(Error::Backend)?;
    cancel.check()
}
fn canonical(bits: Bits<'_>) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bits.bytes, bits.valid_bits).map_err(|_| Error::InvalidBits)
}
fn convert(error: api::Error) -> Error {
    match error {
        api::Error::Backend(error) => Error::Backend(error),
        _ => Error::Invariant,
    }
}
