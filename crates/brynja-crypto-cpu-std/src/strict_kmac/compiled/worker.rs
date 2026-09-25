use super::{Algorithm, Bits, Cancellation, Error, Kernel, Request};
use brynja_crypto_cpu::static_execution::Authority;
use brynja_mac_kmac::{
    Fips202BitString,
    execution::{self as api, in_place as scoped},
};

pub(super) struct Operation<'a> {
    pub algorithm: Algorithm,
    pub kernel: Kernel,
    pub request: Request<'a>,
    pub candidate: Option<Bits<'a>>,
    pub cancel: &'a Cancellation,
    #[cfg(test)]
    pub fault: super::tests::Fault,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Boundary {
    Checkpoint,
    Setup,
    Update,
    Finalize,
    Output,
    Compare,
    Compared,
}

// These functions are entered only on the preacquired protected stack. Authority,
// key setup, scoped state and comparison must never be constructed on the caller.
pub(super) fn probe(kernel: Kernel) -> Result<(), Error> {
    let owner = Authority::new(kernel).map_err(Error::Backend)?;
    let session = api::KeccakSession::from_static(&owner).map_err(Error::Backend)?;
    if session.report().kernel != kernel {
        return Err(Error::Invariant);
    }
    session.check().map_err(Error::Backend)
}
pub(super) fn run(
    operation: Operation<'_>,
    staging: &mut [u8],
    destination: &mut [u8],
) -> Result<Option<bool>, Error> {
    let Operation {
        algorithm,
        kernel,
        request,
        candidate,
        cancel,
        #[cfg(test)]
        fault,
    } = operation;
    cancel.check()?;
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
    let owner = Authority::new(kernel).map_err(Error::Backend)?;
    let session = api::KeccakSession::from_static(&owner).map_err(Error::Backend)?;
    if session.report().kernel != kernel {
        return Err(Error::Invariant);
    }
    #[cfg(test)]
    super::tests::observe(staging, destination, &owner, &session);
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
            checkpoint(Boundary::Setup)?;
            for chunk in request
                .chunks
                .iter()
                .copied()
                .chain(core::iter::once(complete))
            {
                checkpoint(Boundary::Checkpoint)?;
                for part in chunk.chunks(4096) {
                    checkpoint(Boundary::Checkpoint)?;
                    $state.update(part).map_err(Error::Execution)?;
                    checkpoint(Boundary::Update)?;
                }
            }
            checkpoint(Boundary::Finalize)?;
        };
    }
    macro_rules! fixed {
        ($workspace:expr) => {{
            let mut workspace = $workspace.map_err(Error::Execution)?;
            #[cfg(test)]
            super::tests::observe_workspace(&workspace);
            workspace
                .with_bits(key, customization, |mut state| {
                    absorb!(state);
                    let secret = state
                        .finalize_secret_bits(last, staging, valid)
                        .map_err(Error::Execution)?;
                    checkpoint(Boundary::Checkpoint)?;
                    transfer(destination, secret.expose())
                })
                .map_err(Error::Execution)?
        }};
    }
    macro_rules! xof {
        ($workspace:expr) => {{
            let mut workspace = $workspace.map_err(Error::Execution)?;
            #[cfg(test)]
            super::tests::observe_workspace(&workspace);
            workspace
                .with_bits(key, customization, |mut state| {
                    absorb!(state);
                    let mut reader = state.finalize_bits_xof(last).map_err(Error::Execution)?;
                    let mut remaining = &mut *destination;
                    while remaining.len() > staging.len() {
                        checkpoint(Boundary::Checkpoint)?;
                        let (out, rest) = remaining
                            .split_at_mut_checked(staging.len())
                            .ok_or(Error::Invariant)?;
                        let secret = reader.squeeze_secret(staging).map_err(Error::Execution)?;
                        transfer(out, secret.expose())?;
                        remaining = rest;
                    }
                    checkpoint(Boundary::Checkpoint)?;
                    let staged = staging.get_mut(..remaining.len()).ok_or(Error::Invariant)?;
                    let secret = reader
                        .squeeze_final_bits_secret(staged, valid)
                        .map_err(Error::Execution)?;
                    checkpoint(Boundary::Checkpoint)?;
                    transfer(remaining, secret.expose())
                })
                .map_err(Error::Execution)?
        }};
    }
    match algorithm {
        Algorithm::Kmac128(_) => fixed!(scoped::Kmac128Workspace::new(session)),
        Algorithm::Kmac256(_) => fixed!(scoped::Kmac256Workspace::new(session)),
        Algorithm::KmacXof128(_) => xof!(scoped::KmacXof128Workspace::new(session)),
        Algorithm::KmacXof256(_) => xof!(scoped::KmacXof256Workspace::new(session)),
    }?;
    checkpoint(Boundary::Checkpoint)?;
    let result = if let Some(candidate) = candidate {
        {
            checkpoint(Boundary::Compare)?;
            let decision =
                super::super::worker::compare(destination, candidate.as_bytes(), cancel)?;
            #[cfg(test)]
            super::super::tests::require_comparison_count(destination.len());
            checkpoint(Boundary::Compared)?;
            Some(decision)
        }
    } else {
        None
    };
    checkpoint(Boundary::Checkpoint)?;
    Ok(result)
}
fn canonical(bits: Bits<'_>) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(bits.bytes, bits.valid_bits).map_err(|_| Error::InvalidBits)
}
