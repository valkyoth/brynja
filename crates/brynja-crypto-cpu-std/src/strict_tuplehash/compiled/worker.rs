use super::{Algorithm, Bits, Cancellation, Error, Item, Kernel};
use brynja_crypto_cpu::static_execution::Authority;
use brynja_hash_tuple::{
    Fips202BitString,
    execution::{self as api, in_place as scoped},
};
pub(super) struct Operation<'a> {
    pub algorithm: Algorithm,
    pub kernel: Kernel,
    pub items: &'a [Item<'a>],
    pub customization: Bits<'a>,
    pub cancel: &'a Cancellation,
    #[cfg(test)]
    pub fault: super::tests::Fault,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Boundary {
    Setup,
    Item,
    Update,
    Complete,
    Finalize,
    Output,
}
pub(super) fn probe(kernel: Kernel) -> Result<(), Error> {
    let owner = Authority::new(kernel).map_err(Error::Backend)?;
    let session = api::KeccakSession::from_static(&owner).map_err(Error::Backend)?;
    if session.report().kernel != kernel {
        return Err(Error::Invariant);
    }
    session.check().map_err(Error::Backend)
}

// Only library-controlled protected workers call this function. Populated
// tuple state, item writers and framing scratch never cross the thread join.
pub(super) fn run(
    operation: Operation<'_>,
    staging: &mut [u8],
    destination: &mut [u8],
) -> Result<(), Error> {
    let Operation {
        algorithm,
        kernel,
        items,
        customization,
        cancel,
        #[cfg(test)]
        fault,
    } = operation;
    cancel.check()?;
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
    let transfer = |out: &mut [u8], input: &[u8]| {
        brynja_core::copy_secret_region(out, input).map_err(|_| Error::Invariant)?;
        checkpoint(Boundary::Output)
    };
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
    macro_rules! absorb {
        ($state:ident) => {
            checkpoint(Boundary::Setup)?;
            for item in items {
                checkpoint(Boundary::Item)?;
                let declared = super::super::item_bits(item)?;
                #[cfg(test)]
                let declared = super::tests::declared_bits(fault, declared);
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
                let mut writer = $state.begin_item(declared).map_err(Error::Execution)?;
                for chunk in item
                    .chunks
                    .iter()
                    .copied()
                    .chain(core::iter::once(complete))
                {
                    checkpoint(Boundary::Item)?;
                    for part in chunk.chunks(4096) {
                        checkpoint(Boundary::Item)?;
                        writer.update(part).map_err(Error::Execution)?;
                        checkpoint(Boundary::Update)?;
                    }
                }
                checkpoint(Boundary::Item)?;
                writer.update_bits(last).map_err(Error::Execution)?;
                writer.finish().map_err(Error::Execution)?;
                checkpoint(Boundary::Complete)?;
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
                .with_bits(customization, |mut state| {
                    absorb!(state);
                    let staged = staging
                        .get_mut(..destination.len())
                        .ok_or(Error::Invariant)?;
                    let secret = state
                        .finalize_secret_bits(staged, valid)
                        .map_err(Error::Execution)?;
                    checkpoint(Boundary::Item)?;
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
                .with_bits(customization, |mut state| {
                    absorb!(state);
                    let mut reader = state.finalize_xof().map_err(Error::Execution)?;
                    let mut remaining = &mut *destination;
                    while remaining.len() > staging.len() {
                        checkpoint(Boundary::Item)?;
                        let (out, rest) = remaining
                            .split_at_mut_checked(staging.len())
                            .ok_or(Error::Invariant)?;
                        let secret = reader.squeeze_secret(staging).map_err(Error::Execution)?;
                        transfer(out, secret.expose())?;
                        remaining = rest;
                    }
                    checkpoint(Boundary::Item)?;
                    let staged = staging.get_mut(..remaining.len()).ok_or(Error::Invariant)?;
                    let secret = reader
                        .squeeze_final_bits_secret(staged, valid)
                        .map_err(Error::Execution)?;
                    checkpoint(Boundary::Item)?;
                    transfer(remaining, secret.expose())
                })
                .map_err(Error::Execution)?
        }};
    }
    match algorithm {
        Algorithm::TupleHash128(_) => fixed!(scoped::TupleHash128Workspace::new(session)),
        Algorithm::TupleHash256(_) => fixed!(scoped::TupleHash256Workspace::new(session)),
        Algorithm::TupleHashXof128(_) => xof!(scoped::TupleHashXof128Workspace::new(session)),
        Algorithm::TupleHashXof256(_) => xof!(scoped::TupleHashXof256Workspace::new(session)),
    }?;
    checkpoint(Boundary::Finalize)
}
