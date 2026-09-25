use super::super::worker::Resources;
use super::{Algorithm, Bits, Error, Kernel, LeafRoute, check};
use brynja_crypto_cpu::static_execution::Authority;
use brynja_hash_parallel::execution::{KeccakSession, batch};
fn authority(kernel: Kernel) -> Result<Authority, Error> {
    if !matches!(kernel, Kernel::X86Keccak | Kernel::ArmKeccak) {
        return Err(Error::Backend(
            brynja_crypto_cpu::static_execution::Error::WrongOperation,
        ));
    }
    Authority::new(kernel).map_err(Error::Backend)
}
pub(super) fn probe(root: Kernel, leaves: LeafRoute) -> Result<(), Error> {
    let root = authority(root)?;
    KeccakSession::from_static(&root).map_err(Error::Backend)?;
    match leaves {
        LeafRoute::Single(kernel) => {
            let owner = authority(kernel)?;
            KeccakSession::from_static(&owner).map_err(Error::Backend)?;
        }
        LeafRoute::Batch(kernel) => {
            batch::Authority::for_compiled_target(kernel).map_err(|_| Error::Invariant)?;
        }
    }
    Ok(())
}
use crate::CancellationToken;
use brynja_crypto_cpu_std::protected_memory::ProtectedStack;
use brynja_hash_parallel::{
    Fips202BitString, ParallelHash128Plan, ParallelHash256Plan, execution::in_place as scoped,
};

// No secret value is returned from a worker: only canonical borrowed descriptors,
// exact-plan result loans into protected CV slots, and public status. Plan address
// is fixed before jobs exist and remains fixed until every result is consumed.
pub(super) struct Request<'a> {
    pub algorithm: Algorithm,
    pub root_kernel: Kernel,
    pub leaf_route: LeafRoute,
    pub input: Bits<'a>,
    pub block: usize,
    pub customization: Bits<'a>,
    pub cancel: &'a CancellationToken,
    #[cfg(test)]
    pub fault: super::tests::Fault,
}
pub(super) fn run(request: Request<'_>, resources: Resources<'_>) -> Result<(), Error> {
    let Request {
        algorithm,
        root_kernel,
        leaf_route,
        input,
        block,
        customization,
        cancel,
        #[cfg(test)]
        fault,
    } = request;
    let Resources {
        root,
        workers,
        cvs,
        staging,
        destination,
    } = resources;
    let mut canonical = Err(Error::Invariant);
    root.run(|| {
        #[cfg(test)]
        {
            let probe = core::hint::black_box([0u8; 8]);
            super::super::tests::observe(&probe);
        }
        canonical = (|| {
            Ok((
                Fips202BitString::new(input.bytes, input.valid_bits)
                    .map_err(|_| Error::InvalidBits)?,
                Fips202BitString::new(customization.bytes, customization.valid_bits)
                    .map_err(|_| Error::InvalidBits)?,
            ))
        })();
    })?;
    let (input, customization) = canonical?;
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
    macro_rules! single {
        ($plan:ident, $index:ident, $output:ident, $leaf:ident, $width:literal) => {{
            let LeafRoute::Single(kernel) = leaf_route else {
                return Err(Error::Invariant);
            };
            let owner = authority(kernel)?;
            let session = KeccakSession::from_static(&owner).map_err(Error::Backend)?;
            let mut workspace = scoped::$leaf::new(session).map_err(Error::Execution)?;
            #[cfg(test)]
            super::tests::observe(&owner, &workspace);
            let output = <&mut [u8; $width]>::try_from($output).map_err(|_| Error::Invariant)?;
            let result = workspace
                .execute($plan.job($index).map_err(Error::Execution)?, output)
                .map_err(Error::Execution)?;
            #[cfg(test)]
            super::tests::inject(fault, super::tests::Point::Leaf($index), cancel, || {
                owner.quarantine()
            });
            owner.session().map_err(Error::Backend)?;
            result
        }};
    }
    macro_rules! grouped {
        ($plan:ident, $index:ident, $output:ident, $leaf:ident, $width:literal) => {{
            let LeafRoute::Batch(kernel) = leaf_route else {
                return Err(Error::Invariant);
            };
            let owner =
                batch::Authority::for_compiled_target(kernel).map_err(|_| Error::Invariant)?;
            let executor = batch::Executor::with_session(
                owner.session().map_err(|_| Error::Invariant)?,
                batch::Mode::Prefer,
                1,
            )
            .map_err(|_| Error::Invariant)?;
            let mut workspace = batch::Workspace::new();
            #[cfg(test)]
            super::tests::observe(&owner, &workspace);
            let (slots, remainder) = $output.as_chunks_mut::<64>();
            if !remainder.is_empty() {
                return Err(Error::Invariant);
            }
            let slots = <&mut [[u8; 64]; 4]>::try_from(slots).map_err(|_| Error::Invariant)?;
            let count = usize::try_from(
                $plan
                    .leaf_count()
                    .checked_sub($index)
                    .ok_or(Error::Invariant)?
                    .min(4),
            )
            .map_err(|_| Error::Invariant)?;
            let max_work = u64::try_from(block / 72)
                .ok()
                .and_then(|n| n.checked_add(2))
                .and_then(|n| n.checked_mul(4))
                .ok_or(Error::WorkLimit)?;
            let mut cancelled = || cancel.is_cancelled();
            let result = $plan
                .batch($index, count)
                .map_err(Error::Batch)?
                .execute_into(
                    &executor,
                    &mut workspace,
                    slots,
                    &mut batch::Control::new(max_work, &mut cancelled),
                )
                .map_err(batch_error)?;
            #[cfg(test)]
            super::tests::observe_batch(result.report());
            #[cfg(test)]
            super::tests::inject(fault, super::tests::Point::Leaf($index), cancel, || {
                owner.quarantine()
            });
            owner.session().map_err(|_| Error::Quarantined)?;
            result
        }};
    }
    macro_rules! execute {
        ($plan:ident, $workspace:ident, $leaf:ident, $width:literal, $stride:literal, $group:literal, $execute:ident, $merge:ident) => {{
            let plan = $plan::new_bits(input, block).map_err(|_| Error::Invariant)?;
            let leaves = usize::try_from(plan.leaf_count()).map_err(|_| Error::WorkLimit)?;
            let count = leaves.div_ceil($group);
            let bytes = count.checked_mul($stride).ok_or(Error::WorkLimit)?;
            let storage = cvs.get_mut(..bytes).ok_or(Error::WorkLimit)?;
            let mut results = Vec::new();
            results
                .try_reserve_exact(count)
                .map_err(|_| Error::WorkLimit)?;
            results.resize_with(count, || None);
            let mut slots = storage.chunks_exact_mut($stride);
            for (wave, results) in results.chunks_mut(workers.len()).enumerate() {
                check(cancel)?;
                let base = wave.checked_mul(workers.len()).ok_or(Error::Invariant)?;
                let mut jobs = Vec::new();
                jobs.try_reserve_exact(results.len())
                    .map_err(|_| Error::WorkLimit)?;
                for (offset, result) in results.iter_mut().enumerate() {
                    let mut output = Some(slots.next().ok_or(Error::Invariant)?);
                    let index = base
                        .checked_add(offset)
                        .and_then(|n| n.checked_mul($group))
                        .ok_or(Error::Invariant)? as u128;
                    let plan = &plan;
                    jobs.push(move || {
                        *result = Some((|| {
                            check(cancel)?;
                            let output = output.take().ok_or(Error::Invariant)?;
                            #[cfg(test)]
                            {
                                let probe = core::hint::black_box([0u8; 8]);
                                super::super::tests::observe(output);
                                super::super::tests::observe(&probe);
                            }
                            let leaf = $execute!(plan, index, output, $leaf, $width);
                            check(cancel)?;
                            Ok(leaf)
                        })());
                    });
                }
                ProtectedStack::run_group(
                    workers.get_mut(..jobs.len()).ok_or(Error::Invariant)?,
                    &mut jobs,
                )?;
                drop(jobs);
                for result in results.iter() {
                    match result {
                        Some(Ok(_)) => (),
                        Some(Err(error)) => return Err(*error),
                        None => return Err(Error::Invariant),
                    }
                }
            }
            #[cfg(test)]
            if matches!(fault, super::tests::Fault::Reorder) && results.len() >= 2 {
                results.swap(0, 1);
            }
            let mut result = Err(Error::Invariant);
            root.run(|| {
                result = (|| {
                    check(cancel)?;
                    let owner = authority(root_kernel)?;
                    let session = KeccakSession::from_static(&owner).map_err(Error::Backend)?;
                    let mut workspace =
                        scoped::$workspace::new(session).map_err(Error::Execution)?;
                    #[cfg(test)]
                    {
                        super::super::tests::observe(&workspace);
                        super::super::tests::observe(staging);
                        super::super::tests::observe(destination);
                    }
                    workspace
                        .with_bits(&plan, customization, |mut collector| {
                            for result in &mut results {
                                check(cancel)?;
                                collector
                                    .$merge(result.take().ok_or(Error::Invariant)??)
                                    .map_err(|_| Error::Invariant)?;
                            }
                            check(cancel)?;
                            #[cfg(test)]
                            super::tests::inject(fault, super::tests::Point::Root, cancel, || {
                                owner.quarantine()
                            });
                            check(cancel)?;
                            if algorithm.xof() {
                                let mut reader =
                                    collector.finalize_xof().map_err(|_| Error::Invariant)?;
                                let mut remaining = &mut *destination;
                                while remaining.len() > staging.len() {
                                    check(cancel)?;
                                    let (out, rest) = remaining
                                        .split_at_mut_checked(staging.len())
                                        .ok_or(Error::Invariant)?;
                                    let secret = reader
                                        .squeeze_secret(staging)
                                        .map_err(|_| Error::Invariant)?;
                                    transfer(out, secret.expose())?;
                                    remaining = rest;
                                }
                                check(cancel)?;
                                let secret = reader
                                    .squeeze_final_bits_secret(
                                        staging
                                            .get_mut(..remaining.len())
                                            .ok_or(Error::Invariant)?,
                                        valid,
                                    )
                                    .map_err(|_| Error::Invariant)?;
                                transfer(remaining, secret.expose())?;
                            } else {
                                let secret = collector
                                    .finalize_secret_bits(
                                        staging
                                            .get_mut(..destination.len())
                                            .ok_or(Error::Invariant)?,
                                        valid,
                                    )
                                    .map_err(|_| Error::Invariant)?;
                                transfer(destination, secret.expose())?;
                            }
                            #[cfg(test)]
                            super::tests::inject(
                                fault,
                                super::tests::Point::Output,
                                cancel,
                                || owner.quarantine(),
                            );
                            owner.session().map_err(Error::Backend)?;
                            check(cancel)
                        })
                        .map_err(|_| Error::Invariant)?
                })();
            })?;
            result
        }};
    }
    match (algorithm.wide(), leaf_route) {
        (true, LeafRoute::Single(_)) => execute!(
            ParallelHash256Plan,
            ParallelHash256CollectorWorkspace,
            ParallelHash256LeafWorkspace,
            64,
            64,
            1,
            single,
            merge
        ),
        (false, LeafRoute::Single(_)) => execute!(
            ParallelHash128Plan,
            ParallelHash128CollectorWorkspace,
            ParallelHash128LeafWorkspace,
            32,
            32,
            1,
            single,
            merge
        ),
        (true, LeafRoute::Batch(_)) => execute!(
            ParallelHash256Plan,
            ParallelHash256CollectorWorkspace,
            ParallelHash256LeafWorkspace,
            64,
            256,
            4,
            grouped,
            merge_batch
        ),
        (false, LeafRoute::Batch(_)) => execute!(
            ParallelHash128Plan,
            ParallelHash128CollectorWorkspace,
            ParallelHash128LeafWorkspace,
            32,
            256,
            4,
            grouped,
            merge_batch
        ),
    }
}
fn transfer(destination: &mut [u8], source: &[u8]) -> Result<(), Error> {
    brynja_core::copy_secret_region(destination, source).map_err(|_| Error::Invariant)
}

// Classify the actual result, never the concurrently changing cancellation flag:
// cancellation must not turn a backend failure into a reusable request rejection.
pub(super) fn batch_error(error: batch::Error) -> Error {
    match error {
        batch::Error::Hash(batch::HashError::Cancelled) => Error::Cancelled,
        other => Error::Batch(other),
    }
}
