use super::{Algorithm, Bits, Error, check};
use crate::CancellationToken;
use brynja_crypto_cpu_std::protected_memory::ProtectedStack;
use brynja_hash_parallel::{
    Fips202BitString, ParallelHash128Plan, ParallelHash256Plan, hardened_in_place as scoped,
};

// No secret value is returned from a worker: only canonical borrowed descriptors,
// exact-plan result loans into protected CV slots, and public status. Plan address
// is fixed before jobs exist and remains fixed until every result is consumed.
pub(super) struct Request<'a> {
    pub algorithm: Algorithm,
    pub input: Bits<'a>,
    pub block: usize,
    pub customization: Bits<'a>,
    pub cancel: &'a CancellationToken,
    #[cfg(test)]
    pub fault: super::tests::Fault,
}
pub(super) struct Resources<'a> {
    pub root: &'a mut ProtectedStack,
    pub workers: &'a mut [ProtectedStack],
    pub cvs: &'a mut [u8],
    pub staging: &'a mut [u8],
    pub destination: &'a mut [u8],
}
pub(super) fn run(request: Request<'_>, resources: Resources<'_>) -> Result<(), Error> {
    let Request {
        algorithm,
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
            super::tests::observe(&probe);
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
    macro_rules! execute {
        ($plan:ident, $workspace:ident, $width:literal) => {{
            let plan = $plan::new_bits(input, block).map_err(|_| Error::Invariant)?;
            let count = usize::try_from(plan.leaf_count()).map_err(|_| Error::WorkLimit)?;
            let bytes = count.checked_mul($width).ok_or(Error::WorkLimit)?;
            let storage = cvs.get_mut(..bytes).ok_or(Error::WorkLimit)?;
            let mut results = Vec::new();
            results
                .try_reserve_exact(count)
                .map_err(|_| Error::WorkLimit)?;
            results.resize_with(count, || None);
            let mut slots = storage.chunks_exact_mut($width);
            for (wave, results) in results.chunks_mut(workers.len()).enumerate() {
                check(cancel)?;
                let base = wave.checked_mul(workers.len()).ok_or(Error::Invariant)?;
                let mut jobs = Vec::new();
                jobs.try_reserve_exact(results.len())
                    .map_err(|_| Error::WorkLimit)?;
                for (offset, result) in results.iter_mut().enumerate() {
                    let mut output = Some(
                        <&mut [u8; $width]>::try_from(slots.next().ok_or(Error::Invariant)?)
                            .map_err(|_| Error::Invariant)?,
                    );
                    let index = base.checked_add(offset).ok_or(Error::Invariant)? as u128;
                    let plan = &plan;
                    jobs.push(move || {
                        *result = Some((|| {
                            check(cancel)?;
                            let output = output.take().ok_or(Error::Invariant)?;
                            #[cfg(test)]
                            {
                                let probe = core::hint::black_box([0u8; 8]);
                                super::tests::observe(output);
                                super::tests::observe(&probe);
                            }
                            let leaf = plan
                                .job(index)
                                .map_err(|_| Error::Invariant)?
                                .execute(output)
                                .map_err(|_| Error::Invariant)?;
                            #[cfg(test)]
                            super::tests::inject(fault, super::tests::Point::Leaf(index), cancel);
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
                    let mut workspace = scoped::$workspace::new();
                    #[cfg(test)]
                    {
                        super::tests::observe(&workspace);
                        super::tests::observe(staging);
                        super::tests::observe(destination);
                    }
                    workspace
                        .with_bits(&plan, customization, |mut collector| {
                            for result in &mut results {
                                check(cancel)?;
                                collector
                                    .merge(result.take().ok_or(Error::Invariant)??)
                                    .map_err(|_| Error::Invariant)?;
                            }
                            check(cancel)?;
                            #[cfg(test)]
                            super::tests::inject(fault, super::tests::Point::Root, cancel);
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
                            super::tests::inject(fault, super::tests::Point::Output, cancel);
                            check(cancel)
                        })
                        .map_err(|_| Error::Invariant)?
                })();
            })?;
            result
        }};
    }
    if algorithm.wide() {
        execute!(ParallelHash256Plan, ParallelHash256CollectorWorkspace, 64)
    } else {
        execute!(ParallelHash128Plan, ParallelHash128CollectorWorkspace, 32)
    }
}
fn transfer(destination: &mut [u8], source: &[u8]) -> Result<(), Error> {
    brynja_core::copy_secret_region(destination, source).map_err(|_| Error::Invariant)
}
