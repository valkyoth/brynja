use super::{Config, Error, Selection, Slots, accelerated, crypto, hash, live};
use crate::{
    CancellationToken,
    scoped_worker::{Spawner, System},
};
use hash::execution::Mode;
use std::thread;

macro_rules! worker {
    ($run:ident, $using:ident, $batch:ident, $leaf:ident, $plan:ident, $job:ident, $result:ident, $workspace:ident, $width:expr) => {
        pub(super) fn $run<'plan, 'input>(
            plan: &'plan hash::$plan<'input>,
            config: &Config,
            cancellation: &CancellationToken,
            merge: impl for<'out> FnMut(
                hash::$result<'plan, 'out>,
            ) -> Result<(), hash::ParallelHashError>,
        ) -> Result<u128, Error> {
            $using(plan, config, cancellation, merge, &mut System)
        }
        fn $using<'plan, 'input>(
            plan: &'plan hash::$plan<'input>,
            config: &Config,
            cancellation: &CancellationToken,
            mut merge: impl for<'out> FnMut(
                hash::$result<'plan, 'out>,
            ) -> Result<(), hash::ParallelHashError>,
            spawner: &mut impl Spawner,
        ) -> Result<u128, Error> {
            live(cancellation)?;
            if !(1..=64).contains(&config.workers) || config.max_leaves == 0 {
                return Err(Error::Limits);
            }
            if plan.leaf_count() > config.max_leaves {
                return Err(Error::Crypto(hash::execution::Error::WorkLimit));
            }
            let leaves = usize::try_from(plan.leaf_count()).map_err(|_| Error::Limits)?;
            let mut slots =
                Slots::<$width>::new(leaves.min(config.workers)).map_err(|_| Error::Resource)?;
            let mut base = 0usize;
            let mut accelerated = 0u128;
            while base < leaves {
                live(cancellation)?;
                let count = leaves
                    .checked_sub(base)
                    .ok_or(Error::Limits)?
                    .min(slots.0.len());
                let batch = slots.0.get_mut(..count).ok_or(Error::Limits)?;
                let used = $batch(
                    plan,
                    base,
                    batch,
                    config.leaves,
                    cancellation,
                    &mut merge,
                    spawner,
                )?;
                accelerated = accelerated.checked_add(used).ok_or(Error::Limits)?;
                base = base.checked_add(count).ok_or(Error::Limits)?;
            }
            live(cancellation)?;
            Ok(accelerated)
        }
        // Called on the worker thread: authority and empty sponge storage are
        // local. Results retain plan/output borrows, not a live authority lease.
        fn $leaf<'plan, 'input, 'out>(
            job: hash::$job<'plan, 'input>,
            output: &'out mut [u8; $width],
            owner: &Selection,
        ) -> Result<(hash::$result<'plan, 'out>, bool), Error> {
            let _ = brynja_core::clear_owned_region(output);
            match owner.mode()? {
                Mode::Portable | Mode::Prefer(None) => {
                    Ok((job.execute(output).map_err(crypto)?, false))
                }
                Mode::Require(None) => Err(Error::Unavailable),
                Mode::Require(Some(session)) | Mode::Prefer(Some(session)) => {
                    let mut workspace = accelerated::$workspace::new(session).map_err(crypto)?;
                    Ok((workspace.execute(job, output).map_err(crypto)?, true))
                }
            }
        }
        fn $batch<'plan, 'input>(
            plan: &'plan hash::$plan<'input>,
            base: usize,
            slots: &mut [[u8; $width]],
            preference: super::super::Preference,
            cancellation: &CancellationToken,
            merge: &mut impl for<'out> FnMut(
                hash::$result<'plan, 'out>,
            ) -> Result<(), hash::ParallelHashError>,
            spawner: &mut impl Spawner,
        ) -> Result<u128, Error> {
            thread::scope(|scope| {
                let mut handles = Vec::new();
                handles
                    .try_reserve_exact(slots.len())
                    .map_err(|_| Error::Resource)?;
                let mut failure = None;
                for (offset, destination) in slots.iter_mut().enumerate() {
                    let prepared = (|| {
                        live(cancellation)?;
                        let index = base.checked_add(offset).ok_or(Error::Limits)?;
                        plan.job(u128::try_from(index).map_err(|_| Error::Limits)?)
                            .map_err(crypto)
                    })();
                    let job = match prepared {
                        Ok(job) => job,
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    };
                    match spawner.spawn(scope, move || {
                        live(cancellation)?;
                        let owner = Selection::new(preference)?;
                        let result = $leaf(job, destination, &owner)?;
                        live(cancellation)?;
                        Ok::<_, Error>(result)
                    }) {
                        Ok(handle) => handles.push(handle),
                        Err(_) => {
                            failure = Some(Error::Resource);
                            break;
                        }
                    }
                }
                let mut accelerated = 0u128;
                // Every started job joins on ordinary errors; scope joining
                // plus the parent slot guard also cover coordinator unwinding.
                for handle in handles {
                    match handle.join() {
                        Err(_) => {
                            failure.get_or_insert(Error::WorkerPanicked);
                        }
                        Ok(Err(error)) => {
                            failure.get_or_insert(error);
                        }
                        Ok(Ok((leaf, used))) => {
                            if failure.is_none() {
                                let merged = (|| {
                                    live(cancellation)?;
                                    merge(leaf).map_err(crypto)?;
                                    accelerated = accelerated
                                        .checked_add(u128::from(used))
                                        .ok_or(Error::Limits)?;
                                    Ok::<_, Error>(())
                                })();
                                if let Err(error) = merged {
                                    failure = Some(error);
                                }
                            }
                        }
                    }
                }
                failure.map_or(Ok(accelerated), Err)
            })
        }
    };
}
worker!(
    run128,
    run128_with,
    batch128,
    leaf128,
    ParallelHash128Plan,
    ParallelHash128LeafJob,
    ParallelHash128LeafResult,
    ParallelHash128LeafWorkspace,
    32
);
worker!(
    run256,
    run256_with,
    batch256,
    leaf256,
    ParallelHash256Plan,
    ParallelHash256LeafJob,
    ParallelHash256LeafResult,
    ParallelHash256LeafWorkspace,
    64
);

#[cfg(test)]
mod tests;
