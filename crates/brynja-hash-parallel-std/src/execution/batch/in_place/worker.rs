use super::super::selection::Selection;
use super::{Error, Executor, crypto, hash, live};
use crate::{
    CancellationToken,
    scoped_worker::{Spawner, System},
};
use brynja_core::clear_owned_region;
use hash::execution::in_place::batch as leaf;
use std::thread;

// Allocated empty and never resized while populated. Workers borrow disjoint
// slots. The independent parent guard survives forgotten completed-result loans.
struct GroupSlots(Vec<[[u8; 64]; leaf::CAPACITY]>);
impl GroupSlots {
    fn new(length: usize) -> Result<Self, Error> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(length)
            .map_err(|_| crate::execution::Error::Resource)?;
        slots.resize(length, [[0; 64]; leaf::CAPACITY]);
        Ok(Self(slots))
    }
    #[inline(never)]
    fn clear(&mut self) {
        for slot in &mut self.0 {
            let _ = clear_owned_region(slot.as_flattened_mut());
        }
    }
}
impl Drop for GroupSlots {
    fn drop(&mut self) {
        self.clear();
        #[cfg(test)]
        tests::observe_drop(self);
    }
}
#[derive(Default, Debug, Eq, PartialEq)]
pub(super) struct Work {
    pub(super) groups: u128,
    pub(super) accelerated: u128,
    pub(super) vector_calls: u64,
    pub(super) vector_permutations: u64,
    pub(super) scalar_permutations: u64,
}
impl Work {
    fn add(&mut self, report: leaf::KernelReport) -> Result<(), Error> {
        self.merge(Self {
            groups: 1,
            accelerated: u128::from(report.accelerated_slots.count_ones()),
            vector_calls: report.vector_calls,
            vector_permutations: report.vector_permutations,
            scalar_permutations: report.scalar_permutations,
        })
    }
    fn merge(&mut self, other: Self) -> Result<(), Error> {
        let merged = Self {
            groups: self.groups.checked_add(other.groups).ok_or(Error::Limits)?,
            accelerated: self
                .accelerated
                .checked_add(other.accelerated)
                .ok_or(Error::Limits)?,
            vector_calls: self
                .vector_calls
                .checked_add(other.vector_calls)
                .ok_or(Error::Limits)?,
            vector_permutations: self
                .vector_permutations
                .checked_add(other.vector_permutations)
                .ok_or(Error::Limits)?,
            scalar_permutations: self
                .scalar_permutations
                .checked_add(other.scalar_permutations)
                .ok_or(Error::Limits)?,
        };
        *self = merged;
        Ok(())
    }
}
macro_rules! worker {
    ($run:ident,$using:ident,$wave:ident,$plan:ident,$result:ident) => {
        pub(super) fn $run<'plan, 'input>(
            plan: &'plan hash::$plan<'input>,
            executor: &Executor,
            token: &CancellationToken,
            merge: impl for<'out> FnMut(
                leaf::$result<'plan, 'input, 'out>,
            ) -> Result<(), hash::ParallelHashError>,
        ) -> Result<Work, Error> {
            $using(plan, executor, token, merge, &mut System)
        }
        fn $using<'plan, 'input>(
            plan: &'plan hash::$plan<'input>,
            executor: &Executor,
            token: &CancellationToken,
            mut merge: impl for<'out> FnMut(
                leaf::$result<'plan, 'input, 'out>,
            ) -> Result<(), hash::ParallelHashError>,
            spawner: &mut impl Spawner,
        ) -> Result<Work, Error> {
            live(token)?;
            let leaves = usize::try_from(plan.leaf_count()).map_err(|_| Error::Limits)?;
            if plan.leaf_count() > executor.inner.base.config.max_leaves {
                return Err(hash::execution::Error::WorkLimit.into());
            }
            let groups = leaves.div_ceil(leaf::CAPACITY);
            let width = groups.min(executor.inner.base.config.workers);
            let mut storage = GroupSlots::new(width)?;
            let mut first = 0usize;
            let mut work = Work::default();
            while first < groups {
                live(token)?;
                let count = groups.checked_sub(first).ok_or(Error::Limits)?.min(width);
                work.merge($wave(
                    plan,
                    first,
                    storage.0.get_mut(..count).ok_or(Error::Limits)?,
                    executor,
                    token,
                    &mut merge,
                    spawner,
                )?)?;
                first = first.checked_add(count).ok_or(Error::Limits)?;
            }
            live(token)?;
            Ok(work)
        }
        fn $wave<'plan, 'input>(
            plan: &'plan hash::$plan<'input>,
            first: usize,
            slots: &mut [[[u8; 64]; leaf::CAPACITY]],
            executor: &Executor,
            token: &CancellationToken,
            merge: &mut impl for<'out> FnMut(
                leaf::$result<'plan, 'input, 'out>,
            ) -> Result<(), hash::ParallelHashError>,
            spawner: &mut impl Spawner,
        ) -> Result<Work, Error> {
            thread::scope(|scope| {
                let mut work = Work::default();
                let mut handles = Vec::new();
                handles
                    .try_reserve_exact(slots.len())
                    .map_err(|_| crate::execution::Error::Resource)?;
                let mut failure = None;
                for (offset, storage) in slots.iter_mut().enumerate() {
                    let prepared = (|| {
                        live(token)?;
                        let start = first
                            .checked_add(offset)
                            .and_then(|n| n.checked_mul(leaf::CAPACITY))
                            .ok_or(Error::Limits)?;
                        let count = plan
                            .leaf_count()
                            .checked_sub(start as u128)
                            .ok_or(Error::Limits)?
                            .min(leaf::CAPACITY as u128);
                        plan.batch(
                            start as u128,
                            usize::try_from(count).map_err(|_| Error::Limits)?,
                        )
                        .map_err(Error::from)
                    })();
                    let job = match prepared {
                        Ok(job) => job,
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    };
                    match spawner.spawn(scope, move || {
                        live(token)?;
                        let owner = Selection::new(executor.inner.base.config.leaves)?;
                        let engine = owner.executor(executor.inner.minimum)?;
                        let mut workspace = leaf::Workspace::new();
                        let mut cancel = || token.is_cancelled();
                        let result = job.execute_into(
                            &engine,
                            &mut workspace,
                            storage,
                            &mut leaf::Control::new(executor.inner.budget, &mut cancel),
                        )?;
                        live(token)?;
                        Ok::<_, Error>(result)
                    }) {
                        Ok(handle) => handles.push(handle),
                        Err(_) => {
                            failure = Some(crate::execution::Error::Resource.into());
                            break;
                        }
                    }
                }
                // Drain every started handle, including after the first failure.
                // Submission order, not completion order, controls root absorption.
                for handle in handles {
                    match handle.join() {
                        Err(_) => {
                            failure.get_or_insert(crate::execution::Error::WorkerPanicked.into());
                        }
                        Ok(Err(error)) => {
                            failure.get_or_insert(error);
                        }
                        Ok(Ok(leaves)) => {
                            if failure.is_none() {
                                let merged = (|| {
                                    live(token)?;
                                    work.add(leaves.report())?;
                                    merge(leaves).map_err(crypto)
                                })();
                                if let Err(error) = merged {
                                    failure = Some(error);
                                }
                            }
                        }
                    }
                }
                failure.map_or(Ok(work), Err)
            })
        }
    };
}
worker!(run128, run128_with, wave128, ParallelHash128Plan, Leaves128);
worker!(run256, run256_with, wave256, ParallelHash256Plan, Leaves256);
#[cfg(test)]
mod tests;
