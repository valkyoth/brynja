use super::{Error, Executor, leaf, live, selection::Selection};
use crate::CancellationToken;
use brynja_core::clear_owned_region;
use brynja_hash_parallel::execution::{Collector, Plan};
use std::{io, thread};

trait Spawner {
    fn spawn<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope;
}
struct SystemSpawner;
impl Spawner for SystemSpawner {
    fn spawn<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        thread::Builder::new().spawn_scoped(scope, work)
    }
}
struct Storage(Vec<[[u8; 64]; leaf::CAPACITY]>);
impl Storage {
    #[inline(never)]
    fn clear(&mut self) {
        for slot in &mut self.0 {
            let _ = clear_owned_region(slot.as_flattened_mut());
        }
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        self.clear();
        #[cfg(test)]
        tests::observe_drop(self);
    }
}
#[derive(Default, Debug, Eq, PartialEq)]
pub(super) struct Work {
    pub(super) groups: u128,
    pub(super) vector_calls: u64,
    pub(super) vector_permutations: u64,
    pub(super) scalar_permutations: u64,
}
impl Work {
    fn add(&mut self, report: leaf::KernelReport) -> Result<(), Error> {
        self.merge(Self {
            groups: 1,
            vector_calls: report.vector_calls,
            vector_permutations: report.vector_permutations,
            scalar_permutations: report.scalar_permutations,
        })
    }
    fn merge(&mut self, other: Self) -> Result<(), Error> {
        let merged = Self {
            groups: self.groups.checked_add(other.groups).ok_or(Error::Limits)?,
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
struct Operation<'state, 'plan, 'input, 'authority> {
    root: &'state mut Collector<'plan, 'input, 'authority>,
    complete: bool,
}
impl Drop for Operation<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.root.cancel();
        }
    }
}
pub(super) fn run<'plan, 'input>(
    plan: &'plan Plan<'input>,
    root: &mut Collector<'plan, 'input, '_>,
    executor: &Executor,
    token: &CancellationToken,
) -> Result<Work, Error> {
    run_with(plan, root, executor, token, &mut SystemSpawner)
}
fn run_with<'plan, 'input>(
    plan: &'plan Plan<'input>,
    root: &mut Collector<'plan, 'input, '_>,
    executor: &Executor,
    token: &CancellationToken,
    spawner: &mut impl Spawner,
) -> Result<Work, Error> {
    let mut operation = Operation {
        root,
        complete: false,
    };
    live(token)?;
    let leaves = usize::try_from(plan.leaf_count()).map_err(|_| Error::Limits)?;
    let groups = leaves.div_ceil(leaf::CAPACITY);
    let width = groups.min(executor.base.config.workers);
    let mut storage = Storage(Vec::new());
    storage
        .0
        .try_reserve_exact(width)
        .map_err(|_| super::super::Error::Resource)?;
    storage.0.resize(width, [[0; 64]; leaf::CAPACITY]);
    let mut first = 0_usize;
    let mut work = Work::default();
    while first < groups {
        live(token)?;
        let count = groups.checked_sub(first).ok_or(Error::Limits)?.min(width);
        work.merge(wave(
            plan,
            operation.root,
            first,
            storage.0.get_mut(..count).ok_or(Error::Limits)?,
            executor,
            token,
            spawner,
        )?)?;
        first = first.checked_add(count).ok_or(Error::Limits)?;
    }
    operation.complete = true;
    Ok(work)
}
fn wave<'plan, 'input>(
    plan: &'plan Plan<'input>,
    root: &mut Collector<'plan, 'input, '_>,
    first: usize,
    slots: &mut [[[u8; 64]; leaf::CAPACITY]],
    executor: &Executor,
    token: &CancellationToken,
    spawner: &mut impl Spawner,
) -> Result<Work, Error> {
    thread::scope(|scope| {
        let mut work = Work::default();
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(slots.len())
            .map_err(|_| super::super::Error::Resource)?;
        let mut failure = None;
        for (offset, storage) in slots.iter_mut().enumerate() {
            let prepare = (|| {
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
            let job = match prepare {
                Ok(job) => job,
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            };
            // This closure captures input/plan loans and a bounded empty output
            // slot, never a CPU authority or unfinished secret state.
            match spawner.spawn(scope, move || {
                live(token)?;
                let owner = Selection::new(executor.base.config.leaves)?;
                let engine = owner.executor(executor.minimum)?;
                let mut workspace = leaf::Workspace::new();
                let mut cancel = || token.is_cancelled();
                let mut control = leaf::Control::new(executor.budget, &mut cancel);
                let result = job
                    .execute(&engine, &mut workspace, &mut control)?
                    .transfer(storage)?;
                live(token)?;
                Ok::<_, Error>(result)
            }) {
                Ok(handle) => handles.push(handle),
                Err(_) => {
                    failure = Some(super::super::Error::Resource.into());
                    break;
                }
            }
        }
        // Always join all started workers. Out-of-order completion never changes
        // absorption order, and a failure drops every remaining clearing token.
        for handle in handles {
            match handle.join() {
                Err(_) => {
                    failure.get_or_insert(super::super::Error::WorkerPanicked.into());
                }
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Ok(Ok(leaves)) => {
                    if failure.is_none() {
                        let merge = (|| {
                            live(token)?;
                            work.add(leaves.report())?;
                            root.merge_transferred(leaves)?;
                            Ok::<_, Error>(())
                        })();
                        if let Err(error) = merge {
                            failure = Some(error);
                        }
                    }
                }
            }
        }
        failure.map_or(Ok(work), Err)
    })
}
#[cfg(test)]
mod tests;
