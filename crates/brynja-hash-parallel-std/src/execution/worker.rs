use super::{Config, Error, Preference, live, selection::Selection};
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

struct Storage(Vec<[u8; 64]>);
impl Storage {
    #[inline(never)]
    fn clear(&mut self) {
        for value in &mut self.0 {
            let _ = clear_owned_region(value);
        }
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(super) fn run<'plan, 'input>(
    plan: &'plan Plan<'input>,
    root: &mut Collector<'plan, 'input, '_>,
    config: &Config,
    cancellation: &CancellationToken,
) -> Result<(), Error> {
    run_with(plan, root, config, cancellation, &mut SystemSpawner)
}

fn run_with<'plan, 'input>(
    plan: &'plan Plan<'input>,
    root: &mut Collector<'plan, 'input, '_>,
    config: &Config,
    cancellation: &CancellationToken,
    spawner: &mut impl Spawner,
) -> Result<(), Error> {
    let mut operation = Operation {
        root,
        complete: false,
    };
    live(cancellation)?;
    let leaves = usize::try_from(plan.leaf_count()).map_err(|_| Error::Limits)?;
    let width = leaves.min(config.workers);
    let mut storage = Storage(Vec::new());
    storage
        .0
        .try_reserve_exact(width)
        .map_err(|_| Error::Resource)?;
    storage.0.resize(width, [0; 64]);
    let mut base = 0_usize;
    while base < leaves {
        live(cancellation)?;
        let count = leaves.checked_sub(base).ok_or(Error::Limits)?.min(width);
        let batch = storage.0.get_mut(..count).ok_or(Error::Limits)?;
        batch_run(
            plan,
            operation.root,
            base,
            batch,
            config.leaves,
            cancellation,
            spawner,
        )?;
        base = base.checked_add(count).ok_or(Error::Limits)?;
    }
    operation.complete = true;
    Ok(())
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

fn batch_run<'plan, 'input>(
    plan: &'plan Plan<'input>,
    root: &mut Collector<'plan, 'input, '_>,
    base: usize,
    batch: &mut [[u8; 64]],
    preference: Preference,
    cancellation: &CancellationToken,
    spawner: &mut impl Spawner,
) -> Result<(), Error> {
    thread::scope(|scope| {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(batch.len())
            .map_err(|_| Error::Resource)?;
        let mut failure = None;
        for (offset, storage) in batch.iter_mut().enumerate() {
            let prepared = (move || {
                let storage = storage;
                live(cancellation)?;
                let index = base.checked_add(offset).ok_or(Error::Limits)?;
                let index = u128::try_from(index).map_err(|_| Error::Limits)?;
                let job = plan.job(index)?;
                let output = storage
                    .get_mut(..plan.identity().leaf_bytes())
                    .ok_or(Error::Limits)?;
                Ok((job, output))
            })();
            let (job, output) = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            };
            // No session, raw authority or sponge state crosses this boundary.
            match spawner.spawn(scope, move || {
                live(cancellation)?;
                let owner = Selection::new(preference)?;
                let result = job.execute(owner.mode()?, output)?;
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
        // Join every started worker even on error; joining in submission order
        // permits out-of-order completion without out-of-order root absorption.
        for handle in handles {
            match handle.join() {
                Err(_) => {
                    failure.get_or_insert(Error::WorkerPanicked);
                }
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Ok(Ok(leaf)) => {
                    if failure.is_none() {
                        if let Err(error) = live(cancellation) {
                            failure = Some(error);
                        } else if let Err(error) = root.merge(&leaf) {
                            failure = Some(Error::Crypto(error));
                        }
                    }
                }
            }
        }
        failure.map_or(Ok(()), Err)
    })
}

#[cfg(test)]
mod tests;
