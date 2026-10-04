//! Private safe-Rust host orchestration component, not a shipping enclave API.
//! The future OS adapter must bind entries to a pinned trusted image, install
//! per-thread residency callbacks and validate page/cleanup observations. This
//! component only joins borrowed workers and checks public generation metadata.
#![forbid(unsafe_code)]

use core::marker::PhantomData;

const MAX_LEAVES: u64 = 65536;
const OPEN: u64 = 1 << 16;
const CLOSED: u64 = 1 << 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Protocol,
    Worker,
    Spawn,
    Quarantined,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ready,
    Close,
    Complete,
    Retire,
    Failed,
}

/// Public dispatch token only. No secret input or CPU authority crosses threads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Work {
    generation: u32,
    lane: u8,
}
impl Work {
    pub fn word(self) -> u64 {
        u64::from(self.generation) * 16 + u64::from(self.lane)
    }
}

/// A single root operation, bounded by the same input contract as the private
/// image. Not Send/Sync: root callback sequencing belongs to its original thread.
pub struct Scheduler {
    leaves: u64,
    completed: u32,
    phase: Phase,
    thread_bound: PhantomData<*mut ()>,
}

impl Scheduler {
    pub fn new(input_bits: u64, block: u64) -> Result<Self, Error> {
        if !(1..=1024).contains(&block) {
            return Err(Error::Bounds);
        }
        let block_bits = block.checked_mul(8).ok_or(Error::Bounds)?;
        let leaves = input_bits.div_ceil(block_bits);
        if leaves > MAX_LEAVES {
            return Err(Error::Bounds);
        }
        Ok(Self {
            leaves,
            completed: 0,
            phase: Phase::Ready,
            thread_bound: PhantomData,
        })
    }

    fn next(&self) -> Result<(u32, u8, u64), Error> {
        let consumed = u64::from(self.completed)
            .checked_mul(4)
            .ok_or(Error::Bounds)?;
        let remaining = self.leaves.checked_sub(consumed).ok_or(Error::Protocol)?;
        let lanes = u8::try_from(remaining.min(4)).map_err(|_| Error::Bounds)?;
        if lanes == 0 {
            return Err(Error::Protocol);
        }
        let generation = self.completed.checked_add(1).ok_or(Error::Bounds)?;
        Ok((generation, lanes, (1_u64 << lanes) - 1))
    }

    /// The closure is an internal transport seam, NOT an application callback.
    /// Scoped workers borrow their transport; a return, error or recoverable
    /// unwind cannot leave a worker holding that borrow. The transport must not
    /// return before its actual native entry returns. No timeout detaches workers.
    pub fn dispatch<F>(&mut self, native: u64, worker: &F) -> Result<(), Error>
    where
        F: Fn(Work) -> Result<(), Error> + Sync,
    {
        self.dispatch_with(native, worker, |_| Ok(()))
    }

    fn dispatch_with<F, S>(&mut self, native: u64, worker: &F, mut before: S) -> Result<(), Error>
    where
        F: Fn(Work) -> Result<(), Error> + Sync,
        S: FnMut(u8) -> Result<(), Error>,
    {
        let previous = self.phase;
        // Failure/unwind is terminal even before the first thread is created.
        self.phase = Phase::Failed;
        if !matches!(previous, Phase::Ready | Phase::Retire) {
            return Err(Error::Quarantined);
        }
        let (generation, lanes, mask) = self.next()?;
        if native != (u64::from(generation) << 32) | (mask << 12) | OPEN {
            return Err(Error::Protocol);
        }
        std::thread::scope(|scope| {
            let mut handles: [Option<std::thread::ScopedJoinHandle<'_, Result<(), Error>>>; 4] =
                core::array::from_fn(|_| None);
            let mut failed = None;
            for lane in 0..lanes {
                // Fault injection and OS spawn errors use the same join path.
                let spawned = before(lane).and_then(|()| {
                    std::thread::Builder::new()
                        .spawn_scoped(scope, move || worker(Work { generation, lane }))
                        .map_err(|_| Error::Spawn)
                });
                match spawned {
                    Ok(handle) => {
                        *handles.get_mut(usize::from(lane)).ok_or(Error::Protocol)? = Some(handle)
                    }
                    Err(error) => {
                        failed = Some(error);
                        break;
                    }
                }
            }
            // Never use `?` while joining: every started worker must be joined,
            // including those after an error or panicking worker in lane order.
            for handle in handles.into_iter().flatten() {
                if !matches!(handle.join(), Ok(Ok(()))) {
                    failed = Some(Error::Worker);
                }
            }
            match failed {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })?;
        self.phase = Phase::Close;
        Ok(())
    }

    /// Host event 3; no extra enclave entry is needed from this callback.
    pub fn closed(&mut self) -> Result<(), Error> {
        let previous = self.phase;
        self.phase = Phase::Failed;
        if previous != Phase::Close {
            return Err(Error::Protocol);
        }
        self.phase = Phase::Complete;
        Ok(())
    }

    /// Event 4: all successful claims, no live workers, reservations or readers.
    /// This metadata check does not substitute for OS residency/cleanup checks.
    pub fn complete(&mut self, native: u64) -> Result<(), Error> {
        let previous = self.phase;
        self.phase = Phase::Failed;
        let (generation, _, mask) = self.next()?;
        let expected = (u64::from(generation) << 32) | (mask << 12) | (mask << 8) | mask | CLOSED;
        if previous != Phase::Complete || native != expected {
            return Err(Error::Protocol);
        }
        self.completed = generation;
        self.phase = Phase::Retire;
        Ok(())
    }

    /// Call only after the synchronous root entry returns. There is no retirement
    /// callback: the trusted native gate permits the next OPEN only after retiring
    /// the preceding generation. Final completion observes its retired word here.
    /// Reject missing or partially completed waves; empty input starts retired.
    pub fn finish(self, native: u64) -> Result<u32, Error> {
        if !matches!(self.phase, Phase::Ready | Phase::Retire)
            || u64::from(self.completed) != self.leaves.div_ceil(4)
            || native != u64::from(self.completed) << 32
        {
            return Err(Error::Protocol);
        }
        Ok(self.completed)
    }
}

#[cfg(test)]
#[path = "parallel_host_scheduler_tests.rs"]
mod tests;
