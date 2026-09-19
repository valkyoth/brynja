//! Bounded multibuffer workers with scoped collector storage.
//!
//! Every worker constructs its own authority and empty clearing workspace.
//! Only completed exact-plan CV loans return to the coordinator; authorities and
//! unfinished sponge owners never cross threads. Parent guards clear output slots
//! even on forgotten results or recoverable unwind. This does not promise erasure
//! of registers, spills, compiler copies, caller input or storage after abort.
//!
//! ```
//! use brynja_hash_parallel::{Fips202BitString,execution::Identity};
//! use brynja_hash_parallel_std::{CancellationToken,execution::batch::in_place::{Config,Error,Executor,Preference,Request}};
//! # fn main()->Result<(),Error> {
//! let executor=Executor::new(Config{workers:2,max_leaves:32,root:Preference::Portable,
//!     leaves:Preference::Portable,minimum_permutations:1,max_group_permutations:64})?;
//! let request=Request{identity:Identity::ParallelHash128,
//!     input:Fips202BitString::new(b"message",8).map_err(|_|Error::Limits)?,block_size:1,
//!     customization:Fips202BitString::new(&[],0).map_err(|_|Error::Limits)?};
//! let mut output=[0;32];
//! let (secret,report)=executor.hash_secret(&request,&mut output,&CancellationToken::new())?;
//! assert_eq!(report.execution.leaves,7);assert_eq!(report.groups,2);
//! drop(secret);assert_eq!(output,[0;32]);
//! # Ok(()) }
//! ```

pub use super::{Config, Error, Preference, Report, Request};
use super::{Scratch, is_xof, live};
use crate::{
    CancellationToken,
    execution::{Identity, selection::Selection},
};
use brynja_core::clear_owned_region;
use brynja_hash_parallel::{self as hash, ParallelHashSecretOutput, hardened_in_place as portable};
use hash::execution::Mode;
use hash::execution::in_place as accelerated;
mod worker;

/// A nonblocking single-operation gate with independently chosen root and SIMD
/// leaf routes. Thread count is independent of SIMD width. Require rejects an
/// ineligible final group; Prefer permits scalar tails, never backend-error fallback.
pub struct Executor {
    inner: super::Executor,
}
impl Executor {
    /// Checks worker, leaf and crossover limits without allocating or probing CPUs.
    pub fn new(config: Config) -> Result<Self, Error> {
        Ok(Self {
            inner: super::Executor::new(config)?,
        })
    }
    /// Transactional byte output; the entire supplied staging slice clears.
    pub fn hash_public(
        &self,
        request: &Request<'_>,
        output: &mut [u8],
        scratch: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<Report, Error> {
        let valid = if output.is_empty() { 0 } else { 8 };
        self.hash_public_bits(request, output, valid, scratch, cancellation)
    }
    /// Canonical public bits. The gate covers all work and final commit. Even
    /// early errors preserve output and clear all scratch; scratch must cover output.
    /// Choosing this public-output method is an explicit declassification decision.
    pub fn hash_public_bits(
        &self,
        request: &Request<'_>,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<Report, Error> {
        let scratch = Scratch(scratch);
        let _gate = self.inner.base.gate()?;
        let stage = scratch
            .0
            .get_mut(..output.len())
            .ok_or(hash::execution::Error::OutputLength)?;
        let (secret, report) = self.compute_secret(request, stage, valid, cancellation)?;
        brynja_core::copy_secret_region(output, secret.expose())
            .map_err(|_| hash::execution::Error::State)?;
        Ok(report)
    }
    /// Secret byte output; errors clear the entire supplied destination.
    pub fn hash_secret<'out>(
        &self,
        request: &Request<'_>,
        output: &'out mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
        let valid = if output.is_empty() { 0 } else { 8 };
        self.hash_secret_bits(request, output, valid, cancellation)
    }
    /// Canonical secret bits. Completed output retains only its caller destination
    /// borrow, not a root workspace, worker slot or authority lease.
    pub fn hash_secret_bits<'out>(
        &self,
        request: &Request<'_>,
        output: &'out mut [u8],
        valid: u8,
        cancellation: &CancellationToken,
    ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
        let _ = clear_owned_region(output);
        let _gate = self.inner.base.gate()?;
        self.compute_secret(request, output, valid, cancellation)
    }
    fn compute_secret<'out>(
        &self,
        request: &Request<'_>,
        output: &'out mut [u8],
        valid: u8,
        cancellation: &CancellationToken,
    ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
        live(cancellation)?;
        match request.identity {
            Identity::ParallelHash128 | Identity::ParallelHashXof128 => {
                self.secret128(request, output, valid, cancellation)
            }
            Identity::ParallelHash256 | Identity::ParallelHashXof256 => {
                self.secret256(request, output, valid, cancellation)
            }
        }
    }
}
fn crypto(error: hash::ParallelHashError) -> Error {
    hash::execution::Error::from(error).into()
}

macro_rules! root {
    ($run:ident,$plan:ident,$workspace:ident,$workers:ident) => {
        impl Executor {
            fn $run<'out>(
                &self,
                request: &Request<'_>,
                output: &'out mut [u8],
                valid: u8,
                cancellation: &CancellationToken,
            ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
                let plan =
                    hash::$plan::new_bits(request.input, request.block_size).map_err(crypto)?;
                if plan.leaf_count() > self.inner.base.config.max_leaves {
                    return Err(hash::execution::Error::WorkLimit.into());
                }
                let owner = Selection::new(self.inner.base.config.root)?;
                macro_rules! collect {
                    ($storage:expr,$route:expr) => {{
                        let mut workspace = $storage;
                        let route = $route(&workspace);
                        workspace
                            .with_bits(&plan, request.customization, |mut root| {
                                let work = worker::$workers(&plan, self, cancellation, |leaves| {
                                    root.merge_batch(leaves)
                                })?;
                                live(cancellation)?;
                                let secret = if is_xof(request.identity) {
                                    root.finalize_xof()
                                        .map_err(crypto)?
                                        .squeeze_final_bits_secret(output, valid)
                                        .map_err(crypto)?
                                } else {
                                    root.finalize_secret_bits(output, valid).map_err(crypto)?
                                };
                                Ok((
                                    secret,
                                    Report {
                                        execution: crate::execution::Report {
                                            root: route,
                                            leaves: plan.leaf_count(),
                                            accelerated_leaves: work.accelerated,
                                            thread_width: self.inner.base.config.workers.min(
                                                usize::try_from(work.groups)
                                                    .map_err(|_| Error::Limits)?,
                                            ),
                                        },
                                        groups: work.groups,
                                        vector_calls: work.vector_calls,
                                        vector_permutations: work.vector_permutations,
                                        scalar_permutations: work.scalar_permutations,
                                    },
                                ))
                            })
                            .map_err(crypto)?
                    }};
                }
                match owner.mode()? {
                    Mode::Portable | Mode::Prefer(None) => {
                        collect!(portable::$workspace::new(), |_: &portable::$workspace| None)
                    }
                    Mode::Require(None) => Err(crate::execution::Error::Unavailable.into()),
                    Mode::Require(Some(session)) | Mode::Prefer(Some(session)) => collect!(
                        accelerated::$workspace::new(session).map_err(crypto)?,
                        |w: &accelerated::$workspace<'_>| Some(w.report())
                    ),
                }
            }
        }
    };
}
root!(
    secret128,
    ParallelHash128Plan,
    ParallelHash128CollectorWorkspace,
    run128
);
root!(
    secret256,
    ParallelHash256Plan,
    ParallelHash256CollectorWorkspace,
    run256
);

#[cfg(test)]
mod tests;
