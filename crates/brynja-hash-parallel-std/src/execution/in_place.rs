//! Bounded threads using scoped root/leaf storage and explicit existing routes.
//!
//! Authorities are constructed on their executing thread before secret input.
//! Only completed plan-bound output borrows cross back from workers. No secret
//! sponge owner or CPU session is transferred. This is owned-memory lifecycle
//! support, not a register/spill, abort or platform-storage erasure guarantee.

use super::{
    Config, Error, Identity, Report, Request, Scratch, is_xof, live, selection::Selection,
};
use crate::{CancellationToken, scoped_worker::Slots};
use brynja_core::clear_owned_region;
use brynja_hash_parallel::{
    self as hash, ParallelHashSecretOutput, execution::Mode, hardened_in_place as portable,
};
use hash::execution::in_place as accelerated;

mod worker;

/// Bounded single-operation executor with scoped cryptographic storage.
/// Root and leaf preferences are independent. Prefer permits portable work only
/// on initial platform absence; supplied authority errors never authorize fallback.
pub struct Executor {
    inner: super::Executor,
}
impl Executor {
    /// Checks the existing worker/leaf limits without starting threads.
    pub fn new(config: Config) -> Result<Self, Error> {
        Ok(Self {
            inner: super::Executor::new(config)?,
        })
    }
    /// Transactional public bytes; clears the complete staging slice on every exit.
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
    /// Canonical public output bits. Scratch must cover the entire destination;
    /// even early failures preserve output and clear scratch. Declassification is
    /// explicit in choosing this public-output API, as with the existing executor.
    pub fn hash_public_bits(
        &self,
        request: &Request<'_>,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<Report, Error> {
        let scratch = Scratch(scratch);
        let _gate = self.inner.gate()?;
        let stage = scratch
            .0
            .get_mut(..output.len())
            .ok_or(Error::Crypto(hash::execution::Error::OutputLength))?;
        let (secret, report) = self.compute_secret(request, stage, valid, cancellation)?;
        brynja_core::copy_secret_region(output, secret.expose())
            .map_err(|_| Error::Crypto(hash::execution::Error::State))?;
        Ok(report)
    }
    /// Typed secret bytes. Every failure clears the complete supplied destination.
    pub fn hash_secret<'out>(
        &self,
        request: &Request<'_>,
        output: &'out mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
        let valid = if output.is_empty() { 0 } else { 8 };
        self.hash_secret_bits(request, output, valid, cancellation)
    }
    /// Canonical secret bits. Completed output borrows the caller's destination,
    /// never the local root/worker workspaces. Caller input is not erased.
    pub fn hash_secret_bits<'out>(
        &self,
        request: &Request<'_>,
        output: &'out mut [u8],
        valid: u8,
        cancellation: &CancellationToken,
    ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
        let _ = clear_owned_region(output);
        let _gate = self.inner.gate()?;
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
    Error::Crypto(error.into())
}

macro_rules! root {
    ($run:ident, $plan:ident, $workspace:ident, $workers:ident) => {
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
                if plan.leaf_count() > self.inner.config.max_leaves {
                    return Err(Error::Crypto(hash::execution::Error::WorkLimit));
                }
                let leaves = usize::try_from(plan.leaf_count()).map_err(|_| Error::Limits)?;
                let owner = Selection::new(self.inner.config.root)?;
                macro_rules! collect {
                    ($storage:expr, $report:expr) => {{
                        let mut workspace = $storage;
                        let root_report = $report(&workspace);
                        workspace
                            .with_bits(&plan, request.customization, |mut root| {
                                let count = worker::$workers(
                                    &plan,
                                    &self.inner.config,
                                    cancellation,
                                    |leaf| root.merge(leaf),
                                )?;
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
                                        root: root_report,
                                        leaves: plan.leaf_count(),
                                        accelerated_leaves: count,
                                        thread_width: self.inner.config.workers.min(leaves),
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
                    Mode::Require(None) => Err(Error::Unavailable),
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
