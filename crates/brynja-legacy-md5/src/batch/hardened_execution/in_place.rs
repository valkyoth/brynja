//! Scoped secret-bearing batches in caller-owned storage. MD5 is collision-broken.
//!
//! The eight lane owners remain borrowed throughout processing. A separate scope
//! guard clears all lanes even if the handle is forgotten. SIMD selection, work
//! accounting and request-versus-backend failure handling are those of the existing
//! hardened executor. This does not guarantee erasure of compiler copies, spills,
//! registers, caller inputs or platform storage. Abort cannot run destructors.
//! Batch shape, lengths and route/work reports remain public metadata.
//!
//! ```
//! use brynja_legacy_md5::{BitString, Md5BatchControl};
//! use brynja_legacy_md5::hardened_execution::{Executor, in_place::Workspace};
//! let executor = Executor::portable();
//! let mut workspace = Workspace::new(&executor);
//! let inputs = [Some(BitString::new(b"abc", 8).map_err(|_| "invalid bits")?); 8];
//! let mut destination = [[0; 16]; 8];
//! let (secret, report) = workspace.with(|batch| {
//!     batch.digest_secret(&inputs, &mut destination, &mut Md5BatchControl::new(8))
//! })??;
//! assert_eq!(report.work.active_lanes, 8);
//! drop(secret);
//! assert_eq!(destination, [[0; 16]; 8]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use super::{Error, Executor, Md5BatchControl, Md5BatchError, Report};
use crate::{BitString, PublicDeclassification};
use brynja_core::{OwnedSecretRegion, SecretRegionInitialization};

#[inline(never)]
fn clear(batch: &mut super::Batch<'_>) {
    for lane in &mut batch.owner.lanes {
        lane.wipe();
    }
}

struct Scope<'scope, 'authority> {
    batch: &'scope mut super::Batch<'authority>,
    complete: bool,
}
impl Drop for Scope<'_, '_> {
    fn drop(&mut self) {
        clear(self.batch);
        if !self.complete {
            self.batch.executor.quarantine();
        }
    }
}

/// Reusable, allocation-free, thread-bound storage borrowing a hardened executor.
/// No populated owner is returned by value. A scope clears active and inactive
/// lanes before returning, including when its handle is forgotten.
/// ```compile_fail
/// use brynja_legacy_md5::hardened_execution::{Executor, in_place::Workspace};
/// let executor = Executor::portable();
/// let mut workspace = Workspace::new(&executor);
/// let escaped = workspace.with(|batch| batch);
/// ```
/// ```compile_fail
/// use brynja_legacy_md5::hardened_execution::{Executor, in_place::Workspace};
/// let executor = Executor::portable();
/// let mut workspace = Workspace::new(&executor);
/// workspace.with(|_batch| workspace.with(|_other| ()));
/// ```
pub struct Workspace<'authority> {
    batch: super::Batch<'authority>,
}
impl<'authority> Workspace<'authority> {
    /// Constructs empty storage, before any secret is supplied.
    #[must_use]
    pub fn new(executor: &'authority Executor) -> Self {
        Self {
            batch: executor.batch(),
        }
    }
    /// Restores public IVs into cleared lanes and lends one consuming batch.
    ///
    /// Admission failure does not invoke the callback and cannot clear buffers
    /// captured only by it. Once a digest method receives a secret destination,
    /// that method clears it on error/unwind. Ordinary request rejection preserves
    /// executor reuse; backend failure or callback unwind quarantines it. Under
    /// `panic = "abort"`, neither cleanup nor quarantine destructors execute.
    pub fn with<R>(
        &mut self,
        operation: impl for<'scope> FnOnce(Batch<'scope, 'authority>) -> R,
    ) -> Result<R, Error> {
        clear(&mut self.batch);
        for lane in &mut self.batch.owner.lanes {
            // Public IV only; never replace a populated owner by value.
            lane.chaining_state.copy_from_slice(&[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10,
            ]);
        }
        let mut scope = Scope {
            batch: &mut self.batch,
            complete: false,
        };
        scope.batch.executor.ready()?;
        let result = operation(Batch {
            batch: &mut *scope.batch,
        });
        scope.complete = true;
        Ok(result)
    }
}

/// Exclusive borrowed batch with consuming output and cancellation operations.
/// The handle cannot escape its callback, be cloned, or cross threads. A secret
/// output owner borrowing separate caller storage may outlive the callback.
/// ```compile_fail
/// use brynja_legacy_md5::hardened_execution::{Executor, in_place::Workspace};
/// let executor = Executor::portable();
/// let mut workspace = Workspace::new(&executor);
/// workspace.with(|batch| { batch.cancel(); batch.cancel(); });
/// ```
#[must_use = "digest or cancel the scoped batch"]
pub struct Batch<'scope, 'authority> {
    batch: &'scope mut super::Batch<'authority>,
}
impl Batch<'_, '_> {
    /// Explicitly releases all results after complete success. Errors and unwind
    /// leave the public destination unchanged; inactive slots become zero on success.
    pub fn digest_public(
        self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
        _authority: PublicDeclassification,
    ) -> Result<Report, Error> {
        let report = self.batch.run(inputs, control)?;
        self.batch.owner.commit_public(output);
        Ok(report)
    }
    /// Produces a non-cloneable secret owner covering every destination slot.
    /// Errors and recoverable unwind clear the whole destination, including slots
    /// not yet written. Inputs remain caller-owned and are never cleared here.
    pub fn digest_secret<'out>(
        self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &'out mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
    ) -> Result<(OwnedSecretRegion<'out>, Report), Error> {
        let mut initialization = SecretRegionInitialization::begin(output.as_flattened_mut())
            .map_err(|_| Md5BatchError::SecretMemory)?;
        let report = self.batch.run(inputs, control)?;
        for lane in &self.batch.owner.lanes {
            initialization
                .write(&lane.output_staging)
                .map_err(|_| Md5BatchError::SecretMemory)?;
        }
        let output = initialization
            .finish()
            .map_err(|_| Md5BatchError::SecretMemory)?;
        Ok((output, report))
    }
    /// Clears all lanes without digest output or executor revocation.
    pub fn cancel(self) {}
}
impl Drop for Batch<'_, '_> {
    fn drop(&mut self) {
        clear(self.batch);
    }
}

#[cfg(test)]
mod tests;
