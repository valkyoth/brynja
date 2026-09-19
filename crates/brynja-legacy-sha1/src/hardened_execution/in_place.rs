//! Scoped legacy SHA-1 using an existing hardened execution authority.
//!
//! Active storage is borrowed in place. Scope exit clears the owned regions
//! even after a forgotten handle; recoverable unwind also quarantines the
//! executor. CPU scratch uses the existing per-compression cleanup boundary.
//! This does not promise complete register/spill/compiler-copy erasure. Abort
//! cannot run destructors. SHA-1 remains collision-broken, not authentication.
//!
//! ```
//! use brynja_legacy_sha1::hardened_execution::{Executor, in_place::Sha1Workspace};
//! let executor = Executor::portable();
//! let mut workspace = Sha1Workspace::new(&executor);
//! let mut bytes = [0; 20];
//! let output = workspace.with(|mut state| {
//!     state.update(b"abc")?;
//!     state.finalize_secret(&mut bytes)
//! })??;
//! drop(output);
//! assert_eq!(bytes, [0; 20]);
//! # Ok::<(), brynja_legacy_sha1::hardened_execution::Error>(())
//! ```

use super::{Error, Executor, begin_output, empty, engine};
use crate::{BitString, PublicDeclassification, Sha1Error, owner::Sha1Owner};
use brynja_core::OwnedSecretRegion;

struct Storage<'authority> {
    owner: Sha1Owner,
    executor: &'authority Executor,
    active: bool,
}
impl Storage<'_> {
    fn clear(&mut self) {
        self.owner.wipe();
        self.active = false;
    }
    fn operate<R>(
        &mut self,
        action: impl FnOnce(&mut Sha1Owner, &Executor) -> Result<R, Error>,
    ) -> Result<R, Error> {
        if !self.active {
            return Err(Sha1Error::StateConsumed.into());
        }
        self.active = false;
        let mut guard = Operation {
            state: self,
            completed: false,
            quarantine: true,
        };
        guard.state.executor.ready()?;
        let result = action(&mut guard.state.owner, guard.state.executor);
        if result.is_ok() {
            guard.state.active = true;
            guard.completed = true;
        } else if matches!(result, Err(Error::Hash(Sha1Error::MessageTooLong))) {
            // A caller's length rejection terminates this computation, not
            // the otherwise healthy shared execution authority.
            guard.quarantine = false;
        }
        result
    }
}
struct Operation<'scope, 'authority> {
    state: &'scope mut Storage<'authority>,
    completed: bool,
    quarantine: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.state.clear();
            if self.quarantine {
                self.state.executor.quarantine();
            }
        }
    }
}
struct Scope<'scope, 'authority> {
    state: &'scope mut Storage<'authority>,
    completed: bool,
}
impl Drop for Scope<'_, '_> {
    fn drop(&mut self) {
        self.state.clear();
        if !self.completed {
            self.state.executor.quarantine();
        }
    }
}

/// Caller-owned storage borrowing one hardened executor; no route substitution.
/// Construction accepts no secret input and does not perform CPU detection.
/// ```compile_fail
/// use brynja_legacy_sha1::hardened_execution::{Executor, in_place::Sha1Workspace};
/// let executor = Executor::portable();
/// let mut workspace = Sha1Workspace::new(&executor);
/// let escaped = workspace.with(|state| state);
/// ```
/// ```compile_fail
/// use brynja_legacy_sha1::hardened_execution::{Executor, in_place::Sha1Workspace};
/// let workspace = { let executor = Executor::portable(); Sha1Workspace::new(&executor) };
/// drop(workspace);
/// ```
/// ```compile_fail
/// use brynja_legacy_sha1::hardened_execution::{Executor, in_place::Sha1Workspace};
/// let executor = Executor::portable();
/// let mut workspace = Sha1Workspace::new(&executor);
/// workspace.with(|_state| workspace.with(|_overlap| ()));
/// ```
pub struct Sha1Workspace<'authority> {
    state: Storage<'authority>,
}
impl<'authority> Sha1Workspace<'authority> {
    /// Allocates no heap storage. Authority is checked at each scope and operation.
    pub const fn new(executor: &'authority Executor) -> Self {
        Self {
            state: Storage {
                owner: Sha1Owner::new(),
                executor,
                active: false,
            },
        }
    }
    /// Runs a computation in final storage. The outer result is admission;
    /// the inner result/value belongs to the callback. Failed admission never
    /// calls the callback and cannot clear buffers captured only by that callback.
    /// Secret destination clearing starts when finalization receives the buffer.
    /// Neither reuse nor a new workspace can undo executor quarantine.
    pub fn with<R>(
        &mut self,
        action: impl for<'scope> FnOnce(Sha1<'scope, 'authority>) -> R,
    ) -> Result<R, Error> {
        self.state.clear();
        // Public IV written directly; no populated owner is constructed or moved.
        self.state.owner.chaining_state.copy_from_slice(&[
            0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32,
            0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0,
        ]);
        self.state.active = true;
        let mut scope = Scope {
            state: &mut self.state,
            completed: false,
        };
        scope.state.operate(|_, _| Ok(()))?;
        let result = action(Sha1 {
            state: &mut *scope.state,
        });
        scope.completed = true;
        Ok(result)
    }
}

/// Exclusive non-Send/non-Sync handle. No clone, snapshot or length query.
/// Updates fail terminally and clear storage; finalization consumes the handle.
#[must_use = "finalize or cancel the scoped state"]
pub struct Sha1<'scope, 'authority> {
    state: &'scope mut Storage<'authority>,
}
impl Sha1<'_, '_> {
    /// Absorbs bytes without moving active storage. Backend failure never falls back.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.state
            .operate(|owner, executor| engine::update(owner, input, executor))
    }
    /// Consumes the handle and clears its owned state without producing output.
    pub fn cancel(self) {}
    /// Consumes the state; public output remains unchanged on error.
    pub fn finalize_public(
        self,
        destination: &mut [u8],
        authority: PublicDeclassification,
    ) -> Result<(), Error> {
        self.finalize_bits_public(empty()?, destination, authority)
    }
    /// Consumes canonical MSB-first final bits with explicit declassification.
    pub fn finalize_bits_public(
        self,
        tail: BitString<'_>,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        if destination.len() != crate::DIGEST_BYTES {
            return Err(Sha1Error::OutputLength.into());
        }
        self.state
            .operate(|owner, executor| engine::finish(owner, tail, executor))?;
        destination.copy_from_slice(&self.state.owner.output_staging);
        Ok(())
    }
    /// Typed secret output; errors and recoverable unwind clear the destination.
    pub fn finalize_secret(self, destination: &mut [u8]) -> Result<OwnedSecretRegion<'_>, Error> {
        // Begin initialization before any fallible finalization operation.
        let mut output = begin_output(destination)?;
        let tail = empty()?;
        self.state
            .operate(|owner, executor| engine::finish(owner, tail, executor))?;
        output
            .write(&self.state.owner.output_staging)
            .map_err(|_| Sha1Error::SecretMemory)?;
        output.finish().map_err(|_| Sha1Error::SecretMemory.into())
    }
    /// Consumes canonical final bits into separately borrowed secret output.
    pub fn finalize_bits_secret<'out>(
        self,
        tail: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<OwnedSecretRegion<'out>, Error> {
        let mut output = begin_output(destination)?;
        self.state
            .operate(|owner, executor| engine::finish(owner, tail, executor))?;
        output
            .write(&self.state.owner.output_staging)
            .map_err(|_| Sha1Error::SecretMemory)?;
        output.finish().map_err(|_| Sha1Error::SecretMemory.into())
    }
}
impl Drop for Sha1<'_, '_> {
    fn drop(&mut self) {
        self.state.clear();
    }
}

#[cfg(test)]
mod tests;
