//! Explicit ordinary, public-data-only independent-message MD5 SIMD.
//!
//! MD5 is collision-broken. These APIs do not authorize authentication, keyed
//! processing or hardened state. SIMD temporaries are not zeroization-qualified.
//! All eight slots retain their order; None is inactive, Some(empty) is active.
//! Full-width contiguous groups share their complete-block prefix. No lane
//! compaction occurs; unequal suffixes and ALL padding execute portably.

use super::{Md5BatchControl, Md5BatchError, Md5BatchReport, owner::BatchOwner, vector};
pub use crate::cpu::ExecutionAuthority as Authority;
use crate::{BitString, Md5Backend, Md5BackendError, Md5BackendHealth};
use core::cell::Cell;

/// Explicit acknowledgement that every input and its length are public.
pub struct PublicData(());
impl PublicData {
    /// Classification is a caller obligation; this cannot inspect secrets.
    pub const fn acknowledge() -> Self {
        Self(())
    }
}

/// Per-executor route policy. Defaults never opt in automatically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Do not create an instruction authority.
    Portable,
    /// Permit pre-operation missing-feature or ineligible-workload fallback.
    Prefer,
    /// Require at least one real full-width vector invocation per batch.
    Require,
}

/// Value-free failure; every failure preserves all eight caller output slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Authority creation or validation failed; never permits silent fallback.
    Backend(Md5BackendError),
    /// No complete active group has a common full 64-byte message block.
    IneligibleWorkload,
    /// The executor was irreversibly revoked.
    Quarantined,
    /// Work budget, cancellation or message-domain failure.
    Batch(Md5BatchError),
}
impl From<Md5BackendError> for Error {
    fn from(value: Md5BackendError) -> Self {
        Self::Backend(value)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Backend(_) => "MD5 execution authority unavailable",
            Self::IneligibleWorkload => "MD5 workload has no full SIMD group",
            Self::Quarantined => "MD5 executor quarantined",
            Self::Batch(_) => "MD5 batch rejected",
        })
    }
}
impl core::error::Error for Error {}

/// Actual completed-batch accounting, never an execution capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Actual backend, None if this batch performed no SIMD at all.
    pub backend: Option<Md5Backend>,
    /// Actual independent-message vector width, or zero for entirely scalar work.
    pub vector_width: usize,
    /// Exact active lanes, scalar compressions (including padding) and SIMD blocks.
    pub work: Md5BatchReport,
}

/// Reusable, thread-bound ordinary policy/authority; batches own fresh state.
/// No Clone, raw-state import, session export or secret-output method exists.
pub struct Executor {
    authority: Option<Authority>,
    required: bool,
    revoked: Cell<bool>,
}
impl Executor {
    /// Always portable, even when compiled with SIMD features.
    pub const fn portable() -> Self {
        Self {
            authority: None,
            required: false,
            revoked: Cell::new(false),
        }
    }

    /// Explicit static selection. The full feature bundle is a lifetime-wide
    /// deployment obligation, not a runtime CPU probe. Startup failure is fatal.
    pub fn for_compiled_target(mode: Mode) -> Result<Self, Error> {
        if mode == Mode::Portable {
            return Ok(Self::portable());
        }
        match Authority::for_compiled_target() {
            Ok(authority) => Self::with_authority(authority, mode),
            Err(Md5BackendError::MissingFeatures) if mode == Mode::Prefer => Ok(Self::portable()),
            Err(error) => Err(error.into()),
        }
    }

    /// Takes an actual authority. Portable explicitly discards it; other modes
    /// retain it and check startup health, not a forgeable report or boolean.
    pub fn with_authority(authority: Authority, mode: Mode) -> Result<Self, Error> {
        if mode == Mode::Portable {
            return Ok(Self::portable());
        }
        authority.session().ensure_healthy()?;
        Ok(Self {
            authority: Some(authority),
            required: mode == Mode::Require,
            revoked: Cell::new(false),
        })
    }

    /// Configured backend, not a claim that a particular batch used SIMD.
    pub fn backend(&self) -> Option<Md5Backend> {
        self.authority.as_ref().map(Authority::backend)
    }

    /// Non-authorizing health snapshot.
    pub fn health(&self) -> Md5BackendHealth {
        if self.revoked.get() {
            Md5BackendHealth::Quarantined
        } else {
            self.authority
                .as_ref()
                .map_or(Md5BackendHealth::Healthy, Authority::health)
        }
    }

    /// Irreversible; also affects operations whose cancellation callback revokes.
    pub fn quarantine(&self) {
        self.revoked.set(true);
        if let Some(authority) = &self.authority {
            authority.quarantine();
        }
    }

    fn ready(&self) -> Result<(), Error> {
        if self.revoked.get() {
            return Err(Error::Quarantined);
        }
        if let Some(authority) = &self.authority {
            authority.session().ensure_healthy()?;
        }
        Ok(())
    }

    /// Hashes up to eight canonical byte/bit messages in deterministic slot order.
    /// Inactive slots become zero on success; active empty messages hash normally.
    /// Require rejects no-SIMD workloads before charging work or mutating output.
    /// Prefer may process an ineligible batch entirely portably and reports None.
    /// Backend loss never permits fallback. Budget/cancellation failures preserve
    /// output but consumed work is not refunded. Callback unwind revokes this owner.
    pub fn digest(
        &self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
        _public: PublicData,
    ) -> Result<Report, Error> {
        self.ready()?;
        let authority = self
            .authority
            .as_ref()
            .filter(|a| eligible(inputs, a.backend().lane_width()));
        if self.required && authority.is_none() {
            return Err(Error::IneligibleWorkload);
        }
        let mut guard = Operation {
            executor: self,
            complete: false,
        };
        let mut owner = BatchOwner::new();
        let result = match authority {
            Some(a) => vector::execute(&mut owner, inputs, control, a.session()),
            None => owner.portable(inputs, control),
        };
        let work = match result {
            Ok(work) => work,
            Err(error) => {
                // Work/cancellation can be retried using fresh batch state;
                // backend failure and unwind permanently revoke authority.
                guard.complete = error != Md5BatchError::Backend;
                return Err(Error::Batch(error));
            }
        };
        self.ready()?;
        if self.required && work.vector_blocks == 0 {
            return Err(Error::IneligibleWorkload);
        }
        let backend = authority
            .filter(|_| work.vector_blocks != 0)
            .map(Authority::backend);
        owner.commit_public(output);
        guard.complete = true;
        Ok(Report {
            backend,
            vector_width: backend.map_or(0, Md5Backend::lane_width),
            work,
        })
    }
}

fn eligible(inputs: &[Option<BitString<'_>>; 8], width: usize) -> bool {
    inputs.chunks(width).any(|group| {
        group.len() == width
            && group
                .iter()
                .all(|input| input.is_some_and(|bits| bits.split().0.len() >= 64))
    })
}

struct Operation<'a> {
    executor: &'a Executor,
    complete: bool,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.executor.quarantine();
        }
    }
}

#[cfg(test)]
mod tests;
