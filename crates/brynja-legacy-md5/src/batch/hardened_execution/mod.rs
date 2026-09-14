//! Opt-in secret-bearing MD5 SIMD batches. MD5 remains collision-broken.
//!
//! Batch lengths, slot activity, work and route reports are PUBLIC. Pad inputs
//! externally if these dimensions are confidential. All eight scalar owners and
//! all packed SIMD storage clear on success/error/cancellation/recoverable unwind
//! and Drop. Registers, compiler copies/spills, caches, dumps, caller copies,
//! abort, termination and mem::forget remain explicit residual risks. This is
//! neither independent cryptographic verification nor FIPS/military approval.
mod vector;
use super::{Md5BatchControl, Md5BatchError, Md5BatchReport, owner::BatchOwner};
pub use crate::cpu::secret::Authority;
use crate::{BitString, Md5Backend, Md5BackendError, Md5BackendHealth, PublicDeclassification};
use brynja_core::{OwnedSecretRegion, SecretRegionInitialization};
use core::{cell::Cell, marker::PhantomData};

/// Explicit opt-in policy, selected before supplying any secret input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Never construct an instruction authority.
    Portable,
    /// Allow pre-operation unavailability/ineligible-workload portable fallback.
    Prefer,
    /// Require actual full-width SIMD work; reject ineligible batches atomically.
    Require,
}
/// Value-free error; public destinations are unchanged, secret ones are cleared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Authority failed; never allows silent fallback.
    Backend(Md5BackendError),
    /// No complete active SIMD group shares a full 64-byte prefix.
    IneligibleWorkload,
    /// Explicit revocation or failure made this executor unusable.
    Quarantined,
    /// Work, cancellation, length or output ownership failure.
    Batch(Md5BatchError),
}
impl From<Md5BackendError> for Error {
    fn from(e: Md5BackendError) -> Self {
        Self::Backend(e)
    }
}
impl From<Md5BatchError> for Error {
    fn from(e: Md5BatchError) -> Self {
        Self::Batch(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Backend(_) => "hardened MD5 authority failed",
            Self::IneligibleWorkload => "hardened MD5 workload has no SIMD group",
            Self::Quarantined => "hardened MD5 executor quarantined",
            Self::Batch(_) => "hardened MD5 batch rejected",
        })
    }
}
impl core::error::Error for Error {}
/// Public work accounting, never a capability or secret digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// None when no SIMD executed, even when an authority was available.
    pub backend: Option<Md5Backend>,
    /// Actual independent-message width, zero for portable execution.
    pub vector_width: usize,
    /// Active slots and exact vector/scalar block counts, including padding.
    pub work: Md5BatchReport,
}
/// Reusable policy owner; each borrowed batch creates fresh affine lane owners.
/// No Clone/Copy/Debug/Send/Sync or ordinary-authority conversion is provided.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Executor>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Executor>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Executor>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Executor>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Executor>();
/// ```
pub struct Executor {
    authority: Option<Authority>,
    required: bool,
    revoked: Cell<bool>,
    thread: PhantomData<*mut ()>,
}
impl Executor {
    /// Always portable, including in target-specialized binaries.
    pub const fn portable() -> Self {
        Self {
            authority: None,
            required: false,
            revoked: Cell::new(false),
            thread: PhantomData,
        }
    }
    /// Uses an explicit complete binary target contract, not runtime detection.
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
    /// Consumes a distinct hardened authority. Ordinary authorities are rejected
    /// by the type system. Portable discards it without secret computation.
    pub fn with_authority(authority: Authority, mode: Mode) -> Result<Self, Error> {
        if mode == Mode::Portable {
            return Ok(Self::portable());
        }
        authority.ensure_healthy()?;
        Ok(Self {
            authority: Some(authority),
            required: mode == Mode::Require,
            revoked: Cell::new(false),
            thread: PhantomData,
        })
    }
    /// Configured identity, not a claim that a batch executed instructions.
    pub fn backend(&self) -> Option<Md5Backend> {
        self.authority.as_ref().map(Authority::backend)
    }
    /// Current health observation, not platform attestation.
    pub fn health(&self) -> Md5BackendHealth {
        if self.revoked.get() {
            Md5BackendHealth::Quarantined
        } else {
            self.authority
                .as_ref()
                .map_or(Md5BackendHealth::Healthy, Authority::health)
        }
    }
    /// Irreversibly revokes this executor and all its borrowing batches.
    pub fn quarantine(&self) {
        self.revoked.set(true);
        if let Some(a) = &self.authority {
            a.quarantine();
        }
    }
    fn ready(&self) -> Result<(), Error> {
        if self.revoked.get() {
            return Err(Error::Quarantined);
        }
        if let Some(a) = &self.authority {
            a.ensure_healthy()?;
        }
        Ok(())
    }
    /// Allocates no heap memory. Consuming a batch prevents reuse after success,
    /// error or cancellation; dropping it clears all active/inactive lane storage.
    pub fn batch(&self) -> Batch<'_> {
        Batch {
            executor: self,
            owner: BatchOwner::new(),
        }
    }
}
/// Eight ordered clearing lane owners, consumed by either output operation.
/// `None` is inactive; `Some(empty)` is an active empty message. Unequal suffixes
/// and all padding use hardened portable owners. No implicit public output exists.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Batch<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Batch<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Batch<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Batch<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Batch<'static>>();
/// ```
pub struct Batch<'a> {
    executor: &'a Executor,
    owner: BatchOwner,
}
impl Batch<'_> {
    /// Declassifies all results only after complete success; errors/unwind never
    /// alter the public destination. Inactive slots become zero on success.
    pub fn digest_public(
        mut self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
        _authority: PublicDeclassification,
    ) -> Result<Report, Error> {
        let report = self.run(inputs, control)?;
        self.owner.commit_public(output);
        Ok(report)
    }
    /// Returns a non-cloneable clearing secret owner spanning all eight slots.
    /// Every failure/unwind clears the WHOLE supplied destination, including
    /// inactive and not-yet-written slots. Caller inputs remain caller-owned.
    pub fn digest_secret<'out>(
        mut self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &'out mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
    ) -> Result<(OwnedSecretRegion<'out>, Report), Error> {
        let mut initialization = SecretRegionInitialization::begin(output.as_flattened_mut())
            .map_err(|_| Md5BatchError::SecretMemory)?;
        let report = self.run(inputs, control)?;
        for lane in &self.owner.lanes {
            initialization
                .write(&lane.output_staging)
                .map_err(|_| Md5BatchError::SecretMemory)?;
        }
        let output = initialization
            .finish()
            .map_err(|_| Md5BatchError::SecretMemory)?;
        Ok((output, report))
    }
    fn run(
        &mut self,
        inputs: &[Option<BitString<'_>>; 8],
        control: &mut Md5BatchControl<'_>,
    ) -> Result<Report, Error> {
        let mut guard = Operation {
            executor: self.executor,
            complete: false,
        };
        self.executor.ready()?;
        let authority = self
            .executor
            .authority
            .as_ref()
            .filter(|a| eligible(inputs, a.backend().lane_width()));
        if self.executor.required && authority.is_none() {
            return Err(Error::IneligibleWorkload);
        }
        let work = match authority {
            Some(a) => vector::execute(&mut self.owner, inputs, control, a)?,
            None => self.owner.portable(inputs, control)?,
        };
        self.executor.ready()?;
        if self.executor.required && work.vector_blocks == 0 {
            return Err(Error::IneligibleWorkload);
        }
        let backend = authority
            .filter(|_| work.vector_blocks != 0)
            .map(Authority::backend);
        guard.complete = true;
        Ok(Report {
            backend,
            vector_width: backend.map_or(0, Md5Backend::lane_width),
            work,
        })
    }
}
fn eligible(inputs: &[Option<BitString<'_>>; 8], width: usize) -> bool {
    inputs
        .chunks(width)
        .any(|g| g.len() == width && g.iter().all(|i| i.is_some_and(|b| b.split().0.len() >= 64)))
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
