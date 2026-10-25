//! Explicit legacy HMAC-MD5 SIMD composition; never selected by portable HMAC.
//!
//! At least one complete active group is required (eight AVX2 or four NEON
//! lanes). Every active ipad/opad is hashed, not imported as a chaining state.
//! Full groups use the existing hardened kernels; unequal tails and padding
//! remain scalar. Long-key normalization uses SIMD only for eligible groups,
//! otherwise a preselected portable owner. Errors never trigger fallback.
//!
//! Key/message lengths, slot activity, cancellation and work are PUBLIC. Pad
//! before calling if those dimensions are confidential. Caller inputs remain
//! caller-owned. Owned intermediate arrays clear on return or recoverable unwind;
//! no guarantee covers caller copies, compiler spills, registers, paging, dumps,
//! abort or termination. This composition is pending independent qualification.
//! MD5 compatibility is not authorization for a new protocol or FIPS approval.

mod engine;
mod output;

use crate::{BitString, Error, LegacyUse, Verification};
use brynja_core::{SecretRegionInitialization, copy_secret_region};
pub use brynja_legacy_md5::hardened_execution::Executor as Md5Executor;
/// `Require` requires SIMD in both HMAC ipad/opad passes, not every compression.
/// Sparse long keys lacking a full SIMD group are normalized by a separate
/// hardened portable batch; unequal suffixes and padding may also be scalar.
/// This public-shape selection precedes processing and is not error fallback.
pub use brynja_legacy_md5::hardened_execution::Mode as Md5Mode;
use brynja_legacy_md5::hardened_execution::in_place::Workspace;
pub use brynja_legacy_md5::{Md5Backend, Md5BatchControl, Md5BatchReport};
pub use output::{SecretTags, Tags};

/// Borrowed legacy key and canonical bit message for one independent lane.
/// No secret is retained by the selection token or copied into this descriptor.
pub struct Input<'a> {
    key: &'a [u8],
    message: BitString<'a>,
}
impl<'a> Input<'a> {
    /// Empty keys are mathematically accepted, not secure. Supply unpredictable
    /// keys and independently enforce the legacy protocol's failed-tag limits.
    pub const fn new(key: &'a [u8], message: BitString<'a>) -> Self {
        Self { key, message }
    }
}

/// Exact public compression accounting, including long-key normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Actual backend used for both inner and outer HMAC passes.
    pub backend: Md5Backend,
    /// Full independent-message width of that backend.
    pub vector_width: usize,
    /// Work spent normalizing keys longer than 64 bytes; zero otherwise.
    pub normalization: Md5BatchReport,
    /// Work including the ipad block and terminal padding.
    pub inner: Md5BatchReport,
    /// Work including the opad block and terminal padding.
    pub outer: Md5BatchReport,
}

/// Consuming, thread-bound policy selection borrowing a hardened MD5 executor.
/// It contains no key and does not enable runtime CPU detection. The executor's
/// deployment/feature guarantees must already hold. A failure cannot select a
/// portable HMAC implementation. Ordinary budget/cancellation/shape rejection
/// preserves executor reuse; backend/invariant failure or unwind quarantines it.
/// Under `panic = "abort"`, destructors cannot clear storage or quarantine.
/// `Md5Mode::Require` requires SIMD in ipad/opad passes. Sparse long keys use
/// a separate hardened portable batch for normalization; unequal suffixes and
/// padding may be scalar. This public-shape choice is never error fallback.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_legacy_hmac::md5_batch::Md5Batch<'static>>();
/// ```
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_legacy_hmac::md5_batch::Md5Batch<'static>>();
/// ```
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<brynja_legacy_hmac::md5_batch::Md5Batch<'static>>();
/// ```
/// ```compile_fail
/// fn debug<T: core::fmt::Debug>() {}
/// debug::<brynja_legacy_hmac::md5_batch::Md5Batch<'static>>();
/// ```
pub struct Md5Batch<'a> {
    executor: &'a Md5Executor,
    backend: Md5Backend,
    tag_bytes: usize,
}

impl<'a> Md5Batch<'a> {
    /// Selects full 16-byte tags before accepting any secret input.
    pub fn new(ack: LegacyUse, executor: &'a Md5Executor) -> Result<Self, Error> {
        Self::with_tag_length(ack, executor, 16)
    }
    /// Selects byte truncation in 10..=16, before accepting any secret input.
    pub fn with_tag_length(
        _ack: LegacyUse,
        executor: &'a Md5Executor,
        tag_bytes: usize,
    ) -> Result<Self, Error> {
        if !(10..=16).contains(&tag_bytes) {
            return Err(Error::TagLength);
        }
        let backend = executor.backend().ok_or(Error::ExecutionUnavailable)?;
        Workspace::new(executor)
            .with(|batch| batch.cancel())
            .map_err(engine::execution_error)?;
        Ok(Self {
            executor,
            backend,
            tag_bytes,
        })
    }

    /// Declassifies all active tags after complete success. Inactive slots and
    /// bytes beyond the selected truncation become zero; errors leave the entire
    /// public destination unchanged. All phases share the caller's work budget.
    pub fn authenticate<'out>(
        self,
        inputs: &[Option<Input<'_>>; 8],
        output: &'out mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
    ) -> Result<(Tags<'out>, Report), Error> {
        let active = inputs.each_ref().map(Option::is_some);
        let tag_bytes = self.tag_bytes;
        let (_, report) = self.run(inputs, control, |bytes| {
            copy_secret_region(output.as_flattened_mut(), bytes)?;
            Ok(())
        })?;
        Ok((Tags::new(output, active, tag_bytes), report))
    }

    /// Returns clearing ownership of all 128 destination bytes. Every error or
    /// recoverable unwind clears the WHOLE output, including inactive slots.
    pub fn authenticate_secret<'out>(
        self,
        inputs: &[Option<Input<'_>>; 8],
        output: &'out mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
    ) -> Result<(SecretTags<'out>, Report), Error> {
        let mut initialization = SecretRegionInitialization::begin(output.as_flattened_mut())?;
        let active = inputs.each_ref().map(Option::is_some);
        let tag_bytes = self.tag_bytes;
        let (region, report) = self.run(inputs, control, |bytes| {
            initialization.write(bytes)?;
            initialization.finish().map_err(Error::from)
        })?;
        Ok((SecretTags::new(region, active, tag_bytes), report))
    }

    /// Checks every active tag without a mismatch-dependent early exit. Exact
    /// candidate lengths and active-slot agreement are checked before key use.
    /// Only the aggregate decision is returned, not per-lane secret metadata.
    pub fn verify(
        self,
        inputs: &[Option<Input<'_>>; 8],
        candidates: &[Option<&[u8]>; 8],
        control: &mut Md5BatchControl<'_>,
    ) -> Result<(Verification, Report), Error> {
        for (input, candidate) in inputs.iter().zip(candidates) {
            match (input, candidate) {
                (None, None) => (),
                (Some(_), Some(bytes)) if bytes.len() == self.tag_bytes => (),
                _ => return Err(Error::TagLength),
            }
        }
        let tag_bytes = self.tag_bytes;
        self.run(inputs, control, |bytes| {
            let mut difference = crate::scratch::Scratch::<1>::new();
            for (row, candidate) in bytes.as_chunks::<16>().0.iter().zip(candidates) {
                if let Some(candidate) = candidate {
                    for (expected, actual) in row.iter().take(tag_bytes).zip(*candidate) {
                        brynja_core::accumulate_secret_byte_difference(
                            &mut difference.0[0],
                            expected,
                            actual,
                        );
                    }
                }
            }
            Ok(Verification::new(brynja_core::secret_difference_is_zero(
                &difference.0[0],
            )))
        })
    }

    fn run<R>(
        self,
        inputs: &[Option<Input<'_>>; 8],
        control: &mut Md5BatchControl<'_>,
        consume: impl FnOnce(&[u8]) -> Result<R, Error>,
    ) -> Result<(R, Report), Error> {
        let mut operation = engine::Operation::new(self.executor);
        let result = engine::compute(&self, inputs, control, consume);
        operation.complete(&result);
        result
    }
}
