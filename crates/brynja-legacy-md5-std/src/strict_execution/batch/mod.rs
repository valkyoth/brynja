//! Protected legacy MD5 SIMD batches. MD5 remains collision-broken.
//!
//! Default-off `strict-acceleration`, GNU/Linux x86-64 AVX2 or little-endian
//! AArch64 NEON only; complete build-wide features and compatible deployment
//! throughout every worker are mandatory. Static admission is not detection or
//! migration protection. At least one full SIMD group is required; unequal tails
//! and padding use the existing clearing scalar implementation. No unavailable/ineligible
//! fallback. Lengths, slot activity and work reports are public; pad externally
//! for length privacy. This does not make MD5 suitable for authentication.
//!
//! Authority, all eight lane owners, SIMD scratch and staging are created only
//! on a preacquired resident, dump/fork-excluded protected stack. Output remains
//! in a protected mapping until explicit exposure/declassification or clearing.
//! Qualification/retest remain pending. Caller copies, arbitrary interruptions,
//! privileged snapshots and abort remain outside this bounded contract.
//!
//! ```no_run
//! use brynja_legacy_md5_std::strict_execution::{batch::*, Cancellation};
//! fn compatibility_only(messages: [&[u8]; 8], limits: Limits) -> Result<(), Error> {
//!     // Requires compiled SIMD and enough blocks for a full SIMD group.
//!     let mut session = Session::new(limits)?;
//!     let inputs = messages.map(|message| Some(Input::bytes(message)));
//!     let output = session.digest(&inputs, 1024, &Cancellation::new())?;
//!     assert_eq!(output.expose().len(), 128);
//!     Ok(())
//! }
//! ```
use super::{Cancellation, PublicDeclassification};
use brynja_crypto_cpu_std::protected_memory::{self, ProtectedBytes, ProtectedStack};
use brynja_legacy_md5::{Md5Backend, hardened_execution as api};
#[cfg(test)]
mod tests;
mod worker;

/// One unvalidated borrowed MSB-first message. Canonicality is checked on the worker.
pub struct Input<'a> {
    /// Original caller storage is not protected by this wrapper.
    pub bytes: &'a [u8],
    /// Zero for empty; otherwise 1..=8 with unused low bits zero.
    pub valid_bits: u8,
}
impl<'a> Input<'a> {
    /// One byte-aligned input; `None` denotes an inactive slot, not an empty message.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            valid_bits: if bytes.is_empty() { 0 } else { 8 },
        }
    }
}
/// Public resource and aggregate input bounds. There are always eight slots.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Native worker stack, at least 64 KiB.
    pub stack_bytes: usize,
    /// Stack mapping budget including guards/rounding.
    pub max_stack_mapping_bytes: usize,
    /// Digest mapping budget including guards/rounding (128 used bytes).
    pub max_output_mapping_bytes: usize,
    /// Sum of all active message bits, excluding padding.
    pub max_input_bits: u128,
}
/// Value-free failures; no secret output or partial state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Protected target/resource/thread requirement failed.
    Resource(protected_memory::Error),
    /// Invalid canonical bit encoding.
    InvalidBits,
    /// Aggregate input bound exceeded or overflowed.
    WorkLimit,
    /// Cancellation observed before or after bounded batch processing.
    Cancelled,
    /// Underlying batch/authority failure; see its explicit request classification.
    Execution(api::Error),
    /// Wrapper permanently revoked.
    Quarantined,
    /// Internal route/output invariant failed.
    Invariant,
    /// Public destination width differs from eight 16-byte slots.
    OutputLength,
}
impl From<protected_memory::Error> for Error {
    fn from(e: protected_memory::Error) -> Self {
        Self::Resource(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("strict legacy MD5 batch rejected")
    }
}
impl std::error::Error for Error {}
/// Preacquired protected resources, never a live or exported execution authority.
/// Backend/invariant failure and worker unwind quarantine permanently. Request
/// rejection/cancellation preserves reuse. No reset and no implicit declassification.
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Session>();
/// ```
pub struct Session {
    stack: ProtectedStack,
    output: ProtectedBytes,
    limits: Limits,
    backend: Md5Backend,
    quarantined: bool,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Session {
    /// Acquires all resources and runs the required startup KAT on the protected stack.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        super::require_target()
            .map_err(|_| Error::Resource(protected_memory::Error::Unsupported))?;
        let mut stack = ProtectedStack::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let output = ProtectedBytes::new(128, limits.max_output_mapping_bytes)?;
        let mut result = Err(Error::Invariant);
        stack.run(|| result = worker::probe())?;
        let backend = result?;
        Ok(Self {
            stack,
            output,
            limits,
            backend,
            quarantined: false,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Configured required identity; each successful report proves actual vector work.
    pub const fn backend(&self) -> Md5Backend {
        self.backend
    }
    /// Irreversible wrapper-local health.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Clears forgotten output and prevents future requests.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.output.clear();
    }
    /// Bounded complete batch. No caller callback runs on the protected worker.
    /// The compression budget counts all active lanes including scalar padding.
    pub fn digest(
        &mut self,
        inputs: &[Option<Input<'_>>; 8],
        max_compressions: usize,
        cancel: &Cancellation,
    ) -> Result<Output<'_>, Error> {
        self.output.clear();
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        validate(inputs, self.limits.max_input_bits)?;
        cancel.check().map_err(|_| Error::Cancelled)?;
        self.quarantined = true;
        let mut guard = Guard {
            output: &mut self.output,
            keep: false,
        };
        let request = worker::Request {
            inputs,
            max_compressions,
            cancel,
            backend: self.backend,
            #[cfg(test)]
            fault: self.fault,
        };
        let destination = guard.output.as_bytes_mut();
        let mut result = Err(Error::Invariant);
        self.stack
            .run(|| result = worker::run(request, destination))?;
        if reusable(&result) {
            self.quarantined = false;
        }
        let report = result?;
        cancel.check().map_err(|_| Error::Cancelled)?;
        guard.keep = true;
        drop(guard);
        Ok(Output {
            output: &mut self.output,
            report,
        })
    }
}
fn reusable(result: &Result<api::Report, Error>) -> bool {
    use brynja_legacy_md5::Md5BatchError as B;
    matches!(
        result,
        Ok(_)
            | Err(Error::InvalidBits | Error::Cancelled)
            | Err(Error::Execution(
                api::Error::IneligibleWorkload
                    | api::Error::Batch(B::WorkLimit | B::Cancelled | B::MessageTooLong)
            ))
    )
}
fn validate(inputs: &[Option<Input<'_>>; 8], limit: u128) -> Result<(), Error> {
    let mut total = 0u128;
    for input in inputs.iter().flatten() {
        let bits = if input.bytes.is_empty() {
            if input.valid_bits != 0 {
                return Err(Error::InvalidBits);
            }
            0
        } else {
            if !(1..=8).contains(&input.valid_bits) {
                return Err(Error::InvalidBits);
            }
            (input.bytes.len() as u128)
                .checked_sub(1)
                .and_then(|n| n.checked_mul(8))
                .and_then(|n| n.checked_add(u128::from(input.valid_bits)))
                .ok_or(Error::WorkLimit)?
        };
        total = total.checked_add(bits).ok_or(Error::WorkLimit)?;
    }
    if total > limit {
        Err(Error::WorkLimit)
    } else {
        Ok(())
    }
}
struct Guard<'a> {
    output: &'a mut ProtectedBytes,
    keep: bool,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.output.clear();
        }
    }
}
/// Affine protected loan over all eight ordered slots. Inactive slots are zero.
/// A forgotten loan does not defeat session clearing on reuse/quarantine/Drop.
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_legacy_md5_std::strict_execution::batch::Output<'static>>();
/// ```
/// ```compile_fail
/// use brynja_legacy_md5_std::strict_execution::{batch::{Session, Output, Input}, Cancellation};
/// fn escape(s: &mut Session, inputs: &[Option<Input<'_>>; 8]) -> Output<'static> {
///     s.digest(inputs, 100, &Cancellation::new()).unwrap()
/// }
/// ```
/// ```compile_fail
/// use brynja_legacy_md5_std::strict_execution::{batch::{Session, Input}, Cancellation};
/// fn overlap(s: &mut Session, inputs: &[Option<Input<'_>>; 8]) {
///     let output = s.digest(inputs, 100, &Cancellation::new()).unwrap();
///     s.quarantine();
///     let _ = output.expose();
/// }
/// ```
pub struct Output<'a> {
    output: &'a mut ProtectedBytes,
    report: api::Report,
}
impl Output<'_> {
    /// Explicit secret borrow; copied bytes become the caller's responsibility.
    pub fn expose(&self) -> &[u8] {
        self.output.as_bytes()
    }
    /// Public activity/work metadata, not digest bytes or authority.
    pub const fn report(&self) -> api::Report {
        self.report
    }
    /// Explicitly releases all eight slots; wrong width preserves the destination.
    pub fn declassify(
        self,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        if destination.len() != 128 {
            return Err(Error::OutputLength);
        }
        destination.copy_from_slice(self.expose());
        Ok(())
    }
}
impl Drop for Output<'_> {
    fn drop(&mut self) {
        self.output.clear();
    }
}
