//! Fixed-capacity lane ownership, portable execution and transactional outputs.
mod control;
mod owner;
#[cfg(feature = "cpu")]
mod vector;

use crate::{BitString, PublicDeclassification};
use brynja_core::{OwnedSecretRegion, SecretRegionInitialization};
pub use control::{Md5BatchControl, Md5BatchError};
use owner::BatchOwner;

/// Maximum independent message slots; inactive slots produce zero output.
pub const MAX_BATCH_LANES: usize = 8;

/// Secret-free accounting; message lengths, active slots and work are public.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Md5BatchReport {
    /// Number of active independent messages, including active empty messages.
    pub active_lanes: usize,
    /// Compression blocks processed portably, including all terminal padding.
    pub scalar_blocks: usize,
    /// Message blocks processed by SIMD (width times vector invocations).
    pub vector_blocks: usize,
}

/// Ordinary public-data batch owner; eight ordered slots, never heap allocated.
///
/// `None` is inactive, not an empty message. Outputs commit together only after
/// all active lanes finish; success writes zero to inactive output slots.
/// Each message is independent: batch hashing never concatenates the messages.
/// This consumes the owner; no restart, snapshot or post-failure reuse exists.
/// Kernel temporaries are not secret-cleanup-qualified. Use the distinct
/// [`HardenedMd5Batch`] for confidential inputs. MD5 remains collision-broken.
pub struct Md5Batch {
    owner: BatchOwner,
}

impl Md5Batch {
    /// Creates an empty fixed-capacity owner. Input is supplied at consumption.
    pub fn new() -> Self {
        Self {
            owner: BatchOwner::new(),
        }
    }

    /// Hashes canonical bit messages portably, preserving output on any error.
    /// Use `BitString::new(bytes, 8)` for nonempty byte messages and `([], 0)`
    /// for an active empty message. A completely inactive batch is valid.
    pub fn digest(
        mut self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
    ) -> Result<Md5BatchReport, Md5BatchError> {
        let report = self.owner.portable(inputs, control)?;
        self.owner.commit_public(output);
        Ok(report)
    }

    /// Uses an explicit unadmitted SIMD evidence session for full-width common
    /// prefixes. Single messages, inactive groups and terminal work stay scalar.
    /// The report counts actual vector work, not merely requested acceleration.
    #[cfg(feature = "cpu")]
    pub fn digest_with_backend(
        mut self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
        session: &crate::Md5BackendSession,
    ) -> Result<Md5BatchReport, Md5BatchError> {
        let report = vector::execute(&mut self.owner, inputs, control, session)?;
        // Validate again before the sole caller-output commit.
        session
            .ensure_healthy()
            .map_err(|_| Md5BatchError::Backend)?;
        self.owner.commit_public(output);
        Ok(report)
    }
}
impl Default for Md5Batch {
    fn default() -> Self {
        Self::new()
    }
}

/// Portable secret-bearing batch owner; it cannot accept an instruction session.
///
/// Reuses eight registered MD5 owners: every lane's chaining state, block,
/// lengths and output staging clear through their existing Drop implementation
/// on success, failure, cancellation and recoverable unwind. Output ownership
/// also clears on failure/unwind/Drop. Caller inputs remain caller-owned.
/// Lengths, slot activity, work and cancellation metadata are public; callers
/// must pad before using this API if their message lengths are confidential.
/// Registers, compiler-created copies, abort, forget and physical remnants retain
/// the portable MD5 owner's documented limits. No SIMD secret-erasure claim.
/// ```compile_fail
/// let batch = brynja_legacy_md5::HardenedMd5Batch::new();
/// let _ = batch.clone();
/// ```
/// ```compile_fail
/// let batch = brynja_legacy_md5::HardenedMd5Batch::new();
/// println!("{:?}", batch);
/// ```
/// ```compile_fail
/// use brynja_legacy_md5::{HardenedMd5Batch, Md5BackendSession, Md5BatchControl};
/// fn cannot_accelerate(secret: HardenedMd5Batch, session: &Md5BackendSession) {
///     let _ = secret.digest_with_backend(&[None;8], &mut [[0;16];8],
///         &mut Md5BatchControl::new(0), session);
/// }
/// ```
/// ```compile_fail
/// use brynja_legacy_md5::{HardenedMd5Batch, Md5BatchControl};
/// let secret = HardenedMd5Batch::new();
/// let mut output = [[0;16];8];
/// let _ = secret.digest_secret(&[None;8], &mut output, &mut Md5BatchControl::new(0));
/// let _ = secret.digest_secret(&[None;8], &mut output, &mut Md5BatchControl::new(0));
/// ```
pub struct HardenedMd5Batch {
    owner: BatchOwner,
}
impl HardenedMd5Batch {
    /// Creates eight independently clearing portable owners.
    pub fn new() -> Self {
        Self {
            owner: BatchOwner::new(),
        }
    }

    /// Consumes all inputs and releases all slots publicly only after success.
    /// Errors and recoverable unwind preserve the entire public destination.
    pub fn digest_public(
        mut self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
        _authority: PublicDeclassification,
    ) -> Result<Md5BatchReport, Md5BatchError> {
        let report = self.owner.portable(inputs, control)?;
        self.owner.commit_public(output);
        Ok(report)
    }

    /// Consumes all inputs into one affine 128-byte secret owner in slot order.
    /// Errors/cancellation/unwind clear every output slot, including inactive
    /// slots. An all-inactive batch returns a valid all-zero secret region.
    pub fn digest_secret<'out>(
        mut self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &'out mut [[u8; 16]; 8],
        control: &mut Md5BatchControl<'_>,
    ) -> Result<(OwnedSecretRegion<'out>, Md5BatchReport), Md5BatchError> {
        // Establish caller-output cleanup before any callback or computation.
        let mut initialization = SecretRegionInitialization::begin(output.as_flattened_mut())
            .map_err(|_| Md5BatchError::SecretMemory)?;
        let report = self.owner.portable(inputs, control)?;
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
}
impl Default for HardenedMd5Batch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
