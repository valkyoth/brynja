//! Opt-in resident scalar legacy MD5; qualification and independent retest pending.
//!
//! MD5 is collision-broken. This compatibility-only memory profile does not
//! restore collision resistance or make raw hashing an authentication mechanism.
//!
//! Native little-endian Apple Silicon macOS only; models and other targets reject.
//! This separate resident/clearing profile DOES NOT exclude core dumps and is
//! not a strict-profile fallback. Guarded locked output and a private joined
//! worker stack are acquired before processing; full owned payloads clear on
//! release, output on reuse/error/loan drop, and stack only after joining.
//! No public callback, active state or secret-bearing thread return is exposed.
//! Original buffers/copies, OS/TLS/panic-hook storage, hibernation, privileged
//! snapshots and fatal abort remain outside the guarantee. Deployment must forbid
//! fork, external lock/protection revocation and native thread cancellation while
//! resources are live. No certification or independent qualification is claimed.
//! Scalar Session never selects hardware; separately enabled acceleration is
//! explicit and never silently falls back. SHA-1/MD5 remain collision-broken.
//!
//! ```no_run
//! use brynja_legacy_md5_std::macos_resident::{Error, Limits, Session};
//! let mut session = Session::new(Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_output_mapping_bytes: 65536, max_message_bits: 8192, max_chunks: 16,
//! })?;
//! let digest = session.hash(b"abc")?;
//! // Explicit exposure borrows protected output; any copy becomes caller-owned.
//! assert_eq!(digest.expose().len(), 16);
//! drop(digest); // clears output; the session can now be reused
//! # Ok::<(), Error>(())
//! ```
use Mapping as ProtectedBytes;
use Mapping as ProtectedStack;
use resource::Mapping;
#[cfg(feature = "macos-resident-acceleration")]
pub mod batch;
mod resource;
mod resource_error;
#[cfg(test)]
mod test_storage;
pub use resource_error::ResourceError;
mod types;
mod worker;
pub use types::{Cancellation, Error, Limits, PublicDeclassification};
#[cfg(test)]
mod tests;

/// Preacquired resources for one fixed public legacy MD5 identity.
///
/// No active hash state is kept between calls. A forgotten digest loan does not
/// own cleanup: session reuse and Drop still clear the output mapping.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Session>();
/// ```
/// A protected output cannot outlive its owning session:
/// ```compile_fail
/// use brynja_legacy_md5_std::macos_resident::{Session, Digest, Error};
/// fn escape(s: &mut Session) -> Result<Digest<'static>, Error> { s.hash(b"abc") }
/// ```
/// A live digest loan prevents concurrent reuse:
/// ```compile_fail
/// use brynja_legacy_md5_std::macos_resident::{Session, Error};
/// fn reuse(s: &mut Session) -> Result<(), Error> {
///     let first = s.hash(b"abc")?;
///     let _second = s.hash(b"def")?;
///     let _borrow = first.expose();
///     Ok(())
/// }
/// ```
pub struct Session {
    stack: ProtectedStack,
    output: ProtectedBytes,
    limits: Limits,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Session {
    /// Rejects unsupported targets/models and protection failures without fallback.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        require_target()?;
        if limits.max_chunks == 0 || limits.stack_bytes < 65536 {
            return Err(Error::InvalidLimits);
        }
        let stack = ProtectedStack::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let output = ProtectedBytes::new(16, limits.max_output_mapping_bytes)?;
        Ok(Self {
            stack,
            output,
            limits,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }

    /// Hashes one borrowed byte string on the protected worker.
    pub fn hash(&mut self, input: &[u8]) -> Result<Digest<'_>, Error> {
        self.hash_chunks(&[input], &[], 0, &Cancellation::new())
    }

    /// Hashes byte-aligned chunks followed by one raw canonical MSB-first tail.
    ///
    /// `valid_bits` is 0 for an empty tail, 1..=8 otherwise. Tail canonicality is
    /// checked on the protected worker, not on the ordinary caller stack. Lengths
    /// and rejection are observable public metadata. Limits are checked before
    /// launching; cancellation is checked at most every 4096 input bytes and
    /// before output commit. A cancellation racing after the final check may
    /// still complete. Errors clear output; ordinary rejection does not poison
    /// this reusable resource. The callback itself is entirely library-controlled.
    /// Accounting uses checked u128 bits; MD5 encodes the low 64 length bits.
    /// This does not impose SHA-1's distinct less-than-2^64-bit message domain.
    pub fn hash_chunks(
        &mut self,
        chunks: &[&[u8]],
        tail: &[u8],
        valid_bits: u8,
        cancel: &Cancellation,
    ) -> Result<Digest<'_>, Error> {
        self.output.clear();
        let mut transaction = OutputGuard {
            output: &mut self.output,
            complete: false,
        };
        validate_request(self.limits, chunks, tail.len(), valid_bits)?;
        cancel.check()?;
        let mut result = Err(Error::Invariant);
        #[cfg(test)]
        let fault = self.fault;
        let destination = transaction.output.bytes_mut();
        #[cfg(test)]
        let ranges = test_storage::ranges_for_worker(&self.stack, destination);
        self.stack.run(|| {
            #[cfg(test)]
            test_storage::configure(ranges);
            #[cfg(test)]
            tests::configure(fault);
            result = worker::run(chunks, tail, valid_bits, cancel, destination);
        })?;
        result?;
        cancel.check()?;
        transaction.complete = true;
        drop(transaction);
        Ok(Digest {
            output: &mut self.output,
        })
    }
}

struct OutputGuard<'a> {
    output: &'a mut ProtectedBytes,
    complete: bool,
}
impl Drop for OutputGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.output.clear();
        }
    }
}

/// Affine protected output loan. No implicit public conversion or ordinary Eq.
/// Drop clears the owner; forgetting this loan cannot suppress its owner's cleanup.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_legacy_md5_std::macos_resident::Digest<'static>>();
/// ```
pub struct Digest<'a> {
    output: &'a mut ProtectedBytes,
}
impl Digest<'_> {
    /// Explicit borrow, not declassification. Caller-created copies are theirs to protect.
    pub fn expose(&self) -> &[u8] {
        self.output.bytes()
    }
    /// Deliberately copies to public storage, consuming and clearing this secret loan.
    /// Wrong width preserves the public destination and still clears the secret.
    pub fn declassify(
        self,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        if destination.len() != 16 {
            return Err(Error::OutputLength);
        }
        destination.copy_from_slice(self.output.bytes());
        Ok(())
    }
}
impl Drop for Digest<'_> {
    fn drop(&mut self) {
        self.output.clear();
    }
}

fn require_target() -> Result<(), Error> {
    if cfg!(all(
        target_os = "macos",
        target_arch = "aarch64",
        target_pointer_width = "64",
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )) {
        Ok(())
    } else {
        Err(Error::Resource(ResourceError::Unsupported))
    }
}

fn validate_request(
    limits: Limits,
    chunks: &[&[u8]],
    tail_bytes: usize,
    valid_bits: u8,
) -> Result<(), Error> {
    if chunks.len() > limits.max_chunks {
        return Err(Error::WorkLimit);
    }
    let mut bits = if tail_bytes == 0 {
        if valid_bits != 0 {
            return Err(Error::InvalidBits);
        }
        0
    } else {
        if !(1..=8).contains(&valid_bits) {
            return Err(Error::InvalidBits);
        }
        (tail_bytes as u128)
            .checked_sub(1)
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(u128::from(valid_bits)))
            .ok_or(Error::MessageTooLong)?
    };
    for chunk in chunks {
        bits = (chunk.len() as u128)
            .checked_mul(8)
            .and_then(|n| bits.checked_add(n))
            .ok_or(Error::MessageTooLong)?;
    }
    if bits > limits.max_message_bits {
        return Err(Error::WorkLimit);
    }
    Ok(())
}
