//! Opt-in protected-stack scalar SHA-2. Qualification and independent retest pending.
//!
//! Linux GNU x86-64/little-endian AArch64 only, never Miri/Kani's reference model.
//! Construction acquires guarded, resident, dump/fork-excluded stack and output
//! storage before an input can be submitted. A fresh joined native worker creates
//! and consumes the existing scoped hardened hash state on that protected stack.
//! No arbitrary callback, secret-bearing thread result or ordinary heap staging
//! is used by this wrapper. Stack clearing happens after join from the caller.
//! Output stays in its separately owned protected mapping, not a public digest.
//!
//! This is not whole-process/register/interruption erasure or certification.
//! Original inputs, caller copies, public lengths, OS scheduling, privileged
//! inspection, hibernation and process abort retain their documented limits.
//! Existing opaque scalar boundaries cover their normal returns only. No SIMD
//! or hardware route is selected here; those strict integrations remain pending.
//! Deployment must uphold the protected-memory contract (no external revocation,
//! fork or native cancellation). Recoverable worker panic clears before return;
//! panic hooks and fatal termination do not acquire stronger guarantees.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::strict_sha2::{Algorithm, Error, Limits, Session};
//! let mut session = Session::new(Algorithm::Sha256, Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_output_mapping_bytes: 65536, max_message_bits: 8192, max_chunks: 16,
//! })?;
//! let digest = session.hash(b"abc")?;
//! // Explicit exposure borrows protected output; any copy becomes caller-owned.
//! assert_eq!(digest.expose().len(), 32);
//! drop(digest); // clears output; the session can now be reused
//! # Ok::<(), Error>(())
//! ```
use crate::protected_memory::{ProtectedBytes, ProtectedStack};
mod types;
mod worker;
pub use types::{Algorithm, Cancellation, Error, Limits, PublicDeclassification, Sha512TBits};
#[cfg(test)]
mod tests;

/// Preacquired resources for one fixed public SHA-2 identity.
///
/// No active hash state is kept between calls. A forgotten digest loan does not
/// own cleanup: session reuse and Drop still clear the output mapping.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::strict_sha2::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::strict_sha2::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::strict_sha2::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::strict_sha2::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::strict_sha2::Session>();
/// ```
/// A protected output cannot outlive its owning session:
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_sha2::{Session, Digest, Error};
/// fn escape(s: &mut Session) -> Result<Digest<'static>, Error> { s.hash(b"abc") }
/// ```
/// A live digest loan prevents concurrent reuse:
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_sha2::{Session, Error};
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
    algorithm: Algorithm,
    limits: Limits,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Session {
    /// Rejects unsupported targets/models and protection failures without fallback.
    pub fn new(algorithm: Algorithm, limits: Limits) -> Result<Self, Error> {
        require_target()?;
        if limits.max_chunks == 0 {
            return Err(Error::InvalidLimits);
        }
        let stack = ProtectedStack::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let output =
            ProtectedBytes::new(algorithm.output_bytes(), limits.max_output_mapping_bytes)?;
        Ok(Self {
            stack,
            output,
            algorithm,
            limits,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }

    /// The fixed public identity, never private accumulated state.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
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
        validate_request(self.algorithm, self.limits, chunks, tail.len(), valid_bits)?;
        cancel.check()?;
        let mut result = Err(Error::Invariant);
        let algorithm = self.algorithm;
        #[cfg(test)]
        let fault = self.fault;
        let destination = transaction.output.as_bytes_mut();
        self.stack.run(|| {
            #[cfg(test)]
            tests::configure(fault);
            result = worker::run(algorithm, chunks, tail, valid_bits, cancel, destination);
        })?;
        result?;
        cancel.check()?;
        transaction.complete = true;
        drop(transaction);
        Ok(Digest {
            output: &mut self.output,
            algorithm,
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
/// bound::<brynja_crypto_cpu_std::strict_sha2::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::strict_sha2::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::strict_sha2::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::strict_sha2::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::strict_sha2::Digest<'static>>();
/// ```
pub struct Digest<'a> {
    output: &'a mut ProtectedBytes,
    algorithm: Algorithm,
}
impl Digest<'_> {
    /// The exact public identity, including general t even for equal byte widths.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Explicit borrow, not declassification. Caller-created copies are theirs to protect.
    pub fn expose(&self) -> &[u8] {
        self.output.as_bytes()
    }
    /// Deliberately copies to public storage, consuming and clearing this secret loan.
    /// Wrong width preserves the public destination and still clears the secret.
    pub fn declassify(
        self,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        if destination.len() != self.algorithm.output_bytes() {
            return Err(Error::OutputLength);
        }
        destination.copy_from_slice(self.output.as_bytes());
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
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )) {
        Ok(())
    } else {
        Err(Error::Resource(crate::protected_memory::Error::Unsupported))
    }
}

fn validate_request(
    algorithm: Algorithm,
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
    if matches!(algorithm, Algorithm::Sha224 | Algorithm::Sha256) && bits > u128::from(u64::MAX) {
        return Err(Error::MessageTooLong);
    }
    if bits > limits.max_message_bits {
        return Err(Error::WorkLimit);
    }
    Ok(())
}
