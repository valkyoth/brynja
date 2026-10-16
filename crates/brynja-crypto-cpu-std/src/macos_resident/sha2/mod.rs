//! Scalar resident/clearing sessions on Apple Silicon; qualification pending.
//! No core-dump exclusion. Not exported by the strict facade.
//! The parent module's caller-copy, OS/TLS, fatal-abort and deployment limits apply.
//! No SIMD or hardware selection; every operation uses a fresh joined worker.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::macos_resident::sha2::{Algorithm, Error, Limits, Session};
//! let mut session = Session::new(Algorithm::Sha512_256, Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_output_mapping_bytes: 65536, max_message_bits: 65536, max_chunks: 16,
//! })?;
//! let digest = session.hash(b"abc")?;
//! assert_eq!(digest.algorithm(), Algorithm::Sha512_256);
//! assert_eq!(digest.expose().len(), 32);
//! # Ok::<(), Error>(())
//! ```
use super::resource::Mapping;
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
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Session>();
/// ```
/// A resident output cannot outlive its owning session:
/// ```compile_fail
/// use brynja_crypto_cpu_std::macos_resident::sha2::{Session, Digest, Error};
/// fn escape(s: &mut Session) -> Result<Digest<'static>, Error> { s.hash(b"abc") }
/// ```
/// A live digest loan prevents concurrent reuse:
/// ```compile_fail
/// use brynja_crypto_cpu_std::macos_resident::sha2::{Session, Error};
/// fn reuse(s: &mut Session) -> Result<(), Error> {
///     let first = s.hash(b"abc")?;
///     let _second = s.hash(b"def")?;
///     let _borrow = first.expose();
///     Ok(())
/// }
/// ```
pub struct Session {
    stack: Mapping,
    output: Mapping,
    algorithm: Algorithm,
    limits: Limits,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Session {
    /// Rejects unsupported targets/models and protection failures without fallback.
    pub fn new(algorithm: Algorithm, limits: Limits) -> Result<Self, Error> {
        require_target()?;
        if limits.max_chunks == 0 || limits.stack_bytes < 65536 {
            return Err(Error::InvalidLimits);
        }
        let stack = Mapping::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let output = Mapping::new(algorithm.output_bytes(), limits.max_output_mapping_bytes)?;
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

    /// Hashes one borrowed byte string on the resident worker.
    pub fn hash(&mut self, input: &[u8]) -> Result<Digest<'_>, Error> {
        self.hash_chunks(&[input], &[], 0, &Cancellation::new())
    }

    /// Hashes byte-aligned chunks followed by one raw canonical MSB-first tail.
    ///
    /// `valid_bits` is 0 for an empty tail, 1..=8 otherwise. Tail canonicality is
    /// checked on the resident worker, not on the ordinary caller stack. Lengths
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
        let destination = transaction.output.bytes_mut();
        #[cfg(test)]
        let range = (
            self.stack.bytes().as_ptr() as usize,
            self.stack.bytes().len(),
        );
        self.stack.run(|| {
            #[cfg(test)]
            tests::configure(fault, range);
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
    output: &'a mut Mapping,
    complete: bool,
}
impl Drop for OutputGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.output.clear();
        }
    }
}

/// Affine resident output loan. No implicit public conversion or ordinary Eq.
/// Drop clears the owner; forgetting this loan cannot suppress its owner's cleanup.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha2::Digest<'static>>();
/// ```
pub struct Digest<'a> {
    output: &'a mut Mapping,
    algorithm: Algorithm,
}
impl Digest<'_> {
    /// The exact public identity, including general t even for equal byte widths.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
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
        if destination.len() != self.algorithm.output_bytes() {
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
    super::require_native().map_err(Error::Resource)
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
