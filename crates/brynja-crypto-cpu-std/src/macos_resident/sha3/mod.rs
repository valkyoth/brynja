//! Resident/clearing sessions on Apple Silicon; qualification pending.
//! No core-dump exclusion. Not exported by the strict facade.
//! The parent module's caller-copy, OS/TLS, fatal-abort and deployment limits apply.
//! Scalar sessions never select hardware. Optional explicit `CompiledSession`
//! requires `macos-resident-acceleration`; every operation uses a fresh joined worker.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::macos_resident::sha3::{Algorithm, Error, Limits, Session};
//! let mut session = Session::new(Algorithm::Shake256(257), Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_output_mapping_bytes: 65536, max_message_bits: 65536,
//!     max_customization_bits: 4096, max_output_bits: 8192, max_chunks: 16,
//! })?;
//! let output = session.hash(b"abc")?;
//! assert_eq!(output.algorithm().output_bits(), 257);
//! assert_eq!(output.expose().len(), 33);
//! # Ok::<(), Error>(())
//! ```
use super::resource::Mapping;
#[cfg(feature = "macos-resident-acceleration")]
mod compiled;
#[cfg(feature = "macos-resident-acceleration")]
pub use compiled::{CompiledSession, Kernel};
mod types;
mod worker;
pub use types::{Algorithm, Bits, Cancellation, Error, Limits, PublicDeclassification};
#[cfg(test)]
mod tests;

/// Preacquired resources for one public identity and exact output width.
/// No active sponge is retained between requests. Digest loans prevent reuse.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Session>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::macos_resident::sha3::{Session, Digest, Error};
/// fn escape(s: &mut Session) -> Result<Digest<'static>, Error> { s.hash(b"abc") }
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::macos_resident::sha3::{Session, Error};
/// fn overlap(s: &mut Session) -> Result<(), Error> {
///     let first = s.hash(b"abc")?;
///     let second = s.hash(b"def")?;
///     assert_eq!(first.expose(), second.expose());
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
    /// Acquires all storage before an input can be submitted; never falls back.
    pub fn new(algorithm: Algorithm, limits: Limits) -> Result<Self, Error> {
        require_target()?;
        if limits.max_chunks == 0 || limits.stack_bytes < 65536 {
            return Err(Error::InvalidLimits);
        }
        if algorithm.output_bits() > limits.max_output_bits {
            return Err(Error::WorkLimit);
        }
        let stack = Mapping::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let output = Mapping::new(
            algorithm.output_bytes().max(1),
            limits.max_output_mapping_bytes,
        )?;
        Ok(Self {
            stack,
            output,
            algorithm,
            limits,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Public identity, never private accumulated state. cSHAKE N/S are per request.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// A byte-aligned message, using empty N/S for cSHAKE (SHAKE equivalence).
    pub fn hash(&mut self, input: &[u8]) -> Result<Digest<'_>, Error> {
        self.hash_chunks(&[input], Bits::empty(), &Cancellation::new())
    }
    /// Byte-aligned chunks followed by a canonical LSB-first tail, with empty N/S.
    pub fn hash_chunks(
        &mut self,
        chunks: &[&[u8]],
        tail: Bits<'_>,
        cancel: &Cancellation,
    ) -> Result<Digest<'_>, Error> {
        self.hash_customized_chunks(chunks, tail, Bits::empty(), Bits::empty(), cancel)
    }
    /// Complete request; N/S are allowed only for cSHAKE and may be arbitrary bits.
    ///
    /// Shape and budget checks use public lengths before launch. Canonicality is
    /// checked on the resident stack. Cancellation is checked before/after the
    /// bounded N/S prefix and at most every 4096 message/output bytes; it cannot
    /// interrupt prefix setup internally. Cancellation racing after the final
    /// check can still complete. Error/recoverable panic clears output, and the
    /// resource remains reusable. Caller-created copies remain caller-owned.
    pub fn hash_customized_chunks(
        &mut self,
        chunks: &[&[u8]],
        tail: Bits<'_>,
        name: Bits<'_>,
        customization: Bits<'_>,
        cancel: &Cancellation,
    ) -> Result<Digest<'_>, Error> {
        self.output.clear();
        let mut guard = OutputGuard {
            output: &mut self.output,
            complete: false,
        };
        validate_request(
            self.algorithm,
            self.limits,
            chunks,
            &tail,
            &name,
            &customization,
        )?;
        cancel.check()?;
        let algorithm = self.algorithm;
        let destination = guard
            .output
            .bytes_mut()
            .get_mut(..algorithm.output_bytes())
            .ok_or(Error::Invariant)?;
        let mut result = Err(Error::Invariant);
        #[cfg(test)]
        let fault = self.fault;
        #[cfg(test)]
        let range = (
            self.stack.bytes().as_ptr() as usize,
            self.stack.bytes().len(),
        );
        self.stack.run(|| {
            #[cfg(test)]
            tests::configure(fault, range);
            result = worker::run(
                algorithm,
                chunks,
                tail,
                name,
                customization,
                cancel,
                destination,
            );
        })?;
        result?;
        cancel.check()?;
        guard.complete = true;
        drop(guard);
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

/// Affine resident output loan; Drop clears, and forgetting cannot suppress
/// owning-session reuse/Drop cleanup. No implicit public conversion or Eq.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Digest<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::sha3::Digest<'static>>();
/// ```
pub struct Digest<'a> {
    output: &'a mut Mapping,
    algorithm: Algorithm,
}
impl Digest<'_> {
    /// Exact public identity/width. This is not a commitment to the request's N/S.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Explicit secret borrow, not declassification; copies are caller-owned.
    pub fn expose(&self) -> &[u8] {
        if self.algorithm.output_bits() == 0 {
            &[]
        } else {
            self.output.bytes()
        }
    }
    /// Consumes and clears this loan while explicitly copying to public storage.
    /// Wrong width leaves the public destination unchanged and clears the secret.
    pub fn declassify(
        self,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        if destination.len() != self.algorithm.output_bytes() {
            return Err(Error::OutputLength);
        }
        destination.copy_from_slice(self.expose());
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

fn bit_length(bits: &Bits<'_>) -> Result<usize, Error> {
    if bits.bytes.is_empty() {
        return if bits.valid_bits == 0 {
            Ok(0)
        } else {
            Err(Error::InvalidBits)
        };
    }
    if !(1..=8).contains(&bits.valid_bits) {
        return Err(Error::InvalidBits);
    }
    bits.bytes
        .len()
        .checked_sub(1)
        .and_then(|n| n.checked_mul(8))
        .and_then(|n| n.checked_add(usize::from(bits.valid_bits)))
        .ok_or(Error::MessageTooLong)
}
fn validate_request(
    algorithm: Algorithm,
    limits: Limits,
    chunks: &[&[u8]],
    tail: &Bits<'_>,
    name: &Bits<'_>,
    customization: &Bits<'_>,
) -> Result<(), Error> {
    if chunks.len() > limits.max_chunks {
        return Err(Error::WorkLimit);
    }
    let prefix = bit_length(name)?
        .checked_add(bit_length(customization)?)
        .ok_or(Error::MessageTooLong)?;
    if prefix != 0 && !algorithm.customized() {
        return Err(Error::Customization);
    }
    if prefix > limits.max_customization_bits {
        return Err(Error::WorkLimit);
    }
    let mut bits = bit_length(tail)? as u128;
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
