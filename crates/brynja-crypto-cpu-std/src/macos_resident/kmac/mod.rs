//! Opt-in Apple Silicon resident/clearing KMAC/KMACXOF; qualification pending.
//!
//! No core-dump exclusion; not exported by the strict facade. Caller inputs,
//! copies, OS/TLS/panic-hook storage, fatal abort and privileged capture remain
//! outside the parent profile. State, framing and comparison live on a private
//! joined resident worker; staging/output use separately guarded locked mappings.
//! Scalar `Session` never selects hardware. The separate
//! `macos-resident-kmac-acceleration` feature enables explicit Arm Keccak,
//! with compiled-feature/deployment requirements and no scalar fallback.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::macos_resident::kmac::{Algorithm, Session, Limits, Error};
//! let mut session = Session::new(Algorithm::Kmac256(256), Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_buffer_mapping_bytes: 65536, max_message_bits: 8192,
//!     max_setup_bits: 4096, max_output_bits: 4096, max_chunks: 16,
//! })?;
//! let output = session.authenticate(&[0x42; 32], b"message", b"example")?;
//! assert_eq!(output.expose().len(), 32); // deliberate secret borrow, not a public tag
//! drop(output); // clears before session reuse
//! # Ok::<(), Error>(())
//! ```
use super::resource::Mapping;
#[cfg(feature = "macos-resident-kmac-acceleration")]
mod compiled;
mod types;
mod worker;
#[cfg(feature = "macos-resident-kmac-acceleration")]
pub use compiled::{CompiledSession, Kernel};
pub use types::{Algorithm, Bits, Cancellation, Error, Limits, PublicDeclassification, Request};
#[cfg(test)]
mod tests;

/// Reusable resident resources, not a retained keyed state.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Session>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::macos_resident::kmac::{Session, Output, Error};
/// fn escape(s: &mut Session) -> Result<Output<'static>, Error> {
///     s.authenticate(&[0; 32], b"abc", b"")
/// }
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::macos_resident::kmac::{Session, Error};
/// fn overlap(s: &mut Session) -> Result<(), Error> {
///     let first = s.authenticate(&[0; 32], b"a", b"")?;
///     let second = s.authenticate(&[0; 32], b"b", b"")?;
///     assert_eq!(first.expose(), second.expose());
///     Ok(())
/// }
/// ```
pub struct Session {
    stack: Mapping,
    staging: Mapping,
    output: Mapping,
    algorithm: Algorithm,
    limits: Limits,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Session {
    /// Checks public output policy and acquires all three resources before input.
    pub fn new(algorithm: Algorithm, limits: Limits) -> Result<Self, Error> {
        require_target()?;
        if limits.max_chunks == 0 {
            return Err(Error::InvalidLimits);
        }
        if algorithm.output_bits() > limits.max_output_bits {
            return Err(Error::WorkLimit);
        }
        if !algorithm.xof() && algorithm.output_bits() < algorithm.strength() {
            return Err(Error::TagTooShort);
        }
        if limits.stack_bytes < 65536 {
            return Err(Error::Resource(super::Error::InvalidSize));
        }
        let stack = Mapping::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let width = algorithm.output_bytes().max(1);
        let staging = Mapping::new(
            if algorithm.xof() {
                width.min(4096)
            } else {
                width
            },
            limits.max_buffer_mapping_bytes,
        )?;
        let output = Mapping::new(width, limits.max_buffer_mapping_bytes)?;
        Ok(Self {
            stack,
            staging,
            output,
            algorithm,
            limits,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Public construction and width; keys and customization are not retained.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Complete byte-aligned request. Even ordinary MAC tags stay secret until
    /// explicit declassification. Original key/input storage remains caller-owned.
    pub fn authenticate(
        &mut self,
        key: &[u8],
        input: &[u8],
        customization: &[u8],
    ) -> Result<Output<'_>, Error> {
        self.compute(
            Request {
                key: Bits::bytes(key),
                customization: Bits::bytes(customization),
                chunks: &[input],
                tail: Bits::empty(),
            },
            &Cancellation::new(),
        )
    }
    /// Complete arbitrary-bit request, with canonical validation on the worker.
    /// Setup (key/customization) and fixed finalization are bounded by explicit
    /// budgets but not internally cancellable. Message/XOF processing checks at
    /// 4096-byte boundaries. No active state is retained. Errors/unwind clear both
    /// mappings; cancellation racing after the last check can still complete.
    pub fn compute(
        &mut self,
        request: Request<'_>,
        cancel: &Cancellation,
    ) -> Result<Output<'_>, Error> {
        self.execute(request, None, cancel)?;
        Ok(Output {
            output: &mut self.output,
            algorithm: self.algorithm,
        })
    }
    /// Verifies on the resident worker and explicitly releases only the decision.
    /// Candidate width must exactly match the session, including partial bits.
    /// Verification requires full-strength output even for XOF sessions. For
    /// canonical equal-width candidates, comparison has no content-dependent exit.
    /// Malformed/public lengths may reject early. Computed output is always cleared.
    /// Returns `Err(Error::Mismatch)` after cleanup for a completed mismatch.
    /// Reject the request on any error; never retry through a weaker route.
    pub fn verify(
        &mut self,
        request: Request<'_>,
        candidate: Bits<'_>,
        cancel: &Cancellation,
    ) -> Result<(), Error> {
        match self.execute(request, Some(candidate), cancel)? {
            Some(true) => Ok(()),
            Some(false) => Err(Error::Mismatch),
            None => Err(Error::Invariant),
        }
    }
    fn execute(
        &mut self,
        request: Request<'_>,
        candidate: Option<Bits<'_>>,
        cancel: &Cancellation,
    ) -> Result<Option<bool>, Error> {
        self.output.clear();
        self.staging.clear();
        let mut guard = Buffers {
            output: &mut self.output,
            staging: &mut self.staging,
            keep_output: false,
        };
        validate(self.algorithm, self.limits, &request, candidate.as_ref())?;
        cancel.check()?;
        let algorithm = self.algorithm;
        let verifying = candidate.is_some();
        let mut result = Err(Error::Invariant);
        let destination = guard
            .output
            .bytes_mut()
            .get_mut(..algorithm.output_bytes())
            .ok_or(Error::Invariant)?;
        let staging = guard.staging.bytes_mut();
        #[cfg(test)]
        let fault = self.fault;
        #[cfg(test)]
        let ranges = super::test_storage::ranges_for_worker(&self.stack, staging, destination);
        self.stack.run(|| {
            #[cfg(test)]
            super::test_storage::configure(ranges);
            #[cfg(test)]
            tests::configure(fault);
            result = worker::run(algorithm, request, candidate, cancel, staging, destination);
            #[cfg(test)]
            if matches!(result, Ok(Some(_))) {
                tests::comparison_complete();
            }
        })?;
        let result = result?;
        cancel.check()?;
        if result.is_some() != verifying {
            return Err(Error::Invariant);
        }
        guard.keep_output = !verifying;
        Ok(result)
    }
}
struct Buffers<'a> {
    output: &'a mut Mapping,
    staging: &'a mut Mapping,
    keep_output: bool,
}
impl Drop for Buffers<'_> {
    fn drop(&mut self) {
        self.staging.clear();
        if !self.keep_output {
            self.output.clear();
        }
    }
}

/// Affine secret output; forgetting the loan cannot disable session cleanup.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::kmac::Output<'static>>();
/// ```
pub struct Output<'a> {
    output: &'a mut Mapping,
    algorithm: Algorithm,
}
impl Output<'_> {
    /// Exact public construction/width, not a key or customization identifier.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Explicit borrowed secret access; any caller copy is outside this owner.
    pub fn expose(&self) -> &[u8] {
        if self.algorithm.output_bits() == 0 {
            &[]
        } else {
            self.output.bytes()
        }
    }
    /// Explicitly releases a public tag/derived output and clears the secret loan.
    /// Wrong destination width preserves public bytes and clears the secret.
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
impl Drop for Output<'_> {
    fn drop(&mut self) {
        self.output.clear();
    }
}

fn require_target() -> Result<(), Error> {
    super::require_native().map_err(Error::from)
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
fn validate(
    algorithm: Algorithm,
    limits: Limits,
    request: &Request<'_>,
    candidate: Option<&Bits<'_>>,
) -> Result<(), Error> {
    let key = bit_length(&request.key)?;
    if key < algorithm.strength() {
        return Err(Error::KeyTooShort);
    }
    let setup = key
        .checked_add(bit_length(&request.customization)?)
        .ok_or(Error::MessageTooLong)?;
    if setup > limits.max_setup_bits || request.chunks.len() > limits.max_chunks {
        return Err(Error::WorkLimit);
    }
    let mut bits = bit_length(&request.tail)? as u128;
    for chunk in request.chunks {
        bits = (chunk.len() as u128)
            .checked_mul(8)
            .and_then(|n| bits.checked_add(n))
            .ok_or(Error::MessageTooLong)?;
    }
    if bits > limits.max_message_bits {
        return Err(Error::WorkLimit);
    }
    if let Some(candidate) = candidate {
        if algorithm.output_bits() < algorithm.strength() {
            return Err(Error::TagTooShort);
        }
        if bit_length(candidate)? != algorithm.output_bits() {
            return Err(Error::OutputLength);
        }
    }
    Ok(())
}
