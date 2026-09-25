//! Opt-in protected scalar TupleHash/TupleHashXOF; qualification pending.
//!
//! GNU/Linux x86-64/little-endian AArch64 native builds only. Construction
//! acquires guarded, resident, dump/fork-excluded stack, staging and output
//! before accepting input. A library-controlled worker creates and consumes
//! scoped tuple state; each item writer must finish its exact derived length.
//! Join precedes whole-stack clearing. No populated state or secret thread
//! result crosses back to the ordinary caller.
//!
//! This is not whole-process/register/interruption erasure or certification.
//! Original inputs, caller copies, privileged snapshots and abort retain their
//! existing limits. Deployment must uphold protected-memory lifetimes: no fork,
//! external mapping revocation or native cancellation. This wrapper selects
//! scalar opaque boundaries only; strict accelerated integration remains pending.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::strict_tuplehash::{Algorithm, Item, Limits, Session, Error};
//! let mut session = Session::new(Algorithm::TupleHash256(256), Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_buffer_mapping_bytes: 65536, max_input_bits: 8192,
//!     max_customization_bits: 1024, max_output_bits: 4096,
//!     max_items: 16, max_chunks: 64,
//! })?;
//! let output = session.hash(&[Item::bytes(b"first"), Item::bytes(b"second")], b"example")?;
//! assert_eq!(output.expose().len(), 32); // deliberate secret borrow, not public output
//! drop(output); // clears before session reuse
//! # Ok::<(), Error>(())
//! ```
use crate::protected_memory::{ProtectedBytes, ProtectedStack};
mod types;
mod worker;
pub use types::{Algorithm, Bits, Cancellation, Error, Item, Limits, PublicDeclassification};
#[cfg(test)]
mod tests;

/// Preacquired resources, not a retained tuple or streaming writer.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Session>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_tuplehash::{Session, Output, Error};
/// fn escape(s: &mut Session) -> Result<Output<'static>, Error> { s.hash(&[], b"") }
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_tuplehash::{Session, Error};
/// fn overlap(s: &mut Session) -> Result<(), Error> {
///     let first = s.hash(&[], b"")?;
///     let second = s.hash(&[], b"")?;
///     assert_eq!(first.expose(), second.expose());
///     Ok(())
/// }
/// ```
pub struct Session {
    stack: ProtectedStack,
    staging: ProtectedBytes,
    output: ProtectedBytes,
    algorithm: Algorithm,
    limits: Limits,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Session {
    /// Acquires all three resources before an input is submitted. Never falls back.
    /// Empty output reserves one protected placeholder byte but exposes none.
    pub fn new(algorithm: Algorithm, limits: Limits) -> Result<Self, Error> {
        require_target()?;
        if algorithm.output_bits() > limits.max_output_bits {
            return Err(Error::WorkLimit);
        }
        let stack = ProtectedStack::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let width = algorithm.output_bytes().max(1);
        let staging = ProtectedBytes::new(
            if algorithm.xof() {
                width.min(4096)
            } else {
                width
            },
            limits.max_buffer_mapping_bytes,
        )?;
        let output = ProtectedBytes::new(width, limits.max_buffer_mapping_bytes)?;
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
    /// Public construction and exact width, not a customization or tuple identifier.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Hashes the item list with byte-aligned customization. Empty tuple and one
    /// empty item are distinct; splitting an item into chunks does not split it.
    pub fn hash(&mut self, items: &[Item<'_>], customization: &[u8]) -> Result<Output<'_>, Error> {
        self.compute(items, Bits::bytes(customization), &Cancellation::new())
    }
    /// Complete bounded request with arbitrary-bit items and customization.
    /// Shapes/budgets use public lengths before launch. Content validation occurs
    /// only on the protected worker. Item/message/XOF work checks cancellation at
    /// 4096-byte boundaries. Customization setup and fixed finalization are bounded
    /// but not internally cancellable. Cancellation racing after the final check
    /// may still complete. Errors/unwind clear both mappings and allow reuse.
    pub fn compute(
        &mut self,
        items: &[Item<'_>],
        customization: Bits<'_>,
        cancel: &Cancellation,
    ) -> Result<Output<'_>, Error> {
        self.output.clear();
        self.staging.clear();
        let mut guard = Buffers {
            output: &mut self.output,
            staging: &mut self.staging,
            keep_output: false,
        };
        validate(self.limits, items, &customization)?;
        cancel.check()?;
        let algorithm = self.algorithm;
        let destination = guard
            .output
            .as_bytes_mut()
            .get_mut(..algorithm.output_bytes())
            .ok_or(Error::Invariant)?;
        let staging = guard.staging.as_bytes_mut();
        let mut result = Err(Error::Invariant);
        #[cfg(test)]
        let fault = self.fault;
        self.stack.run(|| {
            #[cfg(test)]
            tests::configure(fault);
            result = worker::run(
                algorithm,
                items,
                customization,
                cancel,
                staging,
                destination,
            );
        })?;
        result?;
        cancel.check()?;
        guard.keep_output = true;
        drop(guard);
        Ok(Output {
            output: &mut self.output,
            algorithm,
        })
    }
}
struct Buffers<'a> {
    output: &'a mut ProtectedBytes,
    staging: &'a mut ProtectedBytes,
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
/// Affine protected output loan, not an ordinary digest or implicit public copy.
/// Forgetting the loan cannot suppress owning-session cleanup.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_crypto_cpu_std::strict_tuplehash::Output<'static>>();
/// ```
pub struct Output<'a> {
    output: &'a mut ProtectedBytes,
    algorithm: Algorithm,
}
impl Output<'_> {
    /// Exact public construction/width, including the fixed-versus-XOF distinction.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Explicit secret borrow, not declassification. Copies are caller-owned.
    pub fn expose(&self) -> &[u8] {
        if self.algorithm.output_bits() == 0 {
            &[]
        } else {
            self.output.as_bytes()
        }
    }
    /// Copies explicitly public output, consuming and clearing this loan.
    /// Wrong width preserves the public destination and still clears the secret.
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
fn item_bits(item: &Item<'_>) -> Result<u128, Error> {
    let mut bits = bit_length(&item.tail)? as u128;
    for chunk in item.chunks {
        bits = (chunk.len() as u128)
            .checked_mul(8)
            .and_then(|n| bits.checked_add(n))
            .ok_or(Error::MessageTooLong)?;
    }
    Ok(bits)
}
fn validate(limits: Limits, items: &[Item<'_>], customization: &Bits<'_>) -> Result<(), Error> {
    if items.len() > limits.max_items || bit_length(customization)? > limits.max_customization_bits
    {
        return Err(Error::WorkLimit);
    }
    let (mut bits, mut chunks) = (0u128, 0usize);
    for item in items {
        chunks = chunks
            .checked_add(item.chunks.len())
            .ok_or(Error::MessageTooLong)?;
        if chunks > limits.max_chunks {
            return Err(Error::WorkLimit);
        }
        bits = bits
            .checked_add(item_bits(item)?)
            .ok_or(Error::MessageTooLong)?;
        if bits > limits.max_input_bits {
            return Err(Error::WorkLimit);
        }
    }
    Ok(())
}
