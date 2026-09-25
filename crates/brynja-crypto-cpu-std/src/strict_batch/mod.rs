//! Protected SHA-2 and SHA-3/SHAKE/cSHAKE independent-message batches.
//!
//! Default-off, native GNU/Linux x86-64/little-endian AArch64 only. All workspace,
//! authorities, startup tests, scalar tails, SIMD scratch and staging are on
//! preacquired protected stacks/mappings; all workers join before stack clearing.
//! `Some(kernel)` requires actual SIMD work and compatible build-wide AVX2/NEON
//! throughout deployment. It never falls back; `None` explicitly selects portable.
//! Static authority is not runtime detection, affinity or a migration guarantee.
//! Shapes, lengths and reports are public. Caller copies, arbitrary interruption,
//! privileged snapshots and abort remain outside the bounded owned-memory contract.
//! Compiler/platform qualification and independent retest remain pending.
//!
//! Explicit protected portable execution (no silent acceleration):
//! ```no_run
//! use brynja_crypto_cpu_std::strict_batch::*;
//! fn example(message: &[u8], limits: Limits) -> Result<(), Error> {
//!     let mut session = Session::new(Route::Sha256(None), limits)?;
//!     let mut inputs = std::array::from_fn(|_| None);
//!     inputs[0] = Some(Input::bytes(Algorithm::Sha256(Sha256Algorithm::Sha256), message));
//!     let output = session.digest(&inputs, 1024, &Cancellation::new())?;
//!     assert_eq!(output.expose(0).map(<[u8]>::len), Some(32));
//!     // Borrow only; dropping the loan clears protected output.
//!     Ok(())
//! }
//! ```
use crate::protected_memory::{ProtectedBytes, ProtectedStack};
#[cfg(test)]
mod tests;
mod types;
mod worker;
pub use brynja_hash_sha2::PublicDeclassification;
pub use brynja_hash_sha2::hardened_batch::{Algorithm as Sha256Algorithm, Kernel as Sha256Kernel};
pub use brynja_hash_sha2::hardened_batch512::{
    Algorithm as Sha512Algorithm, Kernel as Sha512Kernel,
};
pub use brynja_hash_sha3::hardened_batch::{Algorithm as KeccakAlgorithm, Kernel as KeccakKernel};
pub use types::{Algorithm, Bits, Cancellation, Error, Input, Limits, Report, Route};
use types::{keccak, sha256, sha512};

/// Preacquired protected resources. No populated owner crosses a worker join.
/// Backend/invariant failure and recoverable worker unwind permanently quarantine.
/// Ordinary budget/input/cancellation rejection permits reuse; no reset exists.
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_crypto_cpu_std::strict_batch::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_crypto_cpu_std::strict_batch::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_crypto_cpu_std::strict_batch::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_crypto_cpu_std::strict_batch::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_crypto_cpu_std::strict_batch::Session>();
/// ```
pub struct Session {
    stack: ProtectedStack,
    staging: ProtectedBytes,
    scratch: ProtectedBytes,
    output: ProtectedBytes,
    route: Route,
    limits: Limits,
    quarantined: bool,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Session {
    /// Acquires all resources and tests required authority before accepting input.
    pub fn new(route: Route, limits: Limits) -> Result<Self, Error> {
        let mut stack = ProtectedStack::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let bytes = limits.max_output_bytes.max(1);
        let staging = ProtectedBytes::new(bytes, limits.max_buffer_mapping_bytes)?;
        let scratch = ProtectedBytes::new(bytes, limits.max_buffer_mapping_bytes)?;
        let output = ProtectedBytes::new(bytes, limits.max_buffer_mapping_bytes)?;
        let mut result = Err(Error::Invariant);
        stack.run(|| result = worker::probe(route))?;
        result?;
        Ok(Self {
            stack,
            staging,
            scratch,
            output,
            route,
            limits,
            quarantined: false,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Configured route, not qualification evidence.
    pub const fn route(&self) -> Route {
        self.route
    }
    /// Irreversible wrapper-local health.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Clears buffers, including forgotten loans, and rejects all future requests.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.output.clear();
        self.staging.clear();
        self.scratch.clear();
    }
    /// Complete bounded batch. SHA-256 has eight slots; for SHA-512/Keccak slots
    /// 4..8 must be inactive. Required SIMD rejects ineligible workloads without
    /// poisoning reuse. Cancellation is checked by library callbacks between
    /// compression/permutation steps and before output commit; no user callback.
    pub fn digest(
        &mut self,
        inputs: &[Option<Input<'_>>; 8],
        max_work: u64,
        cancel: &Cancellation,
    ) -> Result<Output<'_>, Error> {
        self.output.clear();
        self.staging.clear();
        self.scratch.clear();
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        let layout = validate(self.route, self.limits, inputs)?;
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        self.quarantined = true;
        let mut guard = Buffers {
            output: &mut self.output,
            staging: &mut self.staging,
            scratch: &mut self.scratch,
            keep: false,
        };
        let request = worker::Request {
            route: self.route,
            inputs,
            max_work,
            cancel,
            #[cfg(test)]
            fault: self.fault,
        };
        let staging = guard.staging.as_bytes_mut();
        let scratch = guard.scratch.as_bytes_mut();
        let output = guard.output.as_bytes_mut();
        let mut result = Err(Error::Invariant);
        self.stack
            .run(|| result = worker::run(request, staging, scratch, output))?;
        if types::reusable(&result) {
            self.quarantined = false;
        }
        let report = result?;
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        guard.keep = true;
        drop(guard);
        Ok(Output {
            output: &mut self.output,
            layout,
            report,
        })
    }
}
fn validate(
    route: Route,
    limits: Limits,
    inputs: &[Option<Input<'_>>; 8],
) -> Result<[Option<(Algorithm, usize)>; 8], Error> {
    let mut layout = [None; 8];
    let (mut messages, mut custom, mut output) = (0usize, 0usize, 0usize);
    for (index, input) in inputs.iter().enumerate() {
        let Some(input) = input else { continue };
        if index >= route.capacity() {
            return Err(Error::InvalidInput);
        }
        match (route, input.algorithm) {
            (Route::Sha256(_), Algorithm::Sha256(_)) | (Route::Sha512(_), Algorithm::Sha512(_)) => {
                if !input.name.bytes.is_empty() || !input.customization.bytes.is_empty() {
                    return Err(Error::InvalidInput);
                }
            }
            (Route::Keccak(_), Algorithm::Keccak(algorithm, bits)) => {
                if algorithm.fixed_output_bits().is_some_and(|n| n != bits)
                    || (!matches!(
                        algorithm,
                        keccak::Algorithm::Cshake128 | keccak::Algorithm::Cshake256
                    ) && (!input.name.bytes.is_empty()
                        || !input.customization.bytes.is_empty()))
                {
                    return Err(Error::InvalidInput);
                }
            }
            _ => return Err(Error::InvalidInput),
        }
        for bits in [&input.message, &input.name, &input.customization] {
            if (bits.bytes.is_empty() && bits.valid_bits != 0)
                || (!bits.bytes.is_empty() && !(1..=8).contains(&bits.valid_bits))
            {
                return Err(Error::InvalidInput);
            }
        }
        messages = messages
            .checked_add(input.message.bytes.len())
            .ok_or(Error::WorkLimit)?;
        custom = custom
            .checked_add(input.name.bytes.len())
            .and_then(|n| n.checked_add(input.customization.bytes.len()))
            .ok_or(Error::WorkLimit)?;
        *layout.get_mut(index).ok_or(Error::Invariant)? = Some((input.algorithm, output));
        output = output
            .checked_add(input.algorithm.output_bytes())
            .ok_or(Error::WorkLimit)?;
    }
    if messages > limits.max_input_bytes
        || custom > limits.max_customization_bytes
        || output > limits.max_output_bytes
    {
        return Err(Error::WorkLimit);
    }
    Ok(layout)
}
struct Buffers<'a> {
    output: &'a mut ProtectedBytes,
    staging: &'a mut ProtectedBytes,
    scratch: &'a mut ProtectedBytes,
    keep: bool,
}
impl Drop for Buffers<'_> {
    fn drop(&mut self) {
        self.staging.clear();
        self.scratch.clear();
        if !self.keep {
            self.output.clear();
        }
    }
}
/// Affine protected output with exact per-slot identity and width. Inactive slots
/// return None; zero-length active XOF outputs return Some(empty). Forgetting this
/// loan cannot suppress session cleanup. Explicit exposure is not declassification.
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_crypto_cpu_std::strict_batch::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_crypto_cpu_std::strict_batch::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_crypto_cpu_std::strict_batch::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_crypto_cpu_std::strict_batch::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_crypto_cpu_std::strict_batch::Output<'static>>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_batch::{Session, Output, Input, Cancellation};
/// fn escape(s: &mut Session, inputs: &[Option<Input<'_>>; 8]) -> Output<'static> {
///     s.digest(inputs, 100, &Cancellation::new()).unwrap()
/// }
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::strict_batch::{Session, Input, Cancellation};
/// fn overlap(s: &mut Session, inputs: &[Option<Input<'_>>; 8]) {
///     let output = s.digest(inputs, 100, &Cancellation::new()).unwrap();
///     s.quarantine();
///     let _ = output.expose(0);
/// }
/// ```
pub struct Output<'a> {
    output: &'a mut ProtectedBytes,
    layout: [Option<(Algorithm, usize)>; 8],
    report: Report,
}
impl Output<'_> {
    /// Explicit secret borrow for one active slot; copies are caller-owned.
    pub fn expose(&self, index: usize) -> Option<&[u8]> {
        let (algorithm, offset) = self.layout.get(index).copied().flatten()?;
        self.output
            .as_bytes()
            .get(offset..offset.checked_add(algorithm.output_bytes())?)
    }
    /// Exact public identity of one slot.
    pub fn algorithm(&self, index: usize) -> Option<Algorithm> {
        self.layout.get(index).copied().flatten().map(|v| v.0)
    }
    /// Actual performed work, without secret contents.
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Transactionally releases all requested slots after complete shape validation.
    /// Consumes/clears even on error. There is no implicit public output conversion.
    pub fn declassify(
        self,
        destinations: [Option<&mut [u8]>; 8],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        for (index, out) in destinations.iter().enumerate() {
            match (self.expose(index), out) {
                (None, None) => (),
                (Some(a), Some(b)) if a.len() == b.len() => (),
                _ => return Err(Error::InvalidInput),
            }
        }
        for (index, out) in destinations.into_iter().enumerate() {
            if let (Some(source), Some(out)) = (self.expose(index), out) {
                out.copy_from_slice(source);
            }
        }
        Ok(())
    }
}
impl Drop for Output<'_> {
    fn drop(&mut self) {
        self.output.clear();
    }
}
