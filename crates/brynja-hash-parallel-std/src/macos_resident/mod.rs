//! Opt-in Apple Silicon resident/clearing ParallelHash; qualification pending.
//!
//! **Not strict protection: no core-dump exclusion.** Native macOS AArch64 only.
//! Root/leaf states and framing live on joined resident stacks; CVs, staging and
//! output use guarded, resident, fork-excluded mappings. No ordinary-memory or
//! serialized fallback. Only addresses, public shapes and status cross workers.
//! Caller input/copies, OS/TLS storage, panic hooks, dumps, fatal abort, snapshots
//! and arbitrary register capture are outside this owned-memory contract.
//! Deployment forbids fork, native thread cancellation and protection revocation.
//! Scalar sessions never select hardware; the separate acceleration feature
//! enables explicit Arm roots and single-Arm or NEON/scalar-tail leaf routes.
//!
//! ```no_run
//! use brynja_hash_parallel_std::macos_resident::{Algorithm, Limits, Session, Error};
//! let mut session = Session::new(Algorithm::ParallelHash256(256), Limits {
//!     workers: 4, max_leaves: 128, max_block_bytes: 4096,
//!     max_customization_bytes: 1024, max_output_bits: 4096,
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_buffer_mapping_bytes: 1048576,
//! })?;
//! let output = session.hash(b"input", 1024, b"example")?;
//! assert_eq!(output.expose().len(), 32); // explicit secret borrow
//! drop(output); // clears before reuse
//! # Ok::<(), Error>(())
//! ```
use crate::CancellationToken;
use resource::Mapping;
mod resource;
mod resource_error;
pub use resource_error::ResourceError;
#[cfg(feature = "macos-resident-acceleration")]
mod compiled;
mod types;
mod worker;
#[cfg(feature = "macos-resident-acceleration")]
pub use compiled::{BatchKernel, CompiledSession, Kernel, LeafRoute};
pub use types::{Algorithm, Bits, Error, Limits, PublicDeclassification};
#[cfg(test)]
mod tests;

/// Preacquired bounded resources; never retains populated root/leaf state.
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_hash_parallel_std::macos_resident::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_hash_parallel_std::macos_resident::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_hash_parallel_std::macos_resident::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_hash_parallel_std::macos_resident::Session>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_hash_parallel_std::macos_resident::Session>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel_std::macos_resident::{Session, Output, Error};
/// fn escape(s: &mut Session) -> Result<Output<'static>, Error> { s.hash(b"", 1, b"") }
/// ```
/// ```compile_fail
/// use brynja_hash_parallel_std::macos_resident::{Session, Error};
/// fn overlap(s: &mut Session) -> Result<(), Error> {
///     let first = s.hash(b"a", 1, b"")?;
///     let second = s.hash(b"b", 1, b"")?;
///     assert_eq!(first.expose(), second.expose()); Ok(())
/// }
/// ```
pub struct Session {
    root: Mapping,
    workers: Vec<Mapping>,
    cvs: Mapping,
    staging: Mapping,
    output: Mapping,
    algorithm: Algorithm,
    limits: Limits,
    #[cfg(test)]
    fault: tests::Fault,
}
impl Session {
    /// Acquires all stacks and buffers before accepting secret input.
    /// Empty output reserves one resident byte but exposes none.
    pub fn new(algorithm: Algorithm, limits: Limits) -> Result<Self, Error> {
        if !(1..=64).contains(&limits.workers)
            || limits.max_leaves == 0
            || limits.max_block_bytes == 0
            || algorithm.output_bits() > limits.max_output_bits
        {
            return Err(Error::WorkLimit);
        }
        if limits.stack_bytes < 65536 {
            return Err(ResourceError::InvalidSize.into());
        }
        let root = Mapping::new(limits.stack_bytes, limits.max_stack_mapping_bytes)?;
        let mut workers = Vec::new();
        workers
            .try_reserve_exact(limits.workers)
            .map_err(|_| Error::WorkLimit)?;
        for _ in 0..limits.workers {
            workers.push(Mapping::new(
                limits.stack_bytes,
                limits.max_stack_mapping_bytes,
            )?);
        }
        let cv_bytes = limits
            .max_leaves
            .checked_mul(if algorithm.wide() { 64 } else { 32 })
            .ok_or(Error::WorkLimit)?;
        let cvs = Mapping::new(cv_bytes, limits.max_buffer_mapping_bytes)?;
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
            root,
            workers,
            cvs,
            staging,
            output,
            algorithm,
            limits,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Exact public construction and output width.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Complete byte-aligned input/customization.
    pub fn hash(
        &mut self,
        input: &[u8],
        block_bytes: usize,
        customization: &[u8],
    ) -> Result<Output<'_>, Error> {
        self.compute(
            Bits::bytes(input),
            block_bytes,
            Bits::bytes(customization),
            &CancellationToken::new(),
        )
    }
    /// Complete arbitrary-bit request. Cancellation is checked between leaves,
    /// waves, merges, and XOF chunks (4096 bytes); one leaf, customization setup,
    /// and fixed finalization are bounded but not internally cancellable.
    /// Cancellation racing after the last checkpoint may still complete.
    /// All workers join before buffers clear; every error permits session reuse.
    pub fn compute(
        &mut self,
        input: Bits<'_>,
        block_bytes: usize,
        customization: Bits<'_>,
        cancel: &CancellationToken,
    ) -> Result<Output<'_>, Error> {
        self.cvs.clear();
        self.staging.clear();
        self.output.clear();
        #[cfg(test)]
        tests::configure(self);
        let mut buffers = Buffers {
            cvs: &mut self.cvs,
            staging: &mut self.staging,
            output: &mut self.output,
            keep: false,
        };
        if block_bytes == 0
            || block_bytes > self.limits.max_block_bytes
            || customization.bytes.len() > self.limits.max_customization_bytes
            || input.bytes.len().div_ceil(block_bytes) > self.limits.max_leaves
        {
            return Err(Error::WorkLimit);
        }
        check(cancel)?;
        worker::run(
            worker::Request {
                algorithm: self.algorithm,
                input,
                block: block_bytes,
                customization,
                cancel,
                #[cfg(test)]
                fault: self.fault,
            },
            worker::Resources {
                root: &mut self.root,
                workers: &mut self.workers,
                cvs: buffers.cvs.bytes_mut(),
                staging: buffers.staging.bytes_mut(),
                destination: buffers
                    .output
                    .bytes_mut()
                    .get_mut(..self.algorithm.output_bytes())
                    .ok_or(Error::Invariant)?,
            },
        )?;
        check(cancel)?;
        buffers.keep = true;
        drop(buffers);
        Ok(Output {
            output: &mut self.output,
            algorithm: self.algorithm,
        })
    }
}
struct Buffers<'a> {
    cvs: &'a mut Mapping,
    staging: &'a mut Mapping,
    output: &'a mut Mapping,
    keep: bool,
}
impl Drop for Buffers<'_> {
    fn drop(&mut self) {
        self.cvs.clear();
        self.staging.clear();
        if !self.keep {
            self.output.clear();
        }
    }
}
/// Affine resident output loan. Forgetting it cannot suppress session cleanup.
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_hash_parallel_std::macos_resident::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_hash_parallel_std::macos_resident::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_hash_parallel_std::macos_resident::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_hash_parallel_std::macos_resident::Output<'static>>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_hash_parallel_std::macos_resident::Output<'static>>();
/// ```
pub struct Output<'a> {
    output: &'a mut Mapping,
    algorithm: Algorithm,
}
impl Output<'_> {
    /// Public identity, including fixed/XOF domain and output width.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Deliberate secret borrow; copies are the caller's responsibility.
    pub fn expose(&self) -> &[u8] {
        if self.algorithm.output_bits() == 0 {
            &[]
        } else {
            self.output.bytes()
        }
    }
    /// Explicit public copy, consuming/clearing the loan. Width errors preserve
    /// the public destination and still clear the resident output.
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
fn check(cancel: &CancellationToken) -> Result<(), Error> {
    if cancel.is_cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
