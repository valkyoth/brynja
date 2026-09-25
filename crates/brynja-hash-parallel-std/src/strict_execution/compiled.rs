use super::{Algorithm, Bits, Buffers, Error, Limits, Output, Session, check};
use crate::CancellationToken;
pub use brynja_crypto_cpu::keccak_hardened_batch::Kernel as BatchKernel;
pub use brynja_crypto_cpu::static_execution::Kernel;
#[cfg(test)]
mod tests;
mod worker;

/// Explicit worker policy, separate from required accelerated root selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeafRoute {
    /// Every leaf uses the selected single-state compiled Keccak kernel.
    Single(Kernel),
    /// Eligible leaf groups use this SIMD kernel; incomplete groups and unequal
    /// tails explicitly use clearing scalar work on protected worker stacks.
    /// Backend errors never authorize fallback. This is not an all-leaf SIMD claim.
    Batch(BatchKernel),
}
/// Protected compiled ParallelHash/ParallelHashXOF root and joined leaf workers.
///
/// GNU/Linux x86-64/little-endian AArch64 only. Complete build-wide AVX2 or
/// NEON/SHA3 (single-state Arm) / NEON (batch Arm) and lifetime-wide compatible
/// deployment are mandatory. Static admission is not runtime detection or a
/// scheduler/migration guarantee. Authorities and populated state never cross
/// threads; only typed exact-plan loans into protected CV mappings are transferred.
/// All started workers join before CV/staging/output cleanup. Ordinary invalid
/// input/cancellation permits reuse; invariant/backend/resource failures after
/// arming and recoverable worker panic quarantine permanently. No reset/export.
/// Inputs, scheduling/length privacy, privileged snapshots, interruptions and
/// abort retain existing limits. Qualification and independent retest are pending.
/// ```compile_fail
/// fn bound<T: Send>() {} bound::<brynja_hash_parallel_std::strict_execution::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {} bound::<brynja_hash_parallel_std::strict_execution::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {} bound::<brynja_hash_parallel_std::strict_execution::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {} bound::<brynja_hash_parallel_std::strict_execution::CompiledSession>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {} bound::<brynja_hash_parallel_std::strict_execution::CompiledSession>();
/// ```
/// ```no_run
/// use brynja_hash_parallel_std::strict_execution::*;
/// fn example(input: &[u8], root: Kernel, leaves: LeafRoute, limits: Limits)
///     -> Result<(), Error>
/// {
///     // Deployment must preserve both compiled root and leaf feature bundles.
///     let mut session = CompiledSession::new(Algorithm::ParallelHash128(256), root, leaves, limits)?;
///     let output = session.hash(input, 1024, b"application")?;
///     assert_eq!(output.expose().len(), 32);
///     Ok(())
/// }
/// ```
pub struct CompiledSession {
    inner: Session,
    root: Kernel,
    leaves: LeafRoute,
    quarantined: bool,
    #[cfg(test)]
    fault: tests::Fault,
}
impl CompiledSession {
    /// Preacquires all resources and tests root/leaf authority on protected stacks.
    pub fn new(
        algorithm: Algorithm,
        root: Kernel,
        leaves: LeafRoute,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut inner = Session::new(algorithm, limits)?;
        // Groups own four full 64-byte slots even for 128-strength CVs; inactive
        // capacity remains protected and is cleared. No typed reinterpretation.
        if matches!(leaves, LeafRoute::Batch(_)) {
            let bytes = limits
                .max_leaves
                .div_ceil(4)
                .checked_mul(256)
                .ok_or(Error::WorkLimit)?;
            inner.cvs = brynja_crypto_cpu_std::protected_memory::ProtectedBytes::new(
                bytes,
                limits.max_buffer_mapping_bytes,
            )?;
        }
        let mut result = Err(Error::Invariant);
        inner.root.run(|| result = worker::probe(root, leaves))?;
        result?;
        Ok(Self {
            inner,
            root,
            leaves,
            quarantined: false,
            #[cfg(test)]
            fault: tests::Fault::None,
        })
    }
    /// Configured root and leaf policies, not actual-work or qualification claims.
    pub const fn routes(&self) -> (Kernel, LeafRoute) {
        (self.root, self.leaves)
    }
    /// Public exact identity/output width.
    pub const fn algorithm(&self) -> Algorithm {
        self.inner.algorithm
    }
    /// Irreversible wrapper-local health.
    pub const fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    /// Clears forgotten results and prevents further execution.
    pub fn quarantine(&mut self) {
        self.quarantined = true;
        self.inner.cvs.clear();
        self.inner.staging.clear();
        self.inner.output.clear();
    }
    /// Complete byte-aligned request.
    pub fn hash(
        &mut self,
        input: &[u8],
        block: usize,
        customization: &[u8],
    ) -> Result<Output<'_>, Error> {
        self.compute(
            Bits::bytes(input),
            block,
            Bits::bytes(customization),
            &CancellationToken::new(),
        )
    }
    /// Canonical LSB-first input/customization; checks cancellation between bounded
    /// leaves/groups, waves, root merges and XOF chunks. One leaf's work is bounded
    /// by max_block_bytes. No caller callback executes on protected workers.
    pub fn compute(
        &mut self,
        input: Bits<'_>,
        block: usize,
        customization: Bits<'_>,
        cancel: &CancellationToken,
    ) -> Result<Output<'_>, Error> {
        self.inner.cvs.clear();
        self.inner.staging.clear();
        self.inner.output.clear();
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        if block == 0
            || block > self.inner.limits.max_block_bytes
            || customization.bytes.len() > self.inner.limits.max_customization_bytes
            || input.bytes.len().div_ceil(block) > self.inner.limits.max_leaves
        {
            return Err(Error::WorkLimit);
        }
        check(cancel)?;
        let mut buffers = Buffers {
            cvs: &mut self.inner.cvs,
            staging: &mut self.inner.staging,
            output: &mut self.inner.output,
            keep: false,
        };
        self.quarantined = true;
        let result = worker::run(
            worker::Request {
                algorithm: self.inner.algorithm,
                input,
                block,
                customization,
                cancel,
                root_kernel: self.root,
                leaf_route: self.leaves,
                #[cfg(test)]
                fault: self.fault,
            },
            super::worker::Resources {
                root: &mut self.inner.root,
                workers: &mut self.inner.workers,
                cvs: buffers.cvs.as_bytes_mut(),
                staging: buffers.staging.as_bytes_mut(),
                destination: buffers
                    .output
                    .as_bytes_mut()
                    .get_mut(..self.inner.algorithm.output_bytes())
                    .ok_or(Error::Invariant)?,
            },
        );
        if matches!(result, Ok(()) | Err(Error::Cancelled | Error::InvalidBits)) {
            self.quarantined = false;
        }
        result?;
        check(cancel)?;
        buffers.keep = true;
        drop(buffers);
        Ok(Output {
            output: &mut self.inner.output,
            algorithm: self.inner.algorithm,
        })
    }
}
