//! Bounded hardened SHA-3/SHAKE/cSHAKE independent-message batching.
//!
//! Default-off, allocation-free, distinct from ordinary non-erasing batches.
//! Input/output lengths, algorithms, N/S lengths, activity and work are PUBLIC;
//! callers needing length privacy must pad externally. Caller input copies,
//! registers/compiler copies and platform storage are not erased. Drop requires
//! normal return or recoverable unwind, not abort, termination or forgotten owners.
//! No independent cryptographic verification or FIPS validation is implied.
//!
//! ```
//! use brynja_hash_sha3::{Fips202BitString, hardened_batch::{
//!     Algorithm, Control, Error, Executor, Input, Workspace,
//! }};
//! # fn main() -> Result<(), Error> {
//! let message = Fips202BitString::new(b"abc", 8).map_err(|_| Error::InvalidInput)?;
//! let input = Input::new(Algorithm::Sha3_256, message, 256)?;
//! let mut bytes = [0_u8; 32];
//! let mut staging = [0_u8; 32];
//! let mut workspace = Workspace::new();
//! let mut cancelled = || false;
//! let mut control = Control::new(1, &mut cancelled);
//! let (output, report) = Executor::portable().digest_secret(
//!     &[Some(input), None, None, None], [Some(&mut bytes), None, None, None],
//!     &mut workspace, &mut staging, &mut control)?;
//! assert_eq!(output.algorithm(0), Some(Algorithm::Sha3_256));
//! assert_eq!(output.output_bits(0), Some(256));
//! assert_eq!(report.scalar_permutations, 1);
//! drop(output);
//! assert_eq!(bytes, [0; 32]);
//! assert_eq!(staging, [0; 32]);
//! # Ok(()) }
//! ```
mod control;
mod engine;
mod framing;
mod input;
mod output;
mod workspace;
pub use crate::Sha3PublicDeclassification;
pub use brynja_crypto_cpu::keccak_hardened_batch::{
    Authority, Error as BackendError, Kernel, Session,
};
pub use control::Control;
use core::cell::Cell;
pub use input::{Algorithm, Input};
pub use output::SecretBatchOutput;
pub use workspace::Workspace;
/// Maximum number of active or inactive input/output slots.
pub const CAPACITY: usize = 4;
/// Explicit route policy. Prefer uses only caller-selected workload thresholds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Portable only, without probing or vector authority.
    Portable,
    /// Use eligible full vector groups; scalar otherwise.
    Prefer,
    /// Require at least one eligible full vector group; scalar tails allowed.
    Require,
}

/// Public failure classification. Public destinations are unchanged on error;
/// every supplied secret destination is cleared instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Executor was permanently revoked.
    Quarantined,
    /// Terminal backend failure; never authorizes fallback.
    Backend(BackendError),
    /// Invalid identity, customization, output width, or batch shape.
    InvalidInput,
    /// Invalid mode/threshold combination.
    InvalidSelection,
    /// Destination width is not exactly the corresponding request width.
    InvalidDestination,
    /// Staging is shorter than the sum of requested output byte lengths.
    InsufficientScratch,
    /// Required vector group cannot be formed under the selected threshold.
    IneligibleWorkload,
    /// Encoded length or framing exceeds the target's addressable domain.
    MessageTooLong,
    /// Caller-provided finite permutation budget is exhausted.
    WorkLimit,
    /// Caller requested cancellation.
    Cancelled,
    /// Internal invariant failed; any supplied authority is quarantined.
    Invariant,
}

/// Public counters count real calls; scalar tails are not described as SIMD.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Actual vector identity, or None if no vector call executed.
    pub kernel: Option<Kernel>,
    /// Actual vector dispatches, excluding the authority startup KAT.
    pub vector_calls: u64,
    /// Bit i is set only if input slot i actually participated in a vector call.
    /// This does not claim that every permutation of that slot was accelerated.
    pub accelerated_slots: u8,
    /// Independent states permuted by vector dispatches.
    pub vector_permutations: u64,
    /// Independent states permuted by portable code.
    pub scalar_permutations: u64,
}

/// Reusable, thread-bound policy owner. Routine rejection preserves reuse;
/// backend/invariant failure and recoverable unwind revoke it permanently.
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Executor;
/// fn require<T: Send>() {}
/// require::<Executor<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Executor;
/// fn require<T: Sync>() {}
/// require::<Executor<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Executor;
/// fn require<T: Copy>() {}
/// require::<Executor<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Executor;
/// fn require<T: Clone>() {}
/// require::<Executor<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::Executor;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Executor<'_>>();
/// ```
pub struct Executor<'a> {
    session: Option<Session<'a>>,
    mode: Mode,
    minimum_permutations: usize,
    revoked: Cell<bool>,
}
impl<'a> Executor<'a> {
    /// Pure hardened portable execution, without CPU probing or startup KAT.
    pub const fn portable() -> Self {
        Self {
            session: None,
            mode: Mode::Portable,
            minimum_permutations: 1,
            revoked: Cell::new(false),
        }
    }
    /// Borrows distinct hardened instruction authority with a nonzero explicit
    /// crossover threshold. Portable mode is rejected rather than discarding it.
    pub fn with_session(
        session: Session<'a>,
        mode: Mode,
        minimum_permutations: usize,
    ) -> Result<Self, Error> {
        if mode == Mode::Portable || minimum_permutations == 0 {
            return Err(Error::InvalidSelection);
        }
        session.ensure_healthy().map_err(Error::Backend)?;
        Ok(Self {
            session: Some(session),
            mode,
            minimum_permutations,
            revoked: Cell::new(false),
        })
    }
    /// Healthy selected kernel, not a claim that a workload used acceleration.
    /// Fails on revocation; never authorizes portable fallback from failure.
    pub fn kernel(&self) -> Result<Option<Kernel>, Error> {
        self.check()?;
        Ok(self.session.as_ref().map(|session| session.kernel()))
    }
    /// Permanently revokes the executor and any supplied authority.
    pub fn quarantine(&self) {
        self.revoked.set(true);
        if let Some(session) = &self.session {
            session.quarantine();
        }
    }
    fn check(&self) -> Result<(), Error> {
        if self.revoked.get() {
            return Err(Error::Quarantined);
        }
        if let Some(session) = &self.session {
            session.ensure_healthy().map_err(Error::Backend)?;
        }
        Ok(())
    }
    /// Hashes into exclusively borrowed, clearing secret output slots.
    /// On ANY error or recoverable unwind every supplied destination is cleared,
    /// including wrongly sized or inactive slots. Success retains their borrows
    /// in a non-cloneable output owner until explicit declassification or Drop.
    pub fn digest_secret<'out>(
        &self,
        inputs: &[Option<Input<'_>>; CAPACITY],
        destinations: [Option<&'out mut [u8]>; CAPACITY],
        workspace: &mut Workspace,
        staging: &mut [u8],
        control: &mut Control<'_>,
    ) -> Result<(SecretBatchOutput<'out>, Report), Error> {
        let mut output = SecretBatchOutput::new(destinations);
        let report = self.execute(
            inputs,
            &mut output.destinations,
            workspace,
            staging,
            control,
        )?;
        for ((identity, bits), input) in output
            .identities
            .iter_mut()
            .zip(&mut output.bits)
            .zip(inputs)
        {
            if let Some(input) = input {
                *identity = input.algorithm.code();
                framing::store(bits, input.output_bits())?;
            }
        }
        Ok((output, report))
    }
    /// Explicitly declassifies the resulting digests. All public destinations
    /// remain unchanged on error/unwind. Workspace staging clears on every exit.
    pub fn digest_public(
        &self,
        inputs: &[Option<Input<'_>>; CAPACITY],
        mut destinations: [Option<&mut [u8]>; CAPACITY],
        workspace: &mut Workspace,
        staging: &mut [u8],
        control: &mut Control<'_>,
        _authority: Sha3PublicDeclassification,
    ) -> Result<Report, Error> {
        self.execute(inputs, &mut destinations, workspace, staging, control)
    }
    fn execute(
        &self,
        inputs: &[Option<Input<'_>>; CAPACITY],
        destinations: &mut [Option<&mut [u8]>; CAPACITY],
        workspace: &mut Workspace,
        staging: &mut [u8],
        control: &mut Control<'_>,
    ) -> Result<Report, Error> {
        let mut guard = Operation {
            executor: self,
            workspace,
            staging,
            complete: false,
        };
        let result = (|| {
            self.check()?;
            output::validate(inputs, destinations)?;
            let report = engine::run(self, inputs, guard.workspace, guard.staging, control)?;
            engine::validate_commit(inputs, destinations, guard.staging)?;
            Ok(report)
        })();
        guard.complete = matches!(
            result,
            Ok(_)
                | Err(Error::InvalidDestination
                    | Error::InvalidInput
                    | Error::InsufficientScratch
                    | Error::IneligibleWorkload
                    | Error::MessageTooLong
                    | Error::WorkLimit
                    | Error::Cancelled)
        );
        let report = result?;
        // Unexpected transfer invariants still quarantine; ordinary request
        // rejection above remains reusable. Commit has no caller callbacks.
        guard.complete = false;
        output::commit(guard.staging, destinations)?;
        guard.complete = true;
        Ok(report)
    }
}
struct Operation<'a, 's> {
    executor: &'a Executor<'s>,
    workspace: &'a mut Workspace,
    staging: &'a mut [u8],
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        self.workspace.wipe();
        let _ = brynja_core::clear_owned_region(self.staging);
        if !self.complete {
            self.executor.quarantine();
        }
    }
}
#[cfg(test)]
mod tests;
