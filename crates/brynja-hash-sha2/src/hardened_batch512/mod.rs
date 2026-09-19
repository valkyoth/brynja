//! Default-off, allocation-free hardened SHA-512-family batch hashing.
//!
//! Distinct owners and kernels; ordinary batch types cannot substitute. Input
//! lengths, slot activity, algorithms, scheduling and work reports are PUBLIC.
//! Callers needing length privacy must pad externally. Caller input copies,
//! registers, compiler copies, caches and platform storage are not erased here.
//! Drop cleanup requires return or recoverable unwind, not abort/termination or
//! `mem::forget`. These APIs do not imply independent review or FIPS validation.
//!
//! With `hardened-batch512-execution` enabled, portable execution needs no CPU
//! feature flags or authority. Supplied SIMD authority uses AVX2 four-lane or
//! NEON two-lane groups; scalar tails and padding remain clearing operations.
//!
//! ```
//! use brynja_hash_sha2::{BitString, hardened_batch512::{
//!     Algorithm, Control, Error, Executor, Input, Workspace,
//! }};
//! # fn main() -> Result<(), Error> {
//! let bits = BitString::new(b"abc", 8).map_err(|_| Error::Invariant)?;
//! let inputs = [Some(Input::new(Algorithm::Sha512, bits)),
//!     None, None, None];
//! let mut bytes = [0_u8; 64];
//! let mut workspace = Workspace::new();
//! let mut cancelled = || false;
//! let mut control = Control::new(1, &mut cancelled);
//! let (output, report) = Executor::portable().digest_secret(&inputs,
//!     [Some(&mut bytes), None, None, None],
//!     &mut workspace, &mut control)?;
//! assert_eq!(output.algorithm(0), Some(Algorithm::Sha512));
//! assert_eq!(report.scalar_blocks, 1);
//! drop(output); // releases the borrow and clears the secret digest
//! assert_eq!(bytes, [0; 64]);
//! # Ok(()) }
//! ```

mod control;
mod engine;
mod output;
mod workspace;
use crate::BitString;
pub use crate::PublicDeclassification;
pub use brynja_crypto_cpu::sha512_hardened_batch::{
    Authority, Error as BackendError, Kernel, Session,
};
pub use control::Control;
use core::cell::Cell;
pub use output::SecretBatchOutput;
pub use workspace::Workspace;

/// Fixed maximum number of independent input/output slots.
pub const CAPACITY: usize = 4;
mod algorithm;
pub use algorithm::Algorithm;
/// Canonical borrowed input. Copies of input bytes remain caller-owned.
pub struct Input<'a> {
    algorithm: Algorithm,
    bits: BitString<'a>,
}
impl<'a> Input<'a> {
    /// Binds exact algorithm identity to already validated canonical bits.
    pub const fn new(algorithm: Algorithm, bits: BitString<'a>) -> Self {
        Self { algorithm, bits }
    }
}
/// Explicit selection. A supplied backend failure never authorizes fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Always hardened portable compression; never probes or acquires authority.
    Portable,
    /// Eligible full groups use the supplied session; other work is portable.
    Prefer,
    /// Require at least one eligible full-width SIMD group before any hash work.
    /// Unequal tails and padding still use hardened portable compression.
    Require,
}
/// Value-free failure; secret destinations clear, public ones remain unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Supplied backend failed its health or operation contract.
    Backend(BackendError),
    /// Executor was permanently revoked.
    Quarantined,
    /// Active slots or exact destination widths do not match.
    OutputShape,
    /// Zero threshold or unused Portable session selection.
    InvalidSelection,
    /// No eligible full-width group for required execution.
    IneligibleWorkload,
    /// Input exceeds the FIPS 180-4 message-length domain.
    MessageTooLong,
    /// Insufficient cumulative compression budget, including padding.
    WorkLimit,
    /// Caller cancelled; previously charged work is not refunded.
    Cancelled,
    /// Internal shape/accounting invariant failed; executor is quarantined.
    Invariant,
}
/// Public performed-work accounting, never an authority or secret digest.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Kernel only when a SIMD group actually executed.
    pub kernel: Option<Kernel>,
    /// Actual calls to the supplied vector session.
    pub vector_calls: u64,
    /// Useful per-message blocks compressed by SIMD.
    pub vector_blocks: u64,
    /// Portable blocks, including tails, padding and general-t IV derivation.
    pub scalar_blocks: u64,
}
/// Reusable, thread-bound policy owner. Routine rejection preserves reuse;
/// backend/invariant failure and recoverable unwind revoke it permanently.
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch512::Executor;
/// fn require<T: Send>() {}
/// require::<Executor<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch512::Executor;
/// fn require<T: Sync>() {}
/// require::<Executor<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch512::Executor;
/// fn require<T: Copy>() {}
/// require::<Executor<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch512::Executor;
/// fn require<T: Clone>() {}
/// require::<Executor<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha2::hardened_batch512::Executor;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Executor<'_>>();
/// ```
pub struct Executor<'a> {
    session: Option<Session<'a>>,
    mode: Mode,
    minimum_common_blocks: usize,
    revoked: Cell<bool>,
}
impl<'a> Executor<'a> {
    /// Pure hardened portable execution, without CPU probing or startup KAT.
    pub const fn portable() -> Self {
        Self {
            session: None,
            mode: Mode::Portable,
            minimum_common_blocks: 1,
            revoked: Cell::new(false),
        }
    }
    /// Borrows distinct hardened instruction authority with a nonzero explicit
    /// crossover threshold. Portable mode is rejected rather than discarding it.
    pub fn with_session(
        session: Session<'a>,
        mode: Mode,
        minimum_common_blocks: usize,
    ) -> Result<Self, Error> {
        if mode == Mode::Portable || minimum_common_blocks == 0 {
            return Err(Error::InvalidSelection);
        }
        session.ensure_healthy().map_err(Error::Backend)?;
        Ok(Self {
            session: Some(session),
            mode,
            minimum_common_blocks,
            revoked: Cell::new(false),
        })
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
        control: &mut Control<'_>,
    ) -> Result<(SecretBatchOutput<'out>, Report), Error> {
        let mut output = SecretBatchOutput::new(destinations);
        let report = self.execute(inputs, &mut output.destinations, workspace, control)?;
        for (identity, input) in output.identities.iter_mut().zip(inputs) {
            *identity = input
                .as_ref()
                .map_or(0, |input| input.algorithm.code())
                .to_le_bytes();
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
        control: &mut Control<'_>,
        _authority: PublicDeclassification,
    ) -> Result<Report, Error> {
        self.execute(inputs, &mut destinations, workspace, control)
    }
    fn execute(
        &self,
        inputs: &[Option<Input<'_>>; CAPACITY],
        destinations: &mut [Option<&mut [u8]>; CAPACITY],
        workspace: &mut Workspace,
        control: &mut Control<'_>,
    ) -> Result<Report, Error> {
        let mut guard = Operation {
            executor: self,
            workspace,
            complete: false,
        };
        let result = (|| {
            self.check()?;
            output::validate(inputs, destinations)?;
            engine::run(self, inputs, guard.workspace, control)
        })();
        guard.complete = matches!(
            result,
            Ok(_)
                | Err(Error::OutputShape
                    | Error::IneligibleWorkload
                    | Error::MessageTooLong
                    | Error::WorkLimit
                    | Error::Cancelled)
        );
        let report = result?;
        // All widths/slots, health, callbacks and accounting completed above.
        // Commit preflights equal-length borrowed transfers without callbacks.
        // An unexpected internal commit error still revokes the executor.
        guard.complete = false;
        output::commit(&guard.workspace.output, destinations)?;
        guard.complete = true;
        Ok(report)
    }
}
struct Operation<'a, 's> {
    executor: &'a Executor<'s>,
    workspace: &'a mut Workspace,
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        self.workspace.wipe();
        if !self.complete {
            self.executor.quarantine();
        }
    }
}
#[cfg(test)]
mod tests;
