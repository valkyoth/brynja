//! Bounded, ordinary independent-message SHA-224/256 batching.
//!
//! Default-off `batch-execution` is public-data-only and does not zeroize.
//! Eight caller-owned slots may mix identities, unequal lengths and canonical
//! bit tails. Output slots retain input order; inactive slots become `None`.
//! All failures preserve the entire caller destination. No allocation, global
//! dispatch or secret-bearing integration. Dedicated SHA instructions are a
//! separate single-stream API, not used by this vector profile.

use crate::{BitString, Sha224Digest, Sha256Digest};
pub use brynja_crypto_cpu::sha256_batch::{
    Authority, Error as BackendError, Kernel, PublicData, Session,
};

mod control;
mod engine;
pub use control::Control;

/// Maximum independent messages in one bounded call.
pub const CAPACITY: usize = 8;

/// Exact per-slot algorithm identity; SHA-224 has a distinct IV, not just truncation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// SHA-224, 224 output bits.
    Sha224,
    /// SHA-256, 256 output bits.
    Sha256,
}

/// One canonical ordinary/public input. Length and identity are public metadata.
#[derive(Clone, Copy)]
pub struct Input<'a> {
    pub(super) algorithm: Algorithm,
    pub(super) bits: BitString<'a>,
}
impl<'a> Input<'a> {
    /// Retains an already validated canonical bit string with its identity.
    pub const fn new(algorithm: Algorithm, bits: BitString<'a>) -> Self {
        Self { algorithm, bits }
    }
}

/// Typed ordinary digest. Not a MAC, secret output or constant-time equality API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Digest {
    /// Exact SHA-224 output.
    Sha224(Sha224Digest),
    /// Exact SHA-256 output.
    Sha256(Sha256Digest),
}

/// Workload selection; execution failures never permit fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Always use portable compression without a vector authority.
    Portable,
    /// Use supplied vector authority for eligible groups; scalar otherwise.
    Prefer,
    /// Require at least one eligible vector group or reject before work.
    Require,
}

/// Closed request or backend failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Complete bundle, owner health, or kernel operation failed.
    Backend(BackendError),
    /// No full-width group meets the caller's minimum common-block threshold.
    IneligibleWorkload,
    /// No authority supplied for required execution, or zero threshold.
    InvalidSelection,
    /// FIPS message-length domain or representable total work exceeded.
    MessageTooLong,
    /// Caller-supplied block-compression budget exhausted.
    WorkLimit,
    /// Caller cancelled; already charged work is not refunded.
    Cancelled,
    /// Internal fixed-size shape violated; vector owner is revoked.
    Invariant,
}

/// Actual performed work, excluding the authority's one-time startup KAT.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Exact kernel when at least one vector instruction batch ran.
    pub kernel: Option<Kernel>,
    /// Calls into the vector kernel.
    pub vector_calls: u64,
    /// Useful independent-message blocks compressed by SIMD.
    pub vector_blocks: u64,
    /// Scalar complete blocks, unequal suffixes and padding blocks.
    pub scalar_blocks: u64,
}

/// Reusable caller-owned executor. Session ownership is sealed and thread-bound.
/// Routine request errors preserve reuse; backend failures and unwind quarantine
/// the supplied authority. None of this erases ordinary state or scratch.
pub struct Executor<'a> {
    session: Option<Session<'a>>,
    mode: Mode,
    minimum_common_blocks: usize,
}

impl<'a> Executor<'a> {
    /// Pure portable execution; no feature probing or vector KAT.
    pub const fn portable() -> Self {
        Self {
            session: None,
            mode: Mode::Portable,
            minimum_common_blocks: 1,
        }
    }

    /// Uses a supplied live session. `minimum_common_blocks` must be nonzero.
    /// This explicit workload threshold should be measured on the deployment;
    /// vector width alone is not a speedup claim. Mode Portable is rejected here
    /// to avoid acquiring unused instruction authority.
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
        })
    }

    /// Hashes all inputs, committing every output together only after success.
    /// PublicData is a caller assertion, not runtime classification or a means
    /// to declassify keys/passwords/confidential input. A cancelled callback may
    /// run between blocks and before output commit; its unwind revokes authority.
    pub fn digest(
        &self,
        input: PublicData<&[Option<Input<'_>>; CAPACITY]>,
        output: &mut [Option<Digest>; CAPACITY],
        control: &mut Control<'_>,
    ) -> Result<Report, Error> {
        let mut guard = Operation {
            executor: self,
            complete: false,
        };
        let result = engine::run(self, input.into_inner(), control);
        guard.complete = matches!(
            result,
            Ok(_)
                | Err(Error::IneligibleWorkload
                    | Error::MessageTooLong
                    | Error::WorkLimit
                    | Error::Cancelled)
        );
        let (staged, report) = result?;
        *output = staged;
        Ok(report)
    }
}

struct Operation<'a, 'b> {
    executor: &'a Executor<'b>,
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.complete
            && let Some(session) = &self.executor.session
        {
            session.quarantine();
        }
    }
}
