//! Bounded, ordinary independent-message SHA-512-family batching.
//!
//! Default-off `batch512-execution` is public-data-only and does not zeroize.
//! Four caller-owned slots may mix identities, unequal lengths and canonical
//! bit tails. Output slots retain input order; inactive slots become `None`.
//! All failures preserve the entire caller destination. No allocation, global
//! dispatch or secret-bearing integration. Dedicated SHA instructions are a
//! separate single-stream API, not used by this vector profile.
//! PublicData is only a caller assertion; secret provenance is not enforced.
//! Hardened multibuffer ownership is a separate API milestone, not this profile.

use crate::{
    BitString, Sha384Digest, Sha512_224Digest, Sha512_256Digest, Sha512Digest, Sha512TBits,
    Sha512TDigest,
};
pub use brynja_crypto_cpu::sha512_batch::{
    Authority, Error as BackendError, Kernel, PublicData, Session,
};

mod control;
mod engine;
pub use control::Control;

/// Maximum independent messages in one bounded call.
pub const CAPACITY: usize = 4;

/// Exact per-slot identity, including the validated general truncation parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// SHA-384 with its distinct IV.
    Sha384,
    /// SHA-512.
    Sha512,
    /// Named SHA-512/224 with the FIPS derived IV.
    Sha512_224,
    /// Named SHA-512/256 with the FIPS derived IV.
    Sha512_256,
    /// General SHA-512/t; invalid parameters cannot enter this variant.
    Sha512T(Sha512TBits),
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
    /// Exact SHA-384 output.
    Sha384(Sha384Digest),
    /// Exact SHA-512 output.
    Sha512(Sha512Digest),
    /// Named SHA-512/224 output, distinct from general t=224.
    Sha512_224(Sha512_224Digest),
    /// Named SHA-512/256 output, distinct from general t=256.
    Sha512_256(Sha512_256Digest),
    /// Parameter-bound canonical general SHA-512/t output.
    Sha512T(Sha512TDigest),
}
impl Digest {
    /// Borrows the exact output width; a partial last byte is MSB-first.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha384(d) => d.as_ref(),
            Self::Sha512(d) => d.as_ref(),
            Self::Sha512_224(d) => d.as_ref(),
            Self::Sha512_256(d) => d.as_ref(),
            Self::Sha512T(d) => d.as_ref(),
        }
    }
    /// Returns the exact identity; equality never conflates named/general output.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Sha384(_) => Algorithm::Sha384,
            Self::Sha512(_) => Algorithm::Sha512,
            Self::Sha512_224(_) => Algorithm::Sha512_224,
            Self::Sha512_256(_) => Algorithm::Sha512_256,
            Self::Sha512T(d) => Algorithm::Sha512T(d.parameter()),
        }
    }
}

/// Workload selection; execution failures never permit fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Always use portable compression without a vector authority.
    Portable,
    /// Use supplied vector authority for eligible groups; scalar otherwise.
    Prefer,
    /// Require at least one eligible vector group or reject without output mutation.
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
    /// FIPS message-length domain exceeded.
    MessageTooLong,
    /// Caller-supplied block-compression budget exhausted.
    WorkLimit,
    /// Caller cancelled; already charged work is not refunded.
    Cancelled,
    /// Internal shape or report accounting violated; vector owner is revoked.
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
    /// Scalar complete blocks, unequal suffixes, padding and general-t IV derivation.
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
    /// With `panic = "abort"`, Drop does not run and a panic terminates execution
    /// instead; no explicit quarantine or cleanup is promised before termination.
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
