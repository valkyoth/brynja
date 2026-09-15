//! Bounded independent-message SHA-3/SHAKE/cSHAKE batches, public data only.
//!
//! All eight identities use the same Keccak-f[1600] permutation, so lanes may
//! differ in rate, suffix, input length, customization and finite output length.
//! Each lane retains its own framing and output position. Only simultaneously
//! ready lanes are grouped; incomplete groups use portable scalar tails.
//! This is neither ParallelHash tree hashing nor a thread scheduler.
//!
//! Default-off; existing hash APIs are unchanged. No input, state, staging or
//! output is erased. PublicData is an assertion, not provenance verification.
//! Never supply keys, passwords or secret-derived data. Shape/work is public.
//!
//! ```
//! use brynja_hash_sha3::{Fips202BitString, batch::{Algorithm, Control, Executor,
//!     Input, PublicData, Workspace}};
//! let message = Fips202BitString::new(b"abc", 8).map_err(|_| "bits")?;
//! let input = Input::new(Algorithm::Sha3_256, message, 256).map_err(|_| "input")?;
//! let mut output = [0; 32];
//! let mut staging = [0; 32];
//! let mut workspace = Workspace::new();
//! let mut cancelled = || false;
//! let mut control = Control::new(1, &mut cancelled);
//! let report = Executor::portable().digest(PublicData::new(&[input]),
//!     &mut [&mut output], &mut workspace, &mut staging, &mut control)
//!     .map_err(|_| "batch")?;
//! assert_eq!(report.scalar_permutations, 1);
//! assert_eq!(output.as_slice(), brynja_hash_sha3::sha3_256(b"abc")
//!     .map_err(|_| "reference")?.as_bytes());
//! # Ok::<(), &'static str>(())
//! ```

use crate::Fips202BitString;
pub use brynja_crypto_cpu::keccak_batch::{
    Authority, Error as BackendError, Kernel, PublicData, Session,
};
mod control;
mod engine;
mod framing;
#[cfg(test)]
mod tests;
pub use control::Control;

/// Maximum independent messages per call. Larger workloads use repeated calls.
pub const CAPACITY: usize = 4;

/// Exact domain identity. cSHAKE with empty N and S is SHAKE-equivalent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// SHA3-224, 224 output bits.
    Sha3_224,
    /// SHA3-256, 256 output bits.
    Sha3_256,
    /// SHA3-384, 384 output bits.
    Sha3_384,
    /// SHA3-512, 512 output bits.
    Sha3_512,
    /// SHAKE128 with finite caller-selected output.
    Shake128,
    /// SHAKE256 with finite caller-selected output.
    Shake256,
    /// SP 800-185 cSHAKE128 with arbitrary-bit N/S.
    Cshake128,
    /// SP 800-185 cSHAKE256 with arbitrary-bit N/S.
    Cshake256,
}
impl Algorithm {
    /// Sponge rate in bytes, not the number of parallel message lanes.
    pub const fn rate(self) -> usize {
        match self {
            Self::Sha3_224 => 144,
            Self::Sha3_256 | Self::Shake256 | Self::Cshake256 => 136,
            Self::Sha3_384 => 104,
            Self::Sha3_512 => 72,
            Self::Shake128 | Self::Cshake128 => 168,
        }
    }
    /// Required output bits for fixed SHA-3, or None for finite XOF output.
    pub const fn fixed_output_bits(self) -> Option<usize> {
        match self {
            Self::Sha3_224 => Some(224),
            Self::Sha3_256 => Some(256),
            Self::Sha3_384 => Some(384),
            Self::Sha3_512 => Some(512),
            _ => None,
        }
    }
    fn customized(self) -> bool {
        matches!(self, Self::Cshake128 | Self::Cshake256)
    }
}

/// Borrowed canonical input and explicit finite output request.
#[derive(Clone, Copy)]
pub struct Input<'a> {
    algorithm: Algorithm,
    message: Fips202BitString<'a>,
    name: Fips202BitString<'a>,
    customization: Fips202BitString<'a>,
    output_bits: usize,
}
impl<'a> Input<'a> {
    /// Creates SHA-3/SHAKE or empty-domain cSHAKE. Fixed identities require their
    /// exact digest width. Zero-bit output is valid for XOF identities only.
    pub fn new(
        algorithm: Algorithm,
        message: Fips202BitString<'a>,
        output_bits: usize,
    ) -> Result<Self, Error> {
        let empty = Fips202BitString::new(&[], 0).map_err(|_| Error::Invariant)?;
        Self::with_customization(algorithm, message, empty, empty, output_bits)
    }
    /// Creates cSHAKE with arbitrary-bit N/S. Nonempty N/S on SHA-3 or SHAKE is
    /// rejected, never ignored or silently converted to a different identity.
    pub fn with_customization(
        algorithm: Algorithm,
        message: Fips202BitString<'a>,
        name: Fips202BitString<'a>,
        customization: Fips202BitString<'a>,
        output_bits: usize,
    ) -> Result<Self, Error> {
        if algorithm
            .fixed_output_bits()
            .is_some_and(|n| n != output_bits)
            || (!algorithm.customized() && (name.bit_len() != 0 || customization.bit_len() != 0))
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            algorithm,
            message,
            name,
            customization,
            output_bits,
        })
    }
    /// Exact requested identity; output order matches input order.
    pub const fn algorithm(self) -> Algorithm {
        self.algorithm
    }
    /// Finite output bit count. Unused high bits of the last byte are cleared.
    pub const fn output_bits(self) -> usize {
        self.output_bits
    }
    /// Exact required destination width, with no rounded bit-length overflow.
    pub const fn output_bytes(self) -> usize {
        self.output_bits.div_ceil(8)
    }
}

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

/// Public failure; output destinations are unchanged for every returned error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Terminal backend failure; never authorizes fallback.
    Backend(brynja_crypto_cpu::keccak_batch::Error),
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
    /// Independent states permuted by vector dispatches.
    pub vector_permutations: u64,
    /// Independent states permuted by portable code.
    pub scalar_permutations: u64,
}

/// Caller-owned fixed-size state workspace. Public only; not cleared on Drop.
pub struct Workspace {
    states: [[u64; 25]; CAPACITY],
    vector: [[u64; 25]; CAPACITY],
}
impl Workspace {
    /// Empty reusable workspace. Every call initializes all lane states.
    pub const fn new() -> Self {
        Self {
            states: [[0; 25]; CAPACITY],
            vector: [[0; 25]; CAPACITY],
        }
    }
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowed ordinary batch executor. Backend errors and unwind quarantine;
/// ordinary invalid requests, work limits and cancellation leave it reusable.
pub struct Executor<'a> {
    session: Option<Session<'a>>,
    mode: Mode,
    minimum_permutations: usize,
}
impl<'a> Executor<'a> {
    /// Portable, no detector and no authority needed.
    pub const fn portable() -> Self {
        Self {
            session: None,
            mode: Mode::Portable,
            minimum_permutations: 1,
        }
    }
    /// Supplies an explicit session and measured per-lane minimum work threshold.
    /// The Cargo feature alone does not enable x86 AVX2: a matching build-wide
    /// target-feature bundle or an explicit external platform proof is required.
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
        })
    }
    /// Computes up to four independent messages. `outputs` must have one exact
    /// destination per input. `staging` needs the sum of all output byte lengths;
    /// it and workspace are scratch and may change on error. Destinations commit
    /// only after every lane and the last cancellation/health check succeed.
    /// Work charges cover prefix, padding and squeeze permutations; no refund.
    /// Panic quarantine requires unwinding; `panic = "abort"` does not run Drop.
    pub fn digest(
        &self,
        inputs: PublicData<&[Input<'_>]>,
        outputs: &mut [&mut [u8]],
        workspace: &mut Workspace,
        staging: &mut [u8],
        control: &mut Control<'_>,
    ) -> Result<Report, Error> {
        let mut guard = Operation {
            executor: self,
            complete: false,
        };
        let result = engine::run(
            self,
            inputs.into_inner(),
            outputs,
            workspace,
            staging,
            control,
        );
        guard.complete = matches!(
            result,
            Ok(_)
                | Err(Error::InvalidInput
                    | Error::InvalidDestination
                    | Error::InsufficientScratch
                    | Error::IneligibleWorkload
                    | Error::MessageTooLong
                    | Error::WorkLimit
                    | Error::Cancelled)
        );
        result
    }
    fn check(&self) -> Result<(), Error> {
        if let Some(session) = &self.session {
            session.ensure_healthy().map_err(Error::Backend)?;
        }
        Ok(())
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
