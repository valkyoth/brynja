//! Opt-in, bounded ParallelHash scheduling over hardened cSHAKE states.
//!
//! Root and leaf routes are selected independently, before secret processing.
//! A supplied session never falls back. Plan-bound completed leaf values may
//! cross a worker boundary; CPU authorities and unfinished states may not.
//! Caller-owned inputs remain the caller's clearing responsibility. Explicit
//! owners clear their storage, not registers, compiler copies or platform state.
//!
//! ```
//! use brynja_hash_parallel::{parallel_hash128, ParallelHashPublicDeclassification};
//! use brynja_hash_parallel::execution::{Collector, Error, Identity, Mode, Plan};
//! let plan = Plan::new(Identity::ParallelHash128, b"message", 8, 64)?;
//! let mut root = Collector::new(&plan, Mode::Portable, b"application")?;
//! root.execute_serial(|_| Ok(Mode::Portable))?;
//! let mut digest = [0; 32];
//! let mut scratch = [0; 32];
//! root.finalize_public(&mut digest, &mut scratch,
//!     ParallelHashPublicDeclassification::acknowledge())?;
//! let mut reference = [0; 32];
//! parallel_hash128(b"message", &mut [0; 8], b"application", &mut reference)?;
//! assert_eq!(digest, reference);
//! assert_eq!(scratch, [0; 32]);
//! # Ok::<(), Error>(())
//! ```

mod backend;
mod binding;
mod collector;
mod encoding;
mod ownership;
mod plan;
mod stream;
mod stream_output;

pub use brynja_hash_sha3::hardened_execution::{KeccakSession, Report};
pub use collector::{Collector, Reader};
pub use plan::{Job, Leaf, Plan};
pub use stream::{Stream, StreamConfig};
pub use stream_output::StreamReader;

/// Exact SP 800-185 identity; fixed and XOF outputs are not interchangeable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Identity {
    /// ParallelHash128 with right_encode(L).
    ParallelHash128,
    /// ParallelHash256 with right_encode(L).
    ParallelHash256,
    /// ParallelHashXOF128 with right_encode(0).
    ParallelHashXof128,
    /// ParallelHashXOF256 with right_encode(0).
    ParallelHashXof256,
}
impl Identity {
    /// The complete inner chaining-value width in bytes.
    #[must_use]
    pub const fn leaf_bytes(self) -> usize {
        if self.wide() { 64 } else { 32 }
    }
    pub(super) const fn wide(self) -> bool {
        matches!(self, Self::ParallelHash256 | Self::ParallelHashXof256)
    }
    pub(super) const fn xof(self) -> bool {
        matches!(self, Self::ParallelHashXof128 | Self::ParallelHashXof256)
    }
}

/// Selection before processing; authority absence is not backend failure.
pub enum Mode<'a> {
    /// Explicit portable hardened execution.
    Portable,
    /// Portable only when no session is supplied.
    Prefer(Option<KeccakSession<'a>>),
    /// Reject an absent or unhealthy session.
    Require(Option<KeccakSession<'a>>),
}

/// Admitted worker routes; root selection remains independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerPolicy {
    /// Explicitly permit portable and accelerated completed leaves.
    Mixed,
    /// Reject accelerated leaves; useful for reproducible portable campaigns.
    Portable,
    /// Every nonempty leaf job must execute an authorized accelerated route.
    RequireAcceleration,
}
impl WorkerPolicy {
    pub(super) fn accepts(self, route: Option<Report>) -> bool {
        match self {
            Self::Mixed => true,
            Self::Portable => route.is_none(),
            Self::RequireAcceleration => route.is_some(),
        }
    }
}

/// Closed construction/selection failure. No secret payload is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Portable construction or canonical framing failure.
    Construction(crate::ParallelHashError),
    /// Exact accelerated failure; never grants portable fallback.
    Execution(brynja_hash_sha3::hardened_execution::Error),
    /// Required worker/root acceleration was not supplied.
    AccelerationUnavailable,
    /// The caller's admitted leaf-work budget was exceeded or zero.
    WorkLimit,
    /// Output length, bit width or staging capacity was invalid.
    OutputLength,
    /// Wrong identity, leaf provenance, index or terminal phase.
    State,
}
impl From<crate::ParallelHashError> for Error {
    fn from(error: crate::ParallelHashError) -> Self {
        Self::Construction(error)
    }
}
impl From<brynja_hash_sha3::HardenedSha3Error> for Error {
    fn from(error: brynja_hash_sha3::HardenedSha3Error) -> Self {
        Self::Construction(error.into())
    }
}
impl From<brynja_hash_sha3::hardened_execution::Error> for Error {
    fn from(error: brynja_hash_sha3::hardened_execution::Error) -> Self {
        Self::Execution(error)
    }
}

mod sealed {
    pub trait Owner {}
}
/// Sealed private-state clearing capability, not deployment certification.
pub trait HardenedState: sealed::Owner {}
impl sealed::Owner for Collector<'_, '_, '_> {}
impl HardenedState for Collector<'_, '_, '_> {}
impl sealed::Owner for Reader<'_, '_, '_, '_> {}
impl HardenedState for Reader<'_, '_, '_, '_> {}
impl sealed::Owner for Stream<'_, '_> {}
impl HardenedState for Stream<'_, '_> {}
impl sealed::Owner for StreamReader<'_, '_, '_> {}
impl HardenedState for StreamReader<'_, '_, '_> {}

pub(super) fn bits(input: &[u8]) -> Result<crate::Fips202BitString<'_>, Error> {
    crate::Fips202BitString::new(input, if input.is_empty() { 0 } else { 8 })
        .map_err(|_| crate::ParallelHashError::InvalidBitString.into())
}

pub(super) struct Clear<'a>(pub(super) &'a mut [u8]);
impl Drop for Clear<'_> {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(self.0);
    }
}
