//! Explicit ordinary SHA-1 execution for PUBLIC legacy data only.
//!
//! SHA-1 is collision-broken. Acceleration does not authorize signatures, TLS,
//! PKIX, FIPS or keyed use. Hardware temporaries are not cleanup-qualified.
//! Ordinary portable constructors never opt into this API automatically.
//!
//! ```
//! use brynja_legacy_sha1::execution::{Executor, PublicData};
//! let owner = Executor::portable();
//! let mut hash = owner.start(PublicData::acknowledge())?;
//! hash.update(b"abc")?;
//! assert_eq!(Ok(hash.finalize()?), brynja_legacy_sha1::sha1(b"abc"));
//! # Ok::<(), brynja_legacy_sha1::execution::Error>(())
//! ```

pub use crate::cpu::ExecutionAuthority as Authority;
mod ownership;
use crate::{AcceleratedSha1, BitString, Sha1, Sha1Backend, Sha1BackendError, Sha1BackendHealth};
use core::cell::Cell;

/// Explicit classification of all inputs to this ordinary operation as public.
/// Acknowledgement cannot discover whether caller-owned bytes contain secrets.
pub struct PublicData(());
impl PublicData {
    /// Caller accepts responsibility for excluding confidential material.
    pub const fn acknowledge() -> Self {
        Self(())
    }
}

/// Pre-execution policy. A started backend never silently falls back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Never request a CPU instruction authority.
    Portable,
    /// Prefer acceleration; allow only pre-execution unavailability fallback.
    Prefer,
    /// Require an operational accelerated authority or return an error.
    Require,
}

/// Public operation failure without secret payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Exact authority or instruction-session error.
    Backend(Sha1BackendError),
    /// SHA-1's less-than-2^64-bit input domain would be exceeded.
    MessageTooLong,
    /// Owner revoked or stream destroyed after a terminal failure.
    Quarantined,
}
impl From<Sha1BackendError> for Error {
    fn from(error: Sha1BackendError) -> Self {
        match error {
            Sha1BackendError::MessageTooLong => Self::MessageTooLong,
            other => Self::Backend(other),
        }
    }
}

/// Public route observation, not a capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// None means portable processing, never an accelerated claim.
    pub backend: Option<Sha1Backend>,
    /// Owner health; revoked owners cannot resume.
    pub health: Sha1BackendHealth,
}

/// Caller-owned, non-cloneable, thread-bound execution policy and authority.
pub struct Executor {
    authority: Option<Authority>,
    revoked: Cell<bool>,
}
impl Executor {
    /// Does not probe CPU features or create an instruction session.
    pub const fn portable() -> Self {
        Self {
            authority: None,
            revoked: Cell::new(false),
        }
    }

    /// Takes an actual authority, never a report or caller-provided boolean.
    pub fn with_authority(authority: Authority) -> Result<Self, Error> {
        authority.session().ensure_healthy()?;
        Ok(Self {
            authority: Some(authority),
            revoked: Cell::new(false),
        })
    }

    /// Explicit target-specialized selection. Prefer falls back only when the
    /// compile-time bundle is absent, before any startup test or input work.
    pub fn for_compiled_target(mode: Mode) -> Result<Self, Error> {
        if mode == Mode::Portable {
            return Ok(Self::portable());
        }
        match Authority::for_compiled_target() {
            Ok(owner) => Self::with_authority(owner),
            Err(Sha1BackendError::MissingFeatures) if mode == Mode::Prefer => Ok(Self::portable()),
            Err(error) => Err(error.into()),
        }
    }

    /// Permanently invalidates this owner and all borrowed operations.
    pub fn quarantine(&self) {
        self.revoked.set(true);
        if let Some(owner) = &self.authority {
            owner.quarantine();
        }
    }

    fn ready(&self) -> Result<(), Error> {
        if self.revoked.get() {
            return Err(Error::Quarantined);
        }
        if let Some(owner) = &self.authority {
            owner.session().ensure_healthy()?;
        }
        Ok(())
    }

    /// Returns diagnostic metadata, not permission to execute a kernel.
    pub fn report(&self) -> Report {
        Report {
            backend: self.authority.as_ref().map(Authority::backend),
            health: if self.revoked.get() {
                Sha1BackendHealth::Quarantined
            } else {
                self.authority
                    .as_ref()
                    .map_or(Sha1BackendHealth::Healthy, Authority::health)
            },
        }
    }

    /// Borrows this owner for one public-only consuming stream.
    pub fn start(&self, _public: PublicData) -> Result<Stream<'_>, Error> {
        self.ready()?;
        let state = match &self.authority {
            None => State::Portable(Sha1::new()),
            Some(owner) => State::Accelerated(AcceleratedSha1::new(owner.session())?),
        };
        Ok(Stream {
            executor: self,
            state: Some(state),
        })
    }

    /// Complete public byte message. Failure returns no digest.
    pub fn hash(&self, input: &[u8], public: PublicData) -> Result<[u8; 20], Error> {
        let mut state = self.start(public)?;
        state.update(input)?;
        state.finalize()
    }

    /// Complete canonical MSB-first bit message.
    pub fn hash_bits(&self, input: BitString<'_>, public: PublicData) -> Result<[u8; 20], Error> {
        self.start(public)?.finalize_bits(input)
    }
}

enum State<'a> {
    Portable(Sha1),
    Accelerated(AcceleratedSha1<'a>),
}

/// Affine ordinary stream. Finalization/cancellation consumes it; no clone,
/// reset, state import or hardened capability is provided.
pub struct Stream<'a> {
    executor: &'a Executor,
    state: Option<State<'a>>,
}
impl Stream<'_> {
    /// Public input length so far. Revoked or failed streams reject inspection.
    pub fn message_bits(&self) -> Result<u64, Error> {
        self.executor.ready()?;
        match self.state.as_ref().ok_or(Error::Quarantined)? {
            State::Portable(s) => Ok(s.message_bits()),
            State::Accelerated(s) => Ok(s.message_bits()),
        }
    }
    /// Exact public bit-length preflight; rejection does not mutate the stream.
    pub fn check_additional_bits(&self, bits: u64) -> Result<(), Error> {
        self.executor.ready()?;
        match self.state.as_ref().ok_or(Error::Quarantined)? {
            State::Portable(s) => s
                .check_additional_bits(bits)
                .map_err(|_| Error::MessageTooLong),
            State::Accelerated(s) => s.check_additional_bits(bits).map_err(Error::from),
        }
    }
    /// Exact public byte-length preflight.
    pub fn check_additional_bytes(&self, bytes: usize) -> Result<(), Error> {
        self.executor.ready()?;
        let bits = u64::try_from(bytes)
            .ok()
            .and_then(|n| n.checked_mul(8))
            .ok_or(Error::MessageTooLong)?;
        self.check_additional_bits(bits)
    }
    /// Length errors are atomic; authority/backend failures destroy this state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if let Err(error) = self.executor.ready() {
            self.state.take();
            return Err(error);
        }
        let result = match self.state.as_mut().ok_or(Error::Quarantined)? {
            State::Portable(s) => s.update(input).map_err(|_| Error::MessageTooLong),
            State::Accelerated(s) => s.update(input).map_err(Error::from),
        };
        if result.is_err() && result != Err(Error::MessageTooLong) {
            self.state.take();
        }
        result
    }
    /// Consuming public digest release, including on error.
    pub fn finalize(mut self) -> Result<[u8; 20], Error> {
        self.executor.ready()?;
        match self.state.take().ok_or(Error::Quarantined)? {
            State::Portable(s) => Ok(s.finalize()),
            State::Accelerated(s) => s.finalize().map_err(Error::from),
        }
    }
    /// Consumes a canonical partial-bit tail and the stream.
    pub fn finalize_bits(mut self, tail: BitString<'_>) -> Result<[u8; 20], Error> {
        self.executor.ready()?;
        match self.state.take().ok_or(Error::Quarantined)? {
            State::Portable(s) => s.finalize_bits(tail).map_err(|_| Error::MessageTooLong),
            State::Accelerated(s) => s.finalize_bits(tail).map_err(Error::from),
        }
    }
    /// Cancels the operation; source-owned buffers clear through their Drop.
    pub fn cancel(self) {}
}
