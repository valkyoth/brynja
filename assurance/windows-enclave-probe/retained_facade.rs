//! Enclave API integration candidate, NOT an exported production backend.
//! Constructor is private until image verification/deployment are implemented.
//! No host slice, generic driver, raw token, callback or implicit fallback.
#![forbid(unsafe_code)]

use crate::{Resource, retained_model};
pub use retained_model::{Error, State};

/// Explicit caller decision to release a result into ordinary public memory.
/// This marker does not prove provenance or authorize confidential output.
pub struct PublicDeclassification(());
impl PublicDeclassification {
    pub fn acknowledge() -> Self {
        Self(())
    }
}

/// Concrete, thread-bound owner. Dropping attempts confirmed native cleanup;
/// uncertain resources are retained rather than freed as a fallback.
#[must_use]
pub struct Session {
    inner: retained_model::Session<Resource>,
}
impl Session {
    /// Private integration boundary. This fixture constructor is not image
    /// verification and must not become a public image-path constructor.
    pub(crate) fn from_retained(inner: retained_model::Session<Resource>) -> Self {
        Self { inner }
    }

    pub fn state(&self) -> State {
        self.inner.state()
    }

    /// SHA-256 of at most 1024 caller-owned bytes, copied synchronously into the
    /// enclave. The returned result borrows the session, not the original input.
    /// No confidential result bytes enter host memory through this operation.
    pub fn hash(&mut self, input: &[u8]) -> Result<Digest<'_>, Error> {
        self.inner.begin(input).map(|inner| Digest { inner })
    }

    /// Available after a forgotten digest. Success means confirmed release;
    /// a cleanup failure remains quarantined and never reports Closed.
    pub fn close(&mut self) -> Result<(), Error> {
        self.inner.close()
    }
}

/// Affine retained result. No Deref, AsRef, byte exposure or token export.
/// Drop quarantines the session; forgetting leaves it Busy. The owning session
/// remains responsible for clearing and release in either case.
#[must_use]
pub struct Digest<'session> {
    inner: retained_model::Pending<'session, Resource>,
}
impl Digest<'_> {
    /// Consume and replace the retained SHA-256 result entirely inside the enclave.
    pub fn rehash(self) -> Result<Self, Error> {
        self.inner.rehash().map(|inner| Self { inner })
    }

    /// Explicitly declassify into an exact-width public buffer. The destination
    /// is committed only after the worker's cleanup receipt is validated.
    /// A failed operation leaves it unchanged and quarantines the session.
    pub fn declassify(
        self,
        destination: &mut [u8; 32],
        _decision: PublicDeclassification,
    ) -> Result<(), Error> {
        self.inner.export_public(destination)
    }

    /// Consume and clear without exposing result bytes. Validated cancellation
    /// permits reuse; failed cancellation leaves the session quarantined.
    pub fn cancel(self) -> Result<(), Error> {
        self.inner.cancel()
    }
}
