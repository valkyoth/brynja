//! Explicit ordinary CPU routes; never used by the hardened construction.
use super::{Sha512T, Sha512TBits, Sha512TDigest, Sha512TError, ordinary::render};
use crate::{BitString, Sha512AcceleratedError};
use brynja_crypto_cpu::Sha512BackendSession;

/// Failure of an explicitly requested general SHA-512/t CPU operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha512TAcceleratedError {
    /// Length admission or backend health/execution failed; no silent fallback.
    Backend(Sha512AcceleratedError),
    /// Canonical public digest rendering failed.
    Digest(Sha512TError),
}

impl Sha512T {
    /// Absorbs public bytes using an explicitly supplied healthy backend.
    ///
    /// Health and length admission happen before mutation. No portable fallback
    /// occurs on failure. The existing session requires compile-time CPU features
    /// and separate admission; ordinary builds cannot activate a candidate.
    pub fn update_with_backend(
        &mut self,
        input: &[u8],
        backend: &Sha512BackendSession,
    ) -> Result<(), Sha512TAcceleratedError> {
        self.state
            .update_with_backend(input, backend)
            .map_err(Sha512TAcceleratedError::Backend)
    }

    /// Consumes this public-data state, compressing padding through the backend.
    /// Output retains the exact t identity and canonical unused low bits.
    ///
    /// ```compile_fail,E0382
    /// use brynja_hash_sha2::{Sha512T, Sha512TBits};
    /// fn consumed(backend: &brynja_crypto_cpu::Sha512BackendSession) {
    ///     let state = Sha512T::new(Sha512TBits::new(9).unwrap());
    ///     let _ = state.finalize_with_backend(backend);
    ///     let _ = state.finalize_with_backend(backend);
    /// }
    /// ```
    pub fn finalize_with_backend(
        self,
        backend: &Sha512BackendSession,
    ) -> Result<Sha512TDigest, Sha512TAcceleratedError> {
        let words = self
            .state
            .finalize_with_backend(backend)
            .map_err(Sha512TAcceleratedError::Backend)?;
        render(self.parameter, words).map_err(Sha512TAcceleratedError::Digest)
    }

    /// Consumes a final canonical MSB-first bit string through the backend.
    /// Failure consumes the state; this ordinary state does not promise erasure.
    pub fn finalize_bits_with_backend(
        self,
        input: BitString<'_>,
        backend: &Sha512BackendSession,
    ) -> Result<Sha512TDigest, Sha512TAcceleratedError> {
        let words = self
            .state
            .finalize_bits_with_backend(input, backend)
            .map_err(Sha512TAcceleratedError::Backend)?;
        render(self.parameter, words).map_err(Sha512TAcceleratedError::Digest)
    }
}

/// Hashes public bytes with explicit CPU message/padding compression.
/// IV derivation uses the portable public-parameter implementation. No secret erasure.
/// Hardened states intentionally do not expose this route.
///
/// ```compile_fail,E0599
/// use brynja_hash_sha2::{HardenedSha512T, Sha512TBits};
/// fn no_secret_cpu(backend: &brynja_crypto_cpu::Sha512BackendSession) {
///     let mut state = HardenedSha512T::new(Sha512TBits::new(9).unwrap());
///     let _ = state.update_with_backend(b"secret", backend);
/// }
/// ```
pub fn sha512_t_with_backend(
    parameter: Sha512TBits,
    input: &[u8],
    backend: &Sha512BackendSession,
) -> Result<Sha512TDigest, Sha512TAcceleratedError> {
    let mut state = Sha512T::new(parameter);
    state.update_with_backend(input, backend)?;
    state.finalize_with_backend(backend)
}

/// Hashes a canonical public bit string with explicit CPU compression.
pub fn sha512_t_bits_with_backend(
    parameter: Sha512TBits,
    input: BitString<'_>,
    backend: &Sha512BackendSession,
) -> Result<Sha512TDigest, Sha512TAcceleratedError> {
    Sha512T::new(parameter).finalize_bits_with_backend(input, backend)
}
