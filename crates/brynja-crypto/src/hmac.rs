//! HMAC over modern hardened hash owners; qualification remains pending.
//!
//! This namespace exposes an explicit leaf API list, not a whole-crate alias.
//! Algorithm identities are HMAC adapters, not ordinary hash implementations.
//! Keys are caller-owned byte strings; accepting an empty key is mathematical
//! behavior, not a strength guarantee. Supply unpredictable protocol-sized keys.
//! The tag width is selected before processing, never inferred from a candidate.
//! Paging, caller copies, compiler spills and fatal termination remain outside
//! owned-memory cleanup. Protected/resident host sessions are separate APIs.
//!
//! ```
//! use brynja_crypto::hmac::{Hmac, Sha256, Error};
//! let key = [0x42; 32]; // Example only; generate real keys securely.
//! let mut state = Hmac::<Sha256>::new(&key)?;
//! state.update(b"message")?;
//! let mut bytes = [0; 32];
//! let tag = state.finalize_tag(&mut bytes)?;
//! let mut verifier = Hmac::<Sha256>::new(&key)?;
//! verifier.update(b"message")?;
//! assert_eq!(verifier.verify(tag.as_bytes()), Ok(()));
//! # Ok::<(), Error>(())
//! ```
pub use brynja_mac_hmac::{
    Algorithm, Error, Fips202BitString, Fips202BitsError, Hmac, SecretTag, Sha2BitString,
    Sha2BitsError, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512,
    Sha512_224, Sha512_256, Sha512T, Tag, validate_tag_policy,
};

/// Borrowed CPU-authority execution; no implicit detection or scalar fallback.
/// Available only with this facade's own explicit opt-in, even when another
/// dependency enables the leaf's execution feature through feature unification.
#[cfg(any(
    feature = "hmac-hardened-execution",
    feature = "hmac-runtime-execution"
))]
pub use brynja_mac_hmac::execution;
