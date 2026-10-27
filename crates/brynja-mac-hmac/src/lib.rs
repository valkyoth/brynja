//! HMAC over a sealed set of modern, secret-bearing hash implementations.
//!
//! This implementation and its opt-in static execution route are under development and have not yet
//! completed HMAC-specific security review or compiler/native qualification.
//! Hash owners are reused, but their evidence is not evidence of this new
//! composition. No FIPS validation or independent cryptographic review is claimed.
//!
//! Keys of any byte length, including empty keys, are mathematically accepted.
//! This is not a key-strength check: applications must provide unpredictable
//! keys with adequate entropy. Caller buffers, compiler-created moves/spills,
//! fatal termination, paging and OS snapshots are outside owned-memory cleanup.
//! Use neither this API nor ordinary hash APIs as a protected-memory promise.

#![no_std]

mod algorithms;
mod bits;
mod engine;
#[cfg(feature = "hardened-execution")]
pub mod execution;
mod general;
mod output;
mod policy;
mod scratch;

pub use algorithms::{
    Algorithm, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512, Sha512_224,
    Sha512_256,
};
pub use brynja_hash_sha2::{BitString as Sha2BitString, BitStringError as Sha2BitsError};
pub use brynja_hash_sha3::{Fips202BitString, Fips202BitsError};
pub use general::Sha512T;
pub use output::{SecretTag, Tag};

/// Value-free failure from an HMAC operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The selected digest's message length domain would be exceeded.
    MessageTooLong,
    /// The explicit tag length or destination length is invalid.
    TagLength,
    /// The hash parameter is invalid or below the 128-bit HMAC policy minimum.
    AlgorithmParameter,
    /// The selected CPU authority failed; never authorizes portable fallback.
    #[cfg(feature = "hardened-execution")]
    Backend(brynja_crypto_cpu::static_execution::Error),
    /// An execution stream is terminal after a backend error or unwind.
    #[cfg(feature = "hardened-execution")]
    ExecutionFailed,
    /// A secret storage or internal composition invariant failed.
    SecretMemory,
    /// Comparison completed, but the supplied authenticator did not match.
    Mismatch,
}

impl From<brynja_core::SecretMemoryError> for Error {
    fn from(_: brynja_core::SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

/// Validates a protocol-selected tag policy without processing a key.
///
/// Returns the exact tag width in bits. `None` selects the complete digest,
/// including a fractional SHA-512/t final byte. `Some(bytes)` selects a
/// whole-byte prefix of at least 16 bytes and at most floor(digest_bits / 8).
/// An invalid algorithm is rejected before its tag width is considered.
///
/// Choose this policy from the protocol, never from an untrusted candidate tag.
/// Success does not validate key strength, CPU authority or protected storage.
///
/// ```
/// use brynja_mac_hmac::{validate_tag_policy, Error, Sha512T};
/// assert_eq!(validate_tag_policy::<Sha512T<129>>(None), Ok(129));
/// assert_eq!(validate_tag_policy::<Sha512T<129>>(Some(16)), Ok(128));
/// assert_eq!(validate_tag_policy::<Sha512T<129>>(Some(17)), Err(Error::TagLength));
/// ```
pub fn validate_tag_policy<A: Algorithm>(tag_bytes: Option<usize>) -> Result<usize, Error> {
    A::validate()?;
    let Some(bytes) = tag_bytes else {
        return Ok(A::TAG_BITS);
    };
    let bits = bytes.checked_mul(8).ok_or(Error::TagLength)?;
    if !policy::valid_tag_length(A::TAG_BYTES, bytes) || bits > A::TAG_BITS {
        return Err(Error::TagLength);
    }
    Ok(bits)
}

/// Affine, portable HMAC state for one admitted modern hash identity.
///
/// Inner/outer states and scratch use the existing clearing hash owners and
/// volatile region cleanup. There is no reset, snapshot, key export or ordinary
/// hash conversion. Successful finalization and failed finalization both consume
/// this owner; a length-rejected update leaves it unchanged.
///
/// ```
/// use brynja_mac_hmac::{Hmac, Sha256};
/// let key = [0x42; 32]; // Example only; generate real keys securely.
/// let mut mac = Hmac::<Sha256>::new(&key)?;
/// mac.update(b"message")?;
/// let mut bytes = [0; 32];
/// let tag = mac.finalize_tag(&mut bytes)?;
/// let mut verifier = Hmac::<Sha256>::new(&key)?;
/// verifier.update(b"message")?;
/// verifier.verify(tag.as_bytes())?;
/// # Ok::<(), brynja_mac_hmac::Error>(())
/// ```
///
/// ```compile_fail
/// use brynja_mac_hmac::{Hmac, Sha256};
/// let mac = Hmac::<Sha256>::new(b"example").unwrap();
/// let _copy = mac.clone();
/// ```
///
/// ```compile_fail
/// use brynja_mac_hmac::{Hmac, Sha256};
/// let mac = Hmac::<Sha256>::new(b"example").unwrap();
/// println!("{mac:?}");
/// ```
///
/// ```compile_fail
/// use brynja_mac_hmac::{Hmac, Sha256};
/// let mut mac = Hmac::<Sha256>::new(b"example").unwrap();
/// let mut bytes = [0; 32];
/// let _tag = mac.finalize_tag(&mut bytes).unwrap();
/// mac.update(b"reopened").unwrap();
/// ```
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_mac_hmac::Hmac<brynja_mac_hmac::Sha256>>();
/// ```
///
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_mac_hmac::Hmac<brynja_mac_hmac::Sha256>>();
/// ```
///
/// ```compile_fail
/// fn copy<T: Copy>() {}
/// copy::<brynja_mac_hmac::Hmac<brynja_mac_hmac::Sha256>>();
/// ```
pub struct Hmac<A: Algorithm> {
    engine: engine::Engine<A>,
    // An HMAC owner is deliberately local, even if a leaf's auto traits change.
    _local: core::marker::PhantomData<*mut ()>,
}

impl<A: Algorithm> Hmac<A> {
    /// Authenticates a complete message and releases one full-length public tag.
    ///
    /// Errors leave the public destination unchanged. This uses the same
    /// secret-bearing construction as streaming, including long-key handling.
    pub fn authenticate<'a>(
        key: &[u8],
        message: &[u8],
        destination: &'a mut [u8],
    ) -> Result<Tag<'a, A>, Error> {
        let mut mac = Self::new(key)?;
        mac.update(message)?;
        mac.finalize_tag(destination)
    }

    /// Creates a state requiring the complete digest-sized authentication tag.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        validate_tag_policy::<A>(None)?;
        Ok(Self {
            engine: engine::Engine::new(key, A::TAG_BYTES)?,
            _local: core::marker::PhantomData,
        })
    }

    /// Selects an exact byte-aligned tag length before processing the message.
    ///
    /// For non-byte-aligned general SHA-512/t, use `new` for the full t-bit tag;
    /// this method only selects complete bytes no longer than floor(t/8).
    ///
    /// This initial policy accepts 16 through the full digest length in bytes.
    /// The caller must choose this from its protocol, not from an untrusted
    /// candidate tag. Shorter tags reduce guessing resistance; no per-key usage
    /// or failed-verification budget is enforced by this construction.
    pub fn with_tag_length(key: &[u8], tag_bytes: usize) -> Result<Self, Error> {
        validate_tag_policy::<A>(Some(tag_bytes))?;
        Ok(Self {
            engine: engine::Engine::new(key, tag_bytes)?,
            _local: core::marker::PhantomData,
        })
    }

    /// Absorbs complete bytes without exposing accumulated secret-message length.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.engine.update(input)
    }

    /// Consumes the state and explicitly releases a public authentication tag.
    ///
    /// The destination must match the selected length. Every error leaves the
    /// public destination unchanged. Use `finalize_secret` for derived secrets.
    pub fn finalize_tag(self, destination: &mut [u8]) -> Result<Tag<'_, A>, Error> {
        self.engine.public(None, destination)
    }

    /// Consumes the state and returns clearing ownership of the secret tag.
    ///
    /// Every failure clears the entire destination; dropping the returned owner
    /// clears it too. The owner cannot prevent application-created copies.
    pub fn finalize_secret(self, destination: &mut [u8]) -> Result<SecretTag<'_, A>, Error> {
        self.engine.secret(None, destination)
    }

    /// Consumes the state and compares exactly the selected tag length.
    ///
    /// Length rejection depends only on public policy. Equal-length comparison
    /// accumulates all differences without a content-dependent early exit.
    /// `Ok(())` means authenticated; a completed mismatch is [`Error::Mismatch`].
    pub fn verify(self, candidate: &[u8]) -> Result<(), Error> {
        self.engine.verify(None, candidate)
    }

    /// Consumes and clears this owner without producing an output.
    pub fn cancel(self) {}
}
