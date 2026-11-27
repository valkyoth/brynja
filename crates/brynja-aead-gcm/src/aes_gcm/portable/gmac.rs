//! Portable GMAC authenticates associated data; it does not encrypt it or prevent replay.
//! Use a dedicated key and fix a tag width for its lifetime. In particular, GMAC and
//! GCM do not cryptographically separate their domains: distinct Rust types are not
//! a substitute for separate keys. Never repeat a sending IV under the same key.
//! Bound untrusted message lengths and failed verification attempts at the protocol boundary.
//! Prefer the default 12-byte IV for new protocols. If reservation history is lost,
//! rotate the key. A tag must match its owner's width at compile time; constructors
//! reject unsupported tag widths and empty IVs at runtime.
//!
//! GMAC authenticates one byte string, not field boundaries. For a structured
//! record, authenticate the protocol's canonical encoding (for example, each
//! variable-length field preceded by its fixed-width length in bytes).
//!
//! Dropping an owner clears its borrowed schedule. Forgetting the owner or
//! aborting the process can skip that clearing. Caller keys, compiler spills,
//! registers and crash dumps are outside this guarantee.
//!
//! Generate a tag using an invocation number already reserved by the application:
//! ```
//! use brynja_aead_gcm::gmac::{Aes256Gmac, GmacError, GmacTag};
//! fn authenticate(key: &[u8; 32], prefix: [u8; 4], reserved: u64, record: &[u8])
//!     -> Result<([u8; 12], GmacTag), GmacError>
//! {
//!     let mut schedule = [0; 240];
//!     let mut sender = Aes256Gmac::<16>::from_reserved_range(
//!         key, &mut schedule, prefix, reserved, 1)?;
//!     sender.authenticate_next(record)
//! }
//! ```
//! A raw GCM tag cannot be passed to GMAC verification without an explicit import:
//! ```compile_fail,E0308
//! use brynja_aead_gcm::gmac::Aes256Gmac;
//! fn wrong(owner: &Aes256Gmac<'_>, iv: &[u8; 12], record: &[u8], raw: &[u8; 16]) {
//!     let _ = owner.verify(iv, record, raw);
//! }
//! ```

use super::{Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey, Buffers, Error, policy::Key};

#[cfg(test)]
mod known_answers;

/// Detached public GMAC tag. Importing wire bytes does not authenticate them:
/// use the owner's `verify` method, which compares all admitted tag bytes.
#[derive(Clone, Copy, Debug)]
pub struct GmacTag<const T: usize = 16>([u8; T]);

impl<const T: usize> GmacTag<T> {
    /// Wrap an exact-width wire value. GMAC owners admit only 12–16 bytes.
    pub const fn from_bytes(bytes: [u8; T]) -> Self {
        Self(bytes)
    }
    /// The detached tag for transmission or storage.
    pub const fn as_bytes(&self) -> &[u8; T] {
        &self.0
    }
}

/// GMAC admission and authentication failures; no key or message bytes are included.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GmacError {
    /// Invalid IV, message length, or invocation interval.
    Length,
    /// The supplied tag did not authenticate this IV and associated data.
    Authentication,
    /// No sending IV remains, or the owner is verification-only.
    Exhausted,
    /// Only 12, 13, 14, 15 and 16-byte tags are admitted.
    TagLength,
    /// An underlying operation failed; no tag was returned.
    Operation,
}

impl From<Error> for GmacError {
    fn from(error: Error) -> Self {
        match error {
            Error::Length | Error::Hash(crate::ghash::Error::LimitExceeded) => Self::Length,
            Error::Authentication => Self::Authentication,
            Error::Exhausted => Self::Exhausted,
            Error::TagLength => Self::TagLength,
            _ => Self::Operation,
        }
    }
}

macro_rules! owner {
    ($name:ident, $aes:ident, $width:literal, $size:literal $(, $pair:ident)?) => {
        #[doc = concat!("AES-GMAC owner with a ", stringify!($width), "-byte key. The borrowed expanded schedule is cleared on drop; the original key stays caller-owned.")]
        #[must_use]
        pub struct $name<'a, const T: usize = 16, const N: usize = 12>(Key<$aes<'a>, T, N>);

        impl<'a, const T: usize> $name<'a, T> {
            /// For a key dedicated to 96-bit IVs: allocate IVs as a four-byte
            /// prefix followed by a big-endian 64-bit counter. The caller must
            /// durably reserve this nonempty range across senders and restarts.
            /// The range is not a per-key limit on total authenticated data or
            /// failed verifications; enforce those limits across all owners.
            pub fn from_reserved_range($( $pair: &'a AesPair, )?
                key: &[u8; $width], schedule: &'a mut [u8; $size],
                prefix: [u8; 4], first: u64, count: u64,
            ) -> Result<Self, GmacError> {
                let aes = $aes::new($($pair,)? key, schedule).map_err(|_| GmacError::Operation)?;
                Ok(Self(Key::from_reserved_range(aes, prefix, first, count)?))
            }
        }

        impl<'a, const T: usize, const N: usize> $name<'a, T, N> {
            /// For general IV widths, durably allocate from a key-wide budget of
            /// at most 2^32 invocations, disjoint across IV lengths, processes
            /// and devices. The big-endian counter occupies the final min(N, 4)
            /// bytes (8 for 96-bit IVs); prefix fills the rest. For N <= 4 use a
            /// single sending context. Empty IVs and truncating ranges are rejected.
            pub fn from_reserved_invocations($( $pair: &'a AesPair, )?
                key: &[u8; $width], schedule: &'a mut [u8; $size],
                prefix: &[u8], first: u32, count: u64,
            ) -> Result<Self, GmacError> {
                let aes = $aes::new($($pair,)? key, schedule).map_err(|_| GmacError::Operation)?;
                Ok(Self(Key::from_reserved_invocations(aes, prefix, first, count)?))
            }
            /// Construct a receiver for exactly N-byte IVs, without a sending allocation.
            pub fn for_verify($( $pair: &'a AesPair, )?key: &[u8; $width], schedule: &'a mut [u8; $size]) -> Result<Self, GmacError> {
                let aes = $aes::new($($pair,)? key, schedule).map_err(|_| GmacError::Operation)?;
                Ok(Self(Key::for_open(aes)?))
            }
            /// Return the next reserved IV and a detached tag over the associated
            /// data. An admitted IV is spent before keyed work and cannot be retried.
            pub fn authenticate_next(&mut self, aad: &[u8]) -> Result<([u8; N], GmacTag<T>), GmacError> {
                let (iv, tag) = self.0.seal_next(aad, Buffers::InPlace(&mut []), &mut [])?;
                Ok((iv, GmacTag(tag)))
            }
            /// Verify a detached tag without consuming a sending IV. The caller
            /// is responsible for replay policy, including after successful verification.
            pub fn verify(&self, iv: &[u8; N], aad: &[u8], tag: &GmacTag<T>) -> Result<(), GmacError> {
                Ok(self.0.open(iv, aad, tag.as_bytes(), Buffers::Separate(&[], &mut []), &mut [])?)
            }
        }
    };
}

owner!(Aes128Gmac, Aes128ExpandedKey, 16, 176);
owner!(Aes192Gmac, Aes192ExpandedKey, 24, 208);
owner!(Aes256Gmac, Aes256ExpandedKey, 32, 240);

/// Required native owners. Admission takes place before key import; these
/// owners never switch to portable execution. Nonce and buffer contracts
/// are identical to the portable owners.
#[cfg(feature = "gmac-execution")]
pub mod execution {
    use super::super::paired::{Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey};
    pub use super::super::paired::{AesPair, PairBackend, PairError};
    use super::{Buffers, GmacError, GmacTag, Key};
    /// Architecture-specific spelling for the x86 native pair.
    #[cfg(target_arch = "x86_64")]
    pub use AesPair as X86AesPair;
    owner!(Aes128Gmac, Aes128ExpandedKey, 16, 176, pair);
    owner!(Aes192Gmac, Aes192ExpandedKey, 24, 208, pair);
    owner!(Aes256Gmac, Aes256ExpandedKey, 32, 240, pair);
}
