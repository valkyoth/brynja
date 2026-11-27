//! Downstream API: no raw block primitive or backend error is exposed.
use super::{Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey, Buffers, Error, policy::Key};

/// Errors contain no key, nonce, plaintext or tag bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GcmError {
    /// Invalid IV, message, scratch, destination length or nonce interval.
    Length,
    /// The detached authentication tag did not verify.
    Authentication,
    /// No sending IVs remain, or this is an opening-only owner.
    Exhausted,
    /// The requested tag width is not one of 12, 13, 14, 15 or 16 bytes.
    TagLength,
    /// An underlying operation did not complete. No output was committed.
    Operation,
}

impl From<Error> for GcmError {
    fn from(value: Error) -> Self {
        match value {
            Error::Length | Error::Hash(crate::ghash::Error::LimitExceeded) => Self::Length,
            Error::Authentication => Self::Authentication,
            Error::Exhausted => Self::Exhausted,
            Error::TagLength => Self::TagLength,
            _ => Self::Operation,
        }
    }
}

macro_rules! owner {
    ($name:ident, $aes:ident, $width:literal, $size:literal, $description:literal $(, $pair:ident)?) => {
        #[doc = $description]
        #[must_use]
        pub struct $name<'a, const TAG_BYTES: usize = 16, const IV_BYTES: usize = 12>(
            Key<$aes<'a>, TAG_BYTES, IV_BYTES>,
        );

        impl<'a, const T: usize> $name<'a, T> {
            /// Import a key for sending and opening. The caller must already
            /// have reserved `count` IVs starting at `first` for this key and
            /// prefix. Empty or wrapping ranges are rejected. Each IV consists
            /// of the prefix and the 64-bit big-endian invocation number.
            /// Use this unrestricted counter profile only with a key dedicated
            /// to deterministic 96-bit IVs. For mixed lengths, reserve from a
            /// single key-wide budget and use `from_reserved_invocations`.
            pub fn from_reserved_range($( $pair: &'a AesPair, )?
                key: &[u8; $width],
                schedule: &'a mut [u8; $size],
                prefix: [u8; 4],
                first: u64,
                count: u64,
            ) -> Result<Self, GcmError> {
                let aes = $aes::new($($pair,)? key, schedule).map_err(|_| GcmError::Operation)?;
                Ok(Self(Key::from_reserved_range(aes, prefix, first, count)?))
            }
        }

        impl<'a, const T: usize, const N: usize> $name<'a, T, N> {
            /// Import a receiving key for exactly `N`-byte IVs (default: 12).
            /// Zero is not a valid IV width. No sending IVs are allocated.
            /// All attempts to seal with this owner return `Exhausted`.
            pub fn for_open($( $pair: &'a AesPair, )?
                key: &[u8; $width],
                schedule: &'a mut [u8; $size],
            ) -> Result<Self, GcmError> {
                let aes = $aes::new($($pair,)? key, schedule).map_err(|_| GcmError::Operation)?;
                Ok(Self(Key::for_open(aes)?))
            }
            /// Import a deterministic sender with `N`-byte IVs and a slice of
            /// a key-wide budget of at most 2^32 sealing invocations. Before
            /// import, durably reserve `count` contiguous numbers starting at
            /// `first`; never allocate a number twice for this raw key, even
            /// across different prefixes, devices, IV lengths or restarts.
            ///
            /// IV = fixed prefix || big-endian invocation number. For 12-byte
            /// IVs the number occupies 8 bytes; otherwise it occupies the last
            /// min(N, 4) bytes. The prefix must fill the remaining bytes. For
            /// N <= 4 use a single sending context. Empty IVs/ranges and
            /// ranges exceeding the budget or suffix capacity are rejected.
            /// The owner enforces its range; it cannot check external reservations.
            pub fn from_reserved_invocations($( $pair: &'a AesPair, )?
                key: &[u8; $width],
                schedule: &'a mut [u8; $size],
                prefix: &[u8],
                first: u32,
                count: u64,
            ) -> Result<Self, GcmError> {
                let aes = $aes::new($($pair,)? key, schedule).map_err(|_| GcmError::Operation)?;
                Ok(Self(Key::from_reserved_invocations(
                    aes, prefix, first, count,
                )?))
            }

            /// Seal into a separate equal-sized destination and return (IV, tag).
            /// Length rejection spends no nonce; a failure after keyed work starts does.
            pub fn seal_next(
                &mut self,
                aad: &[u8],
                plaintext: &[u8],
                ciphertext: &mut [u8],
                scratch: &mut [u8],
            ) -> Result<([u8; N], [u8; T]), GcmError> {
                Ok(self
                    .0
                    .seal_next(aad, Buffers::Separate(plaintext, ciphertext), scratch)?)
            }

            /// Seal in place using the next reserved IV. On error, data is unchanged.
            pub fn seal_next_in_place(
                &mut self,
                aad: &[u8],
                data: &mut [u8],
                scratch: &mut [u8],
            ) -> Result<([u8; N], [u8; T]), GcmError> {
                Ok(self.0.seal_next(aad, Buffers::InPlace(data), scratch)?)
            }

            /// Authenticate before writing plaintext. The IV must match the owner's
            /// width. Bound untrusted AAD and ciphertext lengths before allocating
            /// buffers or calling: portable work is linear. Does not consume a sending IV.
            pub fn open(
                &self,
                iv: &[u8; N],
                aad: &[u8],
                tag: &[u8; T],
                ciphertext: &[u8],
                plaintext: &mut [u8],
                scratch: &mut [u8],
            ) -> Result<(), GcmError> {
                Ok(self.0.open(
                    iv,
                    aad,
                    tag,
                    Buffers::Separate(ciphertext, plaintext),
                    scratch,
                )?)
            }

            /// Authenticate and then decrypt in place. A rejected tag leaves
            /// the original ciphertext untouched. The same IV width and application
            /// limits on AAD and ciphertext apply as for `open`.
            pub fn open_in_place(
                &self,
                iv: &[u8; N],
                aad: &[u8],
                tag: &[u8; T],
                data: &mut [u8],
                scratch: &mut [u8],
            ) -> Result<(), GcmError> {
                Ok(self.0.open(iv, aad, tag, Buffers::InPlace(data), scratch)?)
            }
        }
    };
}
owner!(
    Aes128Gcm,
    Aes128ExpandedKey,
    16,
    176,
    "Portable AES-128-GCM owner with a fixed tag width in bytes."
);
owner!(
    Aes192Gcm,
    Aes192ExpandedKey,
    24,
    208,
    "Portable AES-192-GCM owner with a fixed tag width in bytes."
);
owner!(
    Aes256Gcm,
    Aes256ExpandedKey,
    32,
    240,
    "Portable AES-256-GCM owner with a fixed tag width in bytes."
);

/// Required native owners. Admission takes place before key import; these
/// owners never switch to portable execution. Nonce and buffer contracts
/// are identical to the portable owners.
#[cfg(feature = "aes-gcm-execution")]
pub mod execution {
    use super::super::paired::{Aes128ExpandedKey, Aes192ExpandedKey, Aes256ExpandedKey};
    pub use super::super::paired::{AesPair, PairBackend, PairError};
    use super::{Buffers, GcmError, Key};
    /// Architecture-specific spelling for the x86 native pair.
    #[cfg(target_arch = "x86_64")]
    pub use AesPair as X86AesPair;
    owner!(
        Aes128Gcm,
        Aes128ExpandedKey,
        16,
        176,
        "AES-128-GCM with a required native AES/GHASH pair.",
        pair
    );
    owner!(
        Aes192Gcm,
        Aes192ExpandedKey,
        24,
        208,
        "AES-192-GCM with a required native AES/GHASH pair.",
        pair
    );
    owner!(
        Aes256Gcm,
        Aes256ExpandedKey,
        32,
        240,
        "AES-256-GCM with a required native AES/GHASH pair.",
        pair
    );
}
