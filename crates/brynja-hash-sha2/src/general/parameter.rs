use super::{Sha512TError, iv};

/// Validated FIPS 180-4 section 5.3.6 mathematical parameter.
///
/// All 510 values in 1..=511 except 384 are supported. This is not protocol,
/// MAC, signature, or FIPS approval. Short outputs have at most about t/2
/// collision-security bits and t preimage-security bits. General /224 and
/// /256 retain distinct types from the existing named SHA-2 APIs.
///
/// Contains only public metadata; copying and ordinary equality are allowed.
///
/// ```
/// use brynja_hash_sha2::Sha512TBits;
/// let parameter = Sha512TBits::new(9)?;
/// assert_eq!(parameter.bits(), 9);
/// assert_eq!(parameter.output_bytes(), 2);
/// assert!(Sha512TBits::new(384).is_err());
/// # Ok::<(), brynja_hash_sha2::Sha512TError>(())
/// ```
///
/// Invalid parameters cannot be constructed with a field literal:
/// ```compile_fail
/// let invalid = brynja_hash_sha2::Sha512TBits(384);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha512TBits(u16);

impl Sha512TBits {
    /// Checks t without allocation, hashing, or mutating any caller storage.
    pub const fn new(bits: u16) -> Result<Self, Sha512TError> {
        if bits == 0 || bits >= 512 || bits == 384 {
            Err(Sha512TError::InvalidParameter)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns the exact bit count, not the rounded byte width.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Exact public or secret digest destination width: ceil(t/8).
    #[must_use]
    pub const fn output_bytes(self) -> usize {
        self.0.div_ceil(8) as usize
    }

    /// Writes the exact ASCII IV-generation label and returns its byte length.
    ///
    /// Needs 9..=11 bytes (11 always suffices). No terminator is written.
    /// A short destination is unchanged; a larger destination's trailing
    /// bytes are unchanged. Work and storage are bounded by eleven bytes.
    /// This encodes public metadata, not a digest or secret-bearing message.
    ///
    /// ```
    /// let parameter = brynja_hash_sha2::Sha512TBits::new(9)?;
    /// let mut label = [0; 11];
    /// let used = parameter.write_iv_label(&mut label)?;
    /// assert_eq!(&label[..used], b"SHA-512/9");
    /// # Ok::<(), brynja_hash_sha2::Sha512TError>(())
    /// ```
    pub fn write_iv_label(self, output: &mut [u8]) -> Result<usize, Sha512TError> {
        let (label, length) = iv::label(self);
        let destination = output.get_mut(..length).ok_or(Sha512TError::OutputLength)?;
        for (slot, byte) in destination.iter_mut().zip(label) {
            *slot = byte;
        }
        Ok(length)
    }

    /// Derives the eight public initial words specified by FIPS 180-4.
    ///
    /// Executes exactly one portable SHA-512 compression of the canonical
    /// label under the XOR-modified IV. Uses fixed stack storage, no global
    /// cache, allocation, caller-supplied IV, or CPU backend. All temporaries
    /// depend only on public t and are not zeroized. These are initial words,
    /// **not a message digest**. Use `Sha512T` or `HardenedSha512T` to hash messages.
    #[must_use]
    pub fn initial_words(self) -> [u64; 8] {
        iv::derive(self)
    }

    pub(crate) const fn last_byte_mask(self) -> u8 {
        0xff_u8 << (8_u16.saturating_sub(self.0 % 8) % 8)
    }
}

impl TryFrom<u16> for Sha512TBits {
    type Error = Sha512TError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
