use super::Error;

/// Validated public algorithm identity; no custom IV or invalid t is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Algorithm {
    wire: u64,
    bytes: usize,
}
impl Algorithm {
    /// SHA-224.
    pub const SHA224: Self = Self { wire: 1, bytes: 28 };
    /// SHA-256.
    pub const SHA256: Self = Self { wire: 2, bytes: 32 };
    /// SHA-384.
    pub const SHA384: Self = Self { wire: 3, bytes: 48 };
    /// SHA-512.
    pub const SHA512: Self = Self { wire: 4, bytes: 64 };
    /// Named SHA-512/224.
    pub const SHA512_224: Self = Self { wire: 5, bytes: 28 };
    /// Named SHA-512/256.
    pub const SHA512_256: Self = Self { wire: 6, bytes: 32 };
    /// General SHA-512/t: 1..=511 except 384. This is distinct from the named
    /// /224 and /256 identities, even where the mathematical results agree.
    pub fn sha512_t(bits: u16) -> Result<Self, Error> {
        if bits == 0 || bits >= 512 || bits == 384 {
            return Err(Error::Bounds);
        }
        Ok(Self {
            wire: 0x1000 | u64::from(bits),
            bytes: usize::from(bits.div_ceil(8)),
        })
    }
    /// Public output width; not a query into secret stream state.
    #[must_use]
    pub const fn output_bytes(self) -> usize {
        self.bytes
    }
    pub(in crate::windows_enclave) const fn wire(self) -> u64 {
        self.wire
    }
}
