use super::Error;
use crate::Fips202BitString;
/// Exact domain identity. cSHAKE with empty N and S is SHAKE-equivalent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// SHA3-224, 224 output bits.
    Sha3_224,
    /// SHA3-256, 256 output bits.
    Sha3_256,
    /// SHA3-384, 384 output bits.
    Sha3_384,
    /// SHA3-512, 512 output bits.
    Sha3_512,
    /// SHAKE128 with finite caller-selected output.
    Shake128,
    /// SHAKE256 with finite caller-selected output.
    Shake256,
    /// SP 800-185 cSHAKE128 with arbitrary-bit N/S.
    Cshake128,
    /// SP 800-185 cSHAKE256 with arbitrary-bit N/S.
    Cshake256,
}
impl Algorithm {
    /// Sponge rate in bytes, not the number of parallel message lanes.
    pub const fn rate(self) -> usize {
        match self {
            Self::Sha3_224 => 144,
            Self::Sha3_256 | Self::Shake256 | Self::Cshake256 => 136,
            Self::Sha3_384 => 104,
            Self::Sha3_512 => 72,
            Self::Shake128 | Self::Cshake128 => 168,
        }
    }
    /// Required output bits for fixed SHA-3, or None for finite XOF output.
    pub const fn fixed_output_bits(self) -> Option<usize> {
        match self {
            Self::Sha3_224 => Some(224),
            Self::Sha3_256 => Some(256),
            Self::Sha3_384 => Some(384),
            Self::Sha3_512 => Some(512),
            _ => None,
        }
    }
    pub(super) fn customized(self) -> bool {
        matches!(self, Self::Cshake128 | Self::Cshake256)
    }
}

/// Borrowed canonical input and explicit finite output request.
pub struct Input<'a> {
    pub(super) algorithm: Algorithm,
    pub(super) message: Fips202BitString<'a>,
    pub(super) name: Fips202BitString<'a>,
    pub(super) customization: Fips202BitString<'a>,
    pub(super) output_bits: usize,
}
impl<'a> Input<'a> {
    /// Creates SHA-3/SHAKE or empty-domain cSHAKE. Fixed identities require their
    /// exact digest width. Zero-bit output is valid for XOF identities only.
    pub fn new(
        algorithm: Algorithm,
        message: Fips202BitString<'a>,
        output_bits: usize,
    ) -> Result<Self, Error> {
        let empty = Fips202BitString::new(&[], 0).map_err(|_| Error::Invariant)?;
        Self::with_customization(algorithm, message, empty, empty, output_bits)
    }
    /// Creates cSHAKE with arbitrary-bit N/S. Nonempty N/S on SHA-3 or SHAKE is
    /// rejected, never ignored or silently converted to a different identity.
    pub fn with_customization(
        algorithm: Algorithm,
        message: Fips202BitString<'a>,
        name: Fips202BitString<'a>,
        customization: Fips202BitString<'a>,
        output_bits: usize,
    ) -> Result<Self, Error> {
        if algorithm
            .fixed_output_bits()
            .is_some_and(|n| n != output_bits)
            || (!algorithm.customized() && (name.bit_len() != 0 || customization.bit_len() != 0))
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            algorithm,
            message,
            name,
            customization,
            output_bits,
        })
    }
    /// Exact requested identity; output order matches input order.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Finite output bit count. Unused high bits of the last byte are cleared.
    pub const fn output_bits(&self) -> usize {
        self.output_bits
    }
    /// Exact required destination width, with no rounded bit-length overflow.
    pub const fn output_bytes(&self) -> usize {
        self.output_bits.div_ceil(8)
    }
}

impl Algorithm {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Sha3_224 => 1,
            Self::Sha3_256 => 2,
            Self::Sha3_384 => 3,
            Self::Sha3_512 => 4,
            Self::Shake128 => 5,
            Self::Shake256 => 6,
            Self::Cshake128 => 7,
            Self::Cshake256 => 8,
        }
    }
    pub(super) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Sha3_224),
            2 => Some(Self::Sha3_256),
            3 => Some(Self::Sha3_384),
            4 => Some(Self::Sha3_512),
            5 => Some(Self::Shake128),
            6 => Some(Self::Shake256),
            7 => Some(Self::Cshake128),
            8 => Some(Self::Cshake256),
            _ => None,
        }
    }
}
