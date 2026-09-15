use crate::Sha512TBits;

/// Exact public digest identity. Named truncations remain distinct from general t.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// SHA-384, with its distinct IV.
    Sha384,
    /// SHA-512.
    Sha512,
    /// Named SHA-512/224.
    Sha512_224,
    /// Named SHA-512/256.
    Sha512_256,
    /// Validated general SHA-512/t. Short t values have correspondingly weak security.
    Sha512T(Sha512TBits),
}
impl Algorithm {
    /// Exact output bits; not merely its rounded byte width.
    pub const fn output_bits(self) -> u16 {
        match self {
            Self::Sha384 => 384,
            Self::Sha512 => 512,
            Self::Sha512_224 => 224,
            Self::Sha512_256 => 256,
            Self::Sha512T(t) => t.bits(),
        }
    }
    /// Exact caller destination width, including a canonical partial final byte.
    pub const fn output_bytes(self) -> usize {
        self.output_bits().div_ceil(8) as usize
    }
    pub(super) fn code(self) -> u16 {
        match self {
            Self::Sha384 => 1,
            Self::Sha512 => 2,
            Self::Sha512_224 => 3,
            Self::Sha512_256 => 4,
            Self::Sha512T(t) => 0x1000 | t.bits(),
        }
    }
    pub(super) fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Sha384),
            2 => Some(Self::Sha512),
            3 => Some(Self::Sha512_224),
            4 => Some(Self::Sha512_256),
            0x1001..=0x11ff => Sha512TBits::new(code & 0x0fff).ok().map(Self::Sha512T),
            _ => None,
        }
    }
    pub(super) fn initial_words(self) -> [u64; 8] {
        match self {
            Self::Sha384 => crate::sha384::INITIAL_STATE,
            Self::Sha512 => crate::sha512::INITIAL_STATE,
            Self::Sha512_224 => crate::sha512_t::SHA512_224_INITIAL_STATE,
            Self::Sha512_256 => crate::sha512_t::SHA512_256_INITIAL_STATE,
            Self::Sha512T(t) => t.initial_words(),
        }
    }
    pub(super) const fn last_byte_mask(self) -> u8 {
        match self {
            Self::Sha512T(t) => t.last_byte_mask(),
            _ => 0xff,
        }
    }
}
