use brynja_core::clear_owned_region;

use crate::Fips202BitString;

const MAX_INTEGER_BYTES: usize = 255;
const MAX_ENCODED_INTEGER_BYTES: usize = 256;

/// A canonical non-negative SP 800-185 integer below 2^2040.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Sp800185Integer<'value> {
    bytes: &'value [u8],
}

impl<'value> Sp800185Integer<'value> {
    /// Validates one minimal big-endian integer representation.
    pub fn from_be_bytes(bytes: &'value [u8]) -> Result<Self, Sp800185EncodingError> {
        if bytes.is_empty() {
            return Err(Sp800185EncodingError::EmptyInteger);
        }
        if bytes.len() > MAX_INTEGER_BYTES {
            return Err(Sp800185EncodingError::IntegerTooLarge);
        }
        if bytes.len() > 1 && bytes.first() == Some(&0) {
            return Err(Sp800185EncodingError::NonCanonicalInteger);
        }
        Ok(Self { bytes })
    }

    /// Returns the canonical big-endian bytes.
    #[must_use]
    pub const fn as_be_bytes(self) -> &'value [u8] {
        self.bytes
    }
}

/// One complete `left_encode` or `right_encode` result.
#[derive(Clone, Eq, PartialEq)]
pub struct EncodedInteger {
    bytes: [u8; MAX_ENCODED_INTEGER_BYTES],
    length: u16,
}

impl EncodedInteger {
    /// Borrows the exact encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
            .get(..usize::from(self.length))
            .unwrap_or_default()
    }
}

/// Exact shape of an encoded SP 800-185 bit string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedBitLength {
    bit_length: u128,
    byte_length: usize,
    valid_bits_in_last_byte: u8,
}

impl EncodedBitLength {
    /// Returns the exact encoded length in bits.
    #[must_use]
    pub const fn bits(self) -> u128 {
        self.bit_length
    }

    /// Returns the exact storage length in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.byte_length
    }

    /// Returns the valid low-bit count in the final byte.
    #[must_use]
    pub const fn valid_bits_in_last_byte(self) -> u8 {
        self.valid_bits_in_last_byte
    }
}

/// Closed SP 800-185 encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Sp800185EncodingError {
    /// A big-endian integer representation was empty.
    EmptyInteger,
    /// A big-endian integer representation contained a redundant leading zero.
    NonCanonicalInteger,
    /// The integer is outside the standard's `0 <= x < 2^2040` domain.
    IntegerTooLarge,
    /// `bytepad` requires a positive byte width.
    InvalidWidth,
    /// An exact bit or byte length could not be represented.
    LengthOverflow,
    /// The caller-owned output has a different length than the exact encoding.
    OutputLength,
}

/// Computes SP 800-185 `left_encode` over the complete integer domain.
#[must_use = "the canonical encoding must be consumed"]
pub fn left_encode(value: Sp800185Integer<'_>) -> EncodedInteger {
    encode_integer(value.as_be_bytes(), false)
}

/// Computes SP 800-185 `right_encode` over the complete integer domain.
#[must_use = "the canonical encoding must be consumed"]
pub fn right_encode(value: Sp800185Integer<'_>) -> EncodedInteger {
    encode_integer(value.as_be_bytes(), true)
}

/// Convenience `left_encode` for every `u128` value.
#[must_use = "the canonical encoding must be consumed"]
pub fn left_encode_u128(value: u128) -> EncodedInteger {
    encode_u128(value, false)
}

/// Convenience `right_encode` for every `u128` value.
#[must_use = "the canonical encoding must be consumed"]
pub fn right_encode_u128(value: u128) -> EncodedInteger {
    encode_u128(value, true)
}

/// Writes `left_encode(len(S)) || S` into an exact caller-owned destination.
///
/// SP 800-185 bit strings use the FIPS 202 low-bit-first representation.
/// Failure occurs before the destination is changed.
pub fn encode_string(
    input: Fips202BitString<'_>,
    destination: &mut [u8],
) -> Result<EncodedBitLength, Sp800185EncodingError> {
    let bit_length =
        u128::try_from(input.bit_len()).map_err(|_| Sp800185EncodingError::LengthOverflow)?;
    let prefix = left_encode_u128(bit_length);
    let prefix_bits = u128::try_from(prefix.as_bytes().len())
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or(Sp800185EncodingError::LengthOverflow)?;
    let encoded_bits = prefix_bits
        .checked_add(bit_length)
        .ok_or(Sp800185EncodingError::LengthOverflow)?;
    let encoded_bytes = bytes_for_bits(encoded_bits)?;
    if destination.len() != encoded_bytes {
        return Err(Sp800185EncodingError::OutputLength);
    }
    destination.fill(0);
    let prefix_length = prefix.as_bytes().len();
    let Some(prefix_target) = destination.get_mut(..prefix_length) else {
        return Err(Sp800185EncodingError::OutputLength);
    };
    prefix_target.copy_from_slice(prefix.as_bytes());
    let Some(input_target) = destination.get_mut(prefix_length..) else {
        return Err(Sp800185EncodingError::OutputLength);
    };
    input_target.copy_from_slice(input.as_bytes());
    Ok(encoded_shape(encoded_bits, encoded_bytes))
}

/// Writes SP 800-185 `bytepad(X, w)` into an exact caller-owned destination.
///
/// Failure occurs before the destination is changed. The returned byte count
/// equals `destination.len()` and is always a multiple of `width`.
pub fn bytepad(
    input: Fips202BitString<'_>,
    width: usize,
    destination: &mut [u8],
) -> Result<usize, Sp800185EncodingError> {
    if width == 0 {
        return Err(Sp800185EncodingError::InvalidWidth);
    }
    let width_u128 = u128::try_from(width).map_err(|_| Sp800185EncodingError::LengthOverflow)?;
    let prefix = left_encode_u128(width_u128);
    let prefix_bits = u128::try_from(prefix.as_bytes().len())
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or(Sp800185EncodingError::LengthOverflow)?;
    let input_bits =
        u128::try_from(input.bit_len()).map_err(|_| Sp800185EncodingError::LengthOverflow)?;
    let unpadded_bits = prefix_bits
        .checked_add(input_bits)
        .ok_or(Sp800185EncodingError::LengthOverflow)?;
    let unpadded_bytes = bytes_for_bits(unpadded_bits)?;
    let padded_bytes = round_up(unpadded_bytes, width)?;
    if destination.len() != padded_bytes {
        return Err(Sp800185EncodingError::OutputLength);
    }
    destination.fill(0);
    let prefix_length = prefix.as_bytes().len();
    let Some(prefix_target) = destination.get_mut(..prefix_length) else {
        return Err(Sp800185EncodingError::OutputLength);
    };
    prefix_target.copy_from_slice(prefix.as_bytes());
    let end = prefix_length
        .checked_add(input.as_bytes().len())
        .ok_or(Sp800185EncodingError::LengthOverflow)?;
    let Some(input_target) = destination.get_mut(prefix_length..end) else {
        return Err(Sp800185EncodingError::OutputLength);
    };
    input_target.copy_from_slice(input.as_bytes());
    Ok(padded_bytes)
}

pub(crate) fn absorb_cshake_prefix<F>(
    rate: usize,
    function_name: Fips202BitString<'_>,
    customization: Fips202BitString<'_>,
    mut absorb: F,
) -> Result<bool, ()>
where
    F: FnMut(&[u8]) -> Result<(), ()>,
{
    if function_name.bit_len() == 0 && customization.bit_len() == 0 {
        return Ok(false);
    }
    if !matches!(rate, 136 | 168) {
        return Err(());
    }
    let expected = cshake_prefix_bytes(rate, function_name, customization)?;
    let mut packer = PrefixPacker::new(&mut absorb);
    packer.push_bytes(left_encode_u128(u128::try_from(rate).map_err(|_| ())?).as_bytes())?;
    push_encoded_string(&mut packer, function_name)?;
    push_encoded_string(&mut packer, customization)?;
    packer.finish(rate)?;
    if packer.emitted != expected {
        return Err(());
    }
    Ok(true)
}

fn cshake_prefix_bytes(
    rate: usize,
    function_name: Fips202BitString<'_>,
    customization: Fips202BitString<'_>,
) -> Result<usize, ()> {
    if rate == 0 {
        return Err(());
    }
    let rate_prefix = left_encode_u128(u128::try_from(rate).map_err(|_| ())?);
    let n_bits = u128::try_from(function_name.bit_len()).map_err(|_| ())?;
    let s_bits = u128::try_from(customization.bit_len()).map_err(|_| ())?;
    let n_prefix = left_encode_u128(n_bits);
    let s_prefix = left_encode_u128(s_bits);
    let fixed_bytes = rate_prefix
        .as_bytes()
        .len()
        .checked_add(n_prefix.as_bytes().len())
        .and_then(|value| value.checked_add(s_prefix.as_bytes().len()))
        .ok_or(())?;
    let fixed_bits = u128::try_from(fixed_bytes)
        .ok()
        .and_then(|value| value.checked_mul(8))
        .ok_or(())?;
    let total_bits = fixed_bits
        .checked_add(n_bits)
        .and_then(|value| value.checked_add(s_bits))
        .ok_or(())?;
    let bytes = bytes_for_bits(total_bits).map_err(|_| ())?;
    round_up(bytes, rate).map_err(|_| ())
}

fn push_encoded_string<F>(
    packer: &mut PrefixPacker<'_, F>,
    value: Fips202BitString<'_>,
) -> Result<(), ()>
where
    F: FnMut(&[u8]) -> Result<(), ()>,
{
    let bits = u128::try_from(value.bit_len()).map_err(|_| ())?;
    packer.push_bytes(left_encode_u128(bits).as_bytes())?;
    packer.push_bit_string(value)
}

struct PrefixPacker<'sink, F>
where
    F: FnMut(&[u8]) -> Result<(), ()>,
{
    absorb: &'sink mut F,
    pending: [u8; 1],
    used: u8,
    emitted: usize,
}

impl<'sink, F> PrefixPacker<'sink, F>
where
    F: FnMut(&[u8]) -> Result<(), ()>,
{
    fn new(absorb: &'sink mut F) -> Self {
        Self {
            absorb,
            pending: [0],
            used: 0,
            emitted: 0,
        }
    }

    fn push_bit_string(&mut self, input: Fips202BitString<'_>) -> Result<(), ()> {
        let (whole, partial) = input.split();
        self.push_bytes(whole)?;
        if let Some((byte, valid)) = partial {
            self.push_bits(byte, valid)?;
        }
        Ok(())
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if self.used == 0 {
            (self.absorb)(bytes)?;
            self.emitted = self.emitted.checked_add(bytes.len()).ok_or(())?;
            return Ok(());
        }
        for byte in bytes {
            self.push_bits(*byte, 8)?;
        }
        Ok(())
    }

    fn push_bits(&mut self, byte: u8, valid: u8) -> Result<(), ()> {
        for position in 0..valid {
            let bit = (byte >> position) & 1;
            self.pending[0] |= bit << self.used;
            self.used = self.used.checked_add(1).ok_or(())?;
            if self.used == 8 {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn finish(&mut self, width: usize) -> Result<(), ()> {
        if self.used != 0 {
            self.flush()?;
        }
        let remainder = self.emitted.checked_rem(width).ok_or(())?;
        if remainder != 0 {
            let padding = width.checked_sub(remainder).ok_or(())?;
            let zeros = [0_u8; 168];
            let slice = zeros.get(..padding).ok_or(())?;
            (self.absorb)(slice)?;
            self.emitted = self.emitted.checked_add(padding).ok_or(())?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ()> {
        (self.absorb)(&self.pending)?;
        self.emitted = self.emitted.checked_add(1).ok_or(())?;
        let _ = clear_owned_region(&mut self.pending);
        self.used = 0;
        Ok(())
    }
}

impl<F> Drop for PrefixPacker<'_, F>
where
    F: FnMut(&[u8]) -> Result<(), ()>,
{
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.pending);
        self.used = 0;
    }
}

fn encode_u128(value: u128, right: bool) -> EncodedInteger {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    encode_integer(bytes.get(first..).unwrap_or_default(), right)
}

fn encode_integer(value: &[u8], right: bool) -> EncodedInteger {
    let mut bytes = [0_u8; MAX_ENCODED_INTEGER_BYTES];
    let length = value.len().saturating_add(1);
    let encoded_length = u8::try_from(value.len()).unwrap_or_default();
    if right {
        if let Some(target) = bytes.get_mut(..value.len()) {
            target.copy_from_slice(value);
        }
        if let Some(target) = bytes.get_mut(value.len()) {
            *target = encoded_length;
        }
    } else {
        bytes[0] = encoded_length;
        if let Some(target) = bytes.get_mut(1..length) {
            target.copy_from_slice(value);
        }
    }
    EncodedInteger {
        bytes,
        length: u16::try_from(length).unwrap_or_default(),
    }
}

fn bytes_for_bits(bits: u128) -> Result<usize, Sp800185EncodingError> {
    let rounded = bits
        .checked_add(7)
        .ok_or(Sp800185EncodingError::LengthOverflow)?
        / 8;
    usize::try_from(rounded).map_err(|_| Sp800185EncodingError::LengthOverflow)
}

fn round_up(length: usize, width: usize) -> Result<usize, Sp800185EncodingError> {
    let remainder = length
        .checked_rem(width)
        .ok_or(Sp800185EncodingError::InvalidWidth)?;
    if remainder == 0 {
        return Ok(length);
    }
    length
        .checked_add(width.saturating_sub(remainder))
        .ok_or(Sp800185EncodingError::LengthOverflow)
}

fn encoded_shape(bits: u128, bytes: usize) -> EncodedBitLength {
    let remainder = u8::try_from(bits.checked_rem(8).unwrap_or_default()).unwrap_or_default();
    EncodedBitLength {
        bit_length: bits,
        byte_length: bytes,
        valid_bits_in_last_byte: if remainder == 0 { 8 } else { remainder },
    }
}

#[cfg(kani)]
mod proofs {
    use super::{bytes_for_bits, round_up};

    #[kani::proof]
    fn rounded_bit_storage_is_minimal() {
        let bits: u16 = kani::any();
        let bytes = bytes_for_bits(u128::from(bits)).unwrap_or_default();
        assert!(bytes.saturating_mul(8) >= usize::from(bits));
        if bytes != 0 {
            assert!(bytes.saturating_sub(1).saturating_mul(8) < usize::from(bits));
        }
    }

    #[kani::proof]
    fn bytepad_rounding_is_exact() {
        let length: u16 = kani::any();
        let width: u8 = kani::any();
        kani::assume(width > 0);
        let rounded = round_up(usize::from(length), usize::from(width)).unwrap_or_default();
        assert_eq!(rounded.checked_rem(usize::from(width)), Some(0));
        assert!(rounded >= usize::from(length));
        assert!(rounded.saturating_sub(usize::from(length)) < usize::from(width));
    }
}
