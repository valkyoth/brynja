//! Official NIST arbitrary-bit vectors and public lifecycle checks.

use brynja_hash_sha2::{
    BitString, BitStringError, Sha224, Sha224Digest, Sha256, Sha256Digest, Sha384, Sha384Digest,
    Sha512, Sha512_224, Sha512_224Digest, Sha512_256, Sha512_256Digest, Sha512Digest, sha224,
    sha224_bits, sha256, sha256_bits, sha384, sha384_bits, sha512, sha512_224, sha512_224_bits,
    sha512_256, sha512_256_bits, sha512_bits,
};

const NIST_VECTORS: &str = include_str!("vectors/nist-bit-selected.txt");

#[test]
fn selected_official_nist_bit_vectors_match_every_identity() {
    let mut count = 0_usize;
    for line in NIST_VECTORS
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let mut fields = line.split('|');
        let algorithm = fields.next().unwrap_or_default();
        let Some(bit_len) = parse_usize(fields.next().unwrap_or_default()) else {
            continue;
        };
        let Some(mut message) = decode_hex(fields.next().unwrap_or_default()) else {
            continue;
        };
        let Some(expected) = decode_hex(fields.next().unwrap_or_default()) else {
            continue;
        };
        assert!(fields.next().is_none());
        message.truncate(bit_len.saturating_add(7) / 8);
        let Some(input) = canonical(&message, bit_len) else {
            continue;
        };
        let recognized = match algorithm {
            "SHA224" => check_sha224(input, &message, bit_len, &expected),
            "SHA256" => check_sha256(input, &message, bit_len, &expected),
            "SHA384" => check_sha384(input, &message, bit_len, &expected),
            "SHA512" => check_sha512(input, &message, bit_len, &expected),
            "SHA512_224" => check_sha512_224(input, &message, bit_len, &expected),
            "SHA512_256" => check_sha512_256(input, &message, bit_len, &expected),
            _ => false,
        };
        assert!(recognized);
        count = count.saturating_add(1);
    }
    assert_eq!(count, 240);
}

#[test]
fn canonical_representation_rejects_every_ambiguous_tail_width() {
    assert!(matches!(
        BitString::new(&[], 8),
        Err(BitStringError::InvalidValidBitCount)
    ));
    assert!(matches!(
        BitString::new(&[0], 0),
        Err(BitStringError::InvalidValidBitCount)
    ));
    for valid in 1_u8..8 {
        let unused_mask = u8::MAX >> valid;
        for unused in 1..=unused_mask {
            assert!(matches!(
                BitString::new(&[unused], valid),
                Err(BitStringError::NonZeroUnusedBits)
            ));
        }
    }
}

#[test]
fn byte_aligned_bit_apis_preserve_every_frozen_byte_api() {
    let messages: [&[u8]; 8] = [
        b"", b"a", b"abc", &[0; 55], &[0; 56], &[0; 64], &[0; 112], &[0; 129],
    ];
    for message in messages {
        let bits = if message.is_empty() {
            canonical(message, 0)
        } else {
            canonical(message, message.len().saturating_mul(8))
        };
        assert!(bits.is_some());
        let Some(bits) = bits else {
            continue;
        };
        assert_eq!(sha224_bits(bits), sha224(message));
        assert_eq!(sha256_bits(bits), sha256(message));
        assert_eq!(sha384_bits(bits), sha384(message));
        assert_eq!(sha512_bits(bits), sha512(message));
        assert_eq!(sha512_224_bits(bits), sha512_224(message));
        assert_eq!(sha512_256_bits(bits), sha512_256(message));
    }
}

#[test]
fn exact_bit_length_preflight_is_transactional_for_every_identity() {
    let mut narrow224 = Sha224::new();
    let mut narrow256 = Sha256::new();
    assert_eq!(narrow224.update(b"x"), Ok(()));
    assert_eq!(narrow256.update(b"x"), Ok(()));
    assert!(narrow224.check_additional_bits(u64::MAX - 8).is_ok());
    assert!(narrow256.check_additional_bits(u64::MAX - 8).is_ok());
    assert!(narrow224.check_additional_bits(u64::MAX - 7).is_err());
    assert!(narrow256.check_additional_bits(u64::MAX - 7).is_err());
    assert_eq!(narrow224.message_bits(), 8);
    assert_eq!(narrow256.message_bits(), 8);

    check_wide_exhaustion(Sha384::new());
    check_wide_exhaustion(Sha512::new());
    check_wide_exhaustion(Sha512_224::new());
    check_wide_exhaustion(Sha512_256::new());
}

trait WideState {
    fn absorb_one(&mut self) -> bool;
    fn check_bits(&self, bits: u128) -> bool;
    fn bits(&self) -> u128;
}

macro_rules! wide_state {
    ($state:ty) => {
        impl WideState for $state {
            fn absorb_one(&mut self) -> bool {
                self.update(b"x").is_ok()
            }

            fn check_bits(&self, bits: u128) -> bool {
                self.check_additional_bits(bits).is_ok()
            }

            fn bits(&self) -> u128 {
                self.message_bits()
            }
        }
    };
}

wide_state!(Sha384);
wide_state!(Sha512);
wide_state!(Sha512_224);
wide_state!(Sha512_256);

fn check_wide_exhaustion(mut state: impl WideState) {
    assert!(state.absorb_one());
    assert!(state.check_bits(u128::MAX - 8));
    assert!(!state.check_bits(u128::MAX - 7));
    assert_eq!(state.bits(), 8);
}

fn check_sha224(input: BitString<'_>, message: &[u8], bits: usize, expected: &[u8]) -> bool {
    let actual = sha224_bits(input);
    assert!(actual.is_ok());
    if let Ok(actual) = actual {
        assert_eq!(actual.as_ref(), expected);
        if let Some((state, tail)) = split_stream(Sha224::new(), message, bits) {
            assert_eq!(state.finalize_bits(tail), Ok(actual));
            return true;
        }
    }
    false
}

fn check_sha256(input: BitString<'_>, message: &[u8], bits: usize, expected: &[u8]) -> bool {
    let actual = sha256_bits(input);
    assert!(actual.is_ok());
    if let Ok(actual) = actual {
        assert_eq!(actual.as_ref(), expected);
        if let Some((state, tail)) = split_stream(Sha256::new(), message, bits) {
            assert_eq!(state.finalize_bits(tail), Ok(actual));
            return true;
        }
    }
    false
}

fn check_sha384(input: BitString<'_>, message: &[u8], bits: usize, expected: &[u8]) -> bool {
    let actual = sha384_bits(input);
    assert!(actual.is_ok());
    if let Ok(actual) = actual {
        assert_eq!(actual.as_ref(), expected);
        if let Some((state, tail)) = split_stream(Sha384::new(), message, bits) {
            assert_eq!(state.finalize_bits(tail), Ok(actual));
            return true;
        }
    }
    false
}

fn check_sha512(input: BitString<'_>, message: &[u8], bits: usize, expected: &[u8]) -> bool {
    let actual = sha512_bits(input);
    assert!(actual.is_ok());
    if let Ok(actual) = actual {
        assert_eq!(actual.as_ref(), expected);
        if let Some((state, tail)) = split_stream(Sha512::new(), message, bits) {
            assert_eq!(state.finalize_bits(tail), Ok(actual));
            return true;
        }
    }
    false
}

fn check_sha512_224(input: BitString<'_>, message: &[u8], bits: usize, expected: &[u8]) -> bool {
    let actual = sha512_224_bits(input);
    assert!(actual.is_ok());
    if let Ok(actual) = actual {
        assert_eq!(actual.as_ref(), expected);
        if let Some((state, tail)) = split_stream(Sha512_224::new(), message, bits) {
            assert_eq!(state.finalize_bits(tail), Ok(actual));
            return true;
        }
    }
    false
}

fn check_sha512_256(input: BitString<'_>, message: &[u8], bits: usize, expected: &[u8]) -> bool {
    let actual = sha512_256_bits(input);
    assert!(actual.is_ok());
    if let Ok(actual) = actual {
        assert_eq!(actual.as_ref(), expected);
        if let Some((state, tail)) = split_stream(Sha512_256::new(), message, bits) {
            assert_eq!(state.finalize_bits(tail), Ok(actual));
            return true;
        }
    }
    false
}

trait ByteUpdate {
    fn absorb(&mut self, input: &[u8]) -> bool;
}

macro_rules! byte_update {
    ($state:ty) => {
        impl ByteUpdate for $state {
            fn absorb(&mut self, input: &[u8]) -> bool {
                self.update(input).is_ok()
            }
        }
    };
}

byte_update!(Sha224);
byte_update!(Sha256);
byte_update!(Sha384);
byte_update!(Sha512);
byte_update!(Sha512_224);
byte_update!(Sha512_256);

fn split_stream<'message, State: ByteUpdate>(
    mut state: State,
    message: &'message [u8],
    bit_len: usize,
) -> Option<(State, BitString<'message>)> {
    let complete_bytes = bit_len / 8;
    let prefix_len = complete_bytes / 2;
    let prefix = message.get(..prefix_len)?;
    let tail = message.get(prefix_len..)?;
    if !state.absorb(prefix) {
        return None;
    }
    let tail_bits = bit_len.saturating_sub(prefix_len.saturating_mul(8));
    canonical(tail, tail_bits).map(|bits| (state, bits))
}

fn canonical(bytes: &[u8], bit_len: usize) -> Option<BitString<'_>> {
    let valid = if bit_len == 0 {
        0
    } else {
        u8::try_from(bit_len.saturating_sub(1) % 8)
            .unwrap_or(7)
            .saturating_add(1)
    };
    BitString::new(bytes, valid).ok()
}

fn parse_usize(input: &str) -> Option<usize> {
    input.parse().ok()
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let [high, low] = pair else {
                return None;
            };
            Some(nibble(*high)?.wrapping_shl(4) | nibble(*low)?)
        })
        .collect()
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(value.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

fn _digest_type_guards(
    _: Sha224Digest,
    _: Sha256Digest,
    _: Sha384Digest,
    _: Sha512Digest,
    _: Sha512_224Digest,
    _: Sha512_256Digest,
) {
}
