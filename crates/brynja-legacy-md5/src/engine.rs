use crate::{BitString, Md5Error, compress::compress, owner::Md5Owner};

pub(crate) fn admit_bits(current: u128, additional: u128) -> Result<u128, Md5Error> {
    current
        .checked_add(additional)
        .ok_or(Md5Error::MessageTooLong)
}

pub(crate) fn admit_bytes(current: u128, additional: usize) -> Result<u128, Md5Error> {
    let bytes = u128::try_from(additional).map_err(|_| Md5Error::MessageTooLong)?;
    let bits = bytes.checked_mul(8).ok_or(Md5Error::MessageTooLong)?;
    admit_bits(current, bits)
}

pub(crate) fn update(owner: &mut Md5Owner, input: &[u8]) -> Result<(), Md5Error> {
    let length = admit_bytes(owner.bits(), input.len())?;
    for byte in input {
        let offset = owner.buffered();
        assert!(offset < owner.block.len(), "MD5 update offset invariant");
        if let Some(destination) = owner.block.get_mut(offset) {
            *destination = *byte;
        }
        let [count] = &mut owner.buffered;
        *count = count.saturating_add(1);
        if owner.buffered() == 64 {
            compress(owner);
        }
    }
    owner.message_length = length.to_be_bytes();
    Ok(())
}

// Only consuming public operations reach finalization. A canonical partial
// byte is terminal; it cannot be followed by another update in safe Rust.
pub(crate) fn finish(owner: &mut Md5Owner, tail: BitString<'_>) -> Result<(), Md5Error> {
    let additional = u128::try_from(tail.bit_len()).map_err(|_| Md5Error::MessageTooLong)?;
    let total = admit_bits(owner.bits(), additional)?;
    let (bytes, partial) = tail.split();
    update(owner, bytes)?;
    finish_padding(owner, partial, total);
    Ok(())
}

pub(crate) fn finish_bytes(owner: &mut Md5Owner) {
    finish_padding(owner, None, owner.bits());
}

fn finish_padding(owner: &mut Md5Owner, partial: Option<(u8, u8)>, total: u128) {
    let (last, valid) = partial.unwrap_or((0, 0));
    let offset = owner.buffered();
    assert!(offset < owner.block.len(), "MD5 padding offset invariant");
    if let Some(destination) = owner.block.get_mut(offset) {
        *destination = last | (0x80_u8 >> valid);
    }
    if offset >= 56 {
        compress(owner);
    }
    // The block was zero-initialized or cleared following each compression.
    // RFC 1321 encodes only the low 64 bits, even beyond 2^64 bits.
    // Emit directly without a separate secret-bearing byte array.
    for (destination, shift) in owner
        .block
        .iter_mut()
        .skip(56)
        .zip([0, 8, 16, 24, 32, 40, 48, 56])
    {
        *destination = u8::try_from((total >> shift) & 0xff).unwrap_or(0);
    }
    compress(owner);
    owner.output_staging.copy_from_slice(&owner.chaining_state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_length_wrap_is_not_sha1_exhaustion() {
        let mut owner = Md5Owner::new();
        owner.message_length = (u128::from(u64::MAX) - 7).to_be_bytes();
        assert_eq!(update(&mut owner, &[0xa5]), Ok(()));
        assert_eq!(owner.bits(), 1_u128 << 64);
        assert_eq!(owner.buffered(), 1);
    }

    #[test]
    fn padding_encodes_low_64_bits_only_in_little_endian_order() {
        for length in [0, 1, 55, 56, 63, 64, 65] {
            for valid in 0..8 {
                let mut short = Md5Owner::new();
                let mut long = Md5Owner::new();
                for _ in 0..length {
                    assert_eq!(update(&mut short, &[0xa5]), Ok(()));
                    assert_eq!(update(&mut long, &[0xa5]), Ok(()));
                }
                let total = short.bits() + u128::from(valid);
                finish_padding(&mut short, Some((0, valid)), total);
                finish_padding(&mut long, Some((0, valid)), total + (1_u128 << 64));
                assert_eq!(short.output_staging, long.output_staging);
            }
        }
        // A second block is not needed: inspect the exact encoded word through
        // the independent public known answers, rather than infer byte order
        // solely from equivalent long/short counters.
        assert_eq!(
            crate::md5(b"abc"),
            Ok([
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72,
            ])
        );
    }

    extern crate std;

    #[test]
    fn invalid_update_offsets_trip_before_mutation() {
        for count in 64..=u8::MAX {
            let mut owner = Md5Owner::new();
            owner.buffered = [count];
            let before = owner.chaining_state;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = update(&mut owner, &[0xa5]);
            }));
            assert!(result.is_err(), "invalid offset {count} was silent");
            assert_eq!(owner.chaining_state, before);
            assert_eq!(owner.block, [0; 64]);
            assert_eq!(owner.buffered, [count]);
            assert_eq!(owner.bits(), 0);
        }
    }

    #[test]
    fn invalid_padding_offsets_trip_before_mutation() {
        for count in 64..=u8::MAX {
            for partial in [None, Some((0xa0, 3))] {
                let mut owner = Md5Owner::new();
                owner.buffered = [count];
                let before = owner.chaining_state;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    finish_padding(&mut owner, partial, 3);
                }));
                assert!(result.is_err(), "invalid offset {count} was silent");
                assert_eq!(owner.chaining_state, before);
                assert_eq!(owner.block, [0; 64]);
                assert_eq!(owner.output_staging, [0; 16]);
                assert_eq!(owner.buffered, [count]);
            }
        }
    }

    #[test]
    fn every_valid_offset_survives_absorption_and_padding() {
        for length in 0..=128 {
            let mut owner = Md5Owner::new();
            for _ in 0..length {
                assert_eq!(update(&mut owner, &[0xa5]), Ok(()));
                assert!(owner.buffered() < 64);
            }
            assert_eq!(owner.buffered(), length % 64);
            for valid in 0..8 {
                let mut padded = Md5Owner::new();
                let input = [0xa5; 128];
                let input = input.get(..length).unwrap_or_default();
                assert_eq!(input.len(), length);
                assert_eq!(update(&mut padded, input), Ok(()));
                let total = padded.bits() + u128::from(valid);
                finish_padding(&mut padded, Some((0, valid)), total);
                assert_eq!(padded.buffered(), 0);
            }
        }
    }

    #[test]
    fn exhaustion_rejects_before_any_state_mutation() {
        let mut owner = Md5Owner::new();
        owner.message_length = (u128::MAX - 7).to_be_bytes();
        let before = owner.chaining_state;
        assert_eq!(update(&mut owner, &[1]), Err(Md5Error::MessageTooLong));
        assert_eq!(owner.bits(), u128::MAX - 7);
        assert_eq!(owner.chaining_state, before);
        assert_eq!(owner.block, [0; 64]);
        assert_eq!(owner.buffered(), 0);
        assert_eq!(admit_bits(u128::MAX - 7, 7), Ok(u128::MAX));
        assert_eq!(admit_bits(u128::MAX, 1), Err(Md5Error::MessageTooLong));
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn md5_bit_exhaustion_matches_carry() {
        let current: u128 = kani::any();
        let additional: u128 = kani::any();
        let (sum, overflow) = current.overflowing_add(additional);
        let admitted = super::admit_bits(current, additional);
        assert_eq!(admitted.is_ok(), !overflow);
        if let Ok(total) = admitted {
            assert_eq!(total, sum);
        }
    }
}
