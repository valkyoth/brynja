use crate::{BitString, Sha1Error, compress::compress, owner::Sha1Owner};

pub(crate) fn admit_bits(current: u64, additional: u64) -> Result<u64, Sha1Error> {
    current
        .checked_add(additional)
        .ok_or(Sha1Error::MessageTooLong)
}

pub(crate) fn admit_bytes(current: u64, additional: usize) -> Result<u64, Sha1Error> {
    let bytes = u64::try_from(additional).map_err(|_| Sha1Error::MessageTooLong)?;
    let bits = bytes.checked_mul(8).ok_or(Sha1Error::MessageTooLong)?;
    admit_bits(current, bits)
}

pub(crate) fn update(owner: &mut Sha1Owner, input: &[u8]) -> Result<(), Sha1Error> {
    let length = admit_bytes(owner.bits(), input.len())?;
    let mut input = input;
    while !input.is_empty() {
        let offset = owner.buffered();
        assert!(offset < owner.block.len(), "SHA-1 update offset invariant");
        let count = owner.block.len().saturating_sub(offset).min(input.len());
        let end = offset.checked_add(count).ok_or(Sha1Error::MessageTooLong)?;
        let source = input.get(..count).ok_or(Sha1Error::MessageTooLong)?;
        let destination = owner
            .block
            .get_mut(offset..end)
            .ok_or(Sha1Error::MessageTooLong)?;
        brynja_core::copy_secret_region(destination, source)
            .map_err(|_| Sha1Error::MessageTooLong)?;
        owner.buffered = [u8::try_from(end).map_err(|_| Sha1Error::MessageTooLong)?];
        if owner.buffered() == 64 {
            compress(owner);
        }
        input = input.get(count..).ok_or(Sha1Error::MessageTooLong)?;
    }
    owner.message_length = length.to_be_bytes();
    Ok(())
}

// Only consuming public operations reach finalization. A canonical partial
// byte is terminal; it cannot be followed by another update in safe Rust.
pub(crate) fn finish(owner: &mut Sha1Owner, tail: BitString<'_>) -> Result<(), Sha1Error> {
    let additional = u64::try_from(tail.bit_len()).map_err(|_| Sha1Error::MessageTooLong)?;
    let total = admit_bits(owner.bits(), additional)?;
    let (bytes, partial) = tail.split_borrowed();
    update(owner, bytes)?;
    finish_padding(owner, partial, total);
    Ok(())
}

pub(crate) fn finish_bytes(owner: &mut Sha1Owner) {
    finish_padding(owner, None, owner.bits());
}

fn finish_padding(owner: &mut Sha1Owner, partial: Option<(&u8, u8)>, total: u64) {
    let offset = owner.buffered();
    assert!(offset < owner.block.len(), "SHA-1 padding offset invariant");
    if let Some(destination) = owner.block.get_mut(offset) {
        match partial {
            Some((byte, valid)) => {
                // Equal one-byte borrows cannot fail the copy length check.
                let _ = brynja_core::copy_secret_region(
                    core::slice::from_mut(destination),
                    core::slice::from_ref(byte),
                );
                brynja_core::apply_secret_byte_mask(destination, 0xff, 0x80 >> valid);
            }
            None => *destination = 0x80,
        }
    }
    if offset >= 56 {
        compress(owner);
    }
    // The block was zero-initialized or cleared following each compression.
    // Emit the length without a separate secret-bearing byte array.
    for (destination, shift) in owner
        .block
        .iter_mut()
        .skip(56)
        .zip([56, 48, 40, 32, 24, 16, 8, 0])
    {
        *destination = u8::try_from((total >> shift) & 0xff).unwrap_or(0);
    }
    compress(owner);
    // The complete state and staging arrays have identical widths.
    let _ = brynja_core::copy_secret_region(&mut owner.output_staging, &owner.chaining_state);
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;

    #[test]
    fn invalid_update_offsets_trip_before_mutation() {
        for count in 64..=u8::MAX {
            let mut owner = Sha1Owner::new();
            owner.buffered = [count];
            let before = owner.chaining_state;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = update(&mut owner, &[0xa5]);
            }));
            assert!(result.is_err(), "invalid offset {count} was silent");
            assert_eq!(owner.chaining_state, before);
            assert_eq!(owner.block, [0; 64]);
            assert_eq!(owner.schedule, [0; 320]);
            assert_eq!(owner.buffered, [count]);
            assert_eq!(owner.bits(), 0);
        }
    }

    #[test]
    fn invalid_padding_offsets_trip_before_mutation() {
        for count in 64..=u8::MAX {
            for partial in [None, Some((&0xa0, 3))] {
                let mut owner = Sha1Owner::new();
                owner.buffered = [count];
                let before = owner.chaining_state;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    finish_padding(&mut owner, partial, 3);
                }));
                assert!(result.is_err(), "invalid offset {count} was silent");
                assert_eq!(owner.chaining_state, before);
                assert_eq!(owner.block, [0; 64]);
                assert_eq!(owner.schedule, [0; 320]);
                assert_eq!(owner.output_staging, [0; 20]);
                assert_eq!(owner.buffered, [count]);
            }
        }
    }

    #[test]
    fn every_valid_offset_survives_absorption_and_padding() {
        for length in 0..=128 {
            let mut owner = Sha1Owner::new();
            for _ in 0..length {
                assert_eq!(update(&mut owner, &[0xa5]), Ok(()));
                assert!(owner.buffered() < 64);
            }
            assert_eq!(owner.buffered(), length % 64);
            for valid in 0..8 {
                let mut padded = Sha1Owner::new();
                let input = [0xa5; 128];
                let input = input.get(..length).unwrap_or_default();
                assert_eq!(input.len(), length);
                assert_eq!(update(&mut padded, input), Ok(()));
                let total = padded.bits() + u64::from(valid);
                finish_padding(&mut padded, Some((&0, valid)), total);
                assert_eq!(padded.buffered(), 0);
            }
        }
    }

    #[test]
    fn borrowed_bulk_updates_match_single_bytes_at_every_boundary() -> Result<(), Sha1Error> {
        let input: [u8; 257] = core::array::from_fn(|i| u8::try_from(i % 251).unwrap_or(0));
        for length in 0..=input.len() {
            let bytes = input.get(..length).ok_or(Sha1Error::MessageTooLong)?;
            let mut expected = Sha1Owner::new();
            for byte in bytes {
                update(&mut expected, core::slice::from_ref(byte))?;
            }
            for chunk in [1, 2, 7, 31, 63, 64, 65, 128, 257] {
                let mut owner = Sha1Owner::new();
                for part in bytes.chunks(chunk) {
                    update(&mut owner, &[])?;
                    update(&mut owner, part)?;
                }
                assert_eq!(owner.chaining_state, expected.chaining_state);
                assert_eq!(owner.block, expected.block);
                assert_eq!(owner.buffered, expected.buffered);
                assert_eq!(owner.bits(), expected.bits());
                assert_eq!(owner.buffered(), length % 64);
                assert_eq!(owner.bits(), u64::try_from(length).unwrap_or(0) * 8);
            }
        }
        Ok(())
    }

    #[test]
    fn exhaustion_rejects_before_any_state_mutation() {
        let mut owner = Sha1Owner::new();
        owner.message_length = (u64::MAX - 7).to_be_bytes();
        let before = owner.chaining_state;
        assert_eq!(update(&mut owner, &[1]), Err(Sha1Error::MessageTooLong));
        assert_eq!(owner.bits(), u64::MAX - 7);
        assert_eq!(owner.chaining_state, before);
        assert_eq!(owner.block, [0; 64]);
        assert_eq!(owner.schedule, [0; 320]);
        assert_eq!(owner.buffered(), 0);
        assert_eq!(admit_bits(u64::MAX - 7, 7), Ok(u64::MAX));
        assert_eq!(admit_bits(u64::MAX, 1), Err(Sha1Error::MessageTooLong));
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn sha1_bit_exhaustion_matches_wide_arithmetic() {
        let current: u64 = kani::any();
        let additional: u64 = kani::any();
        let wide = u128::from(current) + u128::from(additional);
        assert_eq!(
            super::admit_bits(current, additional).is_ok(),
            wide <= u128::from(u64::MAX)
        );
        if let Ok(total) = super::admit_bits(current, additional) {
            assert_eq!(u128::from(total), wide);
        }
    }
}
