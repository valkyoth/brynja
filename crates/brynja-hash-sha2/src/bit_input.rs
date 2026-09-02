pub(crate) fn checked_bit_length_u64(current_bytes: u64, additional_bits: u64) -> Result<u64, ()> {
    current_bytes
        .checked_mul(8)
        .and_then(|current_bits| current_bits.checked_add(additional_bits))
        .ok_or(())
}

pub(crate) fn checked_bit_length_u128(
    current_bytes: u128,
    additional_bits: u128,
) -> Result<u128, ()> {
    current_bytes
        .checked_mul(8)
        .and_then(|current_bits| current_bits.checked_add(additional_bits))
        .ok_or(())
}

pub(crate) fn begin_padding<const BLOCK_BYTES: usize>(
    buffer: &mut [u8; BLOCK_BYTES],
    buffer_len: usize,
    partial: Option<(u8, u8)>,
) {
    let marker = match partial {
        Some((byte, valid_bits)) => byte | (0x80_u8 >> valid_bits),
        None => 0x80,
    };
    if let Some(target) = buffer.get_mut(buffer_len) {
        *target = marker;
    }
    for byte in buffer.iter_mut().skip(buffer_len.saturating_add(1)) {
        *byte = 0;
    }
}

#[cfg(kani)]
mod proofs {
    use super::{checked_bit_length_u64, checked_bit_length_u128};

    #[kani::proof]
    fn narrow_length_matches_exact_bit_addition() {
        let bytes: u64 = kani::any();
        let bits: u64 = kani::any();
        let expected = bytes
            .checked_mul(8)
            .and_then(|current| current.checked_add(bits));
        assert_eq!(checked_bit_length_u64(bytes, bits).ok(), expected);
    }

    #[kani::proof]
    fn wide_length_matches_exact_bit_addition() {
        let bytes: u128 = kani::any();
        let bits: u128 = kani::any();
        let expected = bytes
            .checked_mul(8)
            .and_then(|current| current.checked_add(bits));
        assert_eq!(checked_bit_length_u128(bytes, bits).ok(), expected);
    }
}
