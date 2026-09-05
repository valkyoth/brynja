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
    for byte in input {
        let offset = owner.buffered();
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
pub(crate) fn finish(owner: &mut Sha1Owner, tail: BitString<'_>) -> Result<(), Sha1Error> {
    let additional = u64::try_from(tail.bit_len()).map_err(|_| Sha1Error::MessageTooLong)?;
    let total = admit_bits(owner.bits(), additional)?;
    let (bytes, partial) = tail.split();
    update(owner, bytes)?;
    finish_padding(owner, partial, total);
    Ok(())
}

pub(crate) fn finish_bytes(owner: &mut Sha1Owner) {
    finish_padding(owner, None, owner.bits());
}

fn finish_padding(owner: &mut Sha1Owner, partial: Option<(u8, u8)>, total: u64) {
    let (last, valid) = partial.unwrap_or((0, 0));
    let offset = owner.buffered();
    if let Some(destination) = owner.block.get_mut(offset) {
        *destination = last | (0x80_u8 >> valid);
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
    owner.output_staging.copy_from_slice(&owner.chaining_state);
}

#[cfg(test)]
mod tests {
    use super::*;

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
