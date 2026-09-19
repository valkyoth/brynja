use super::{Error, Executor};
use crate::{BitString, Sha1BackendError, Sha1Error, owner::Sha1Owner};

pub(super) fn update(
    owner: &mut Sha1Owner,
    mut input: &[u8],
    executor: &Executor,
) -> Result<(), Error> {
    let total = crate::engine::admit_bytes(owner.bits(), input.len())?;
    while !input.is_empty() {
        let offset = owner.buffered();
        let remaining = 64_usize
            .checked_sub(offset)
            .filter(|n| *n > 0)
            .ok_or(Sha1BackendError::Quarantined)?;
        let count = remaining.min(input.len());
        let end = offset
            .checked_add(count)
            .ok_or(Sha1BackendError::Quarantined)?;
        let source = input.get(..count).ok_or(Sha1BackendError::Quarantined)?;
        let destination = owner
            .block
            .get_mut(offset..end)
            .ok_or(Sha1BackendError::Quarantined)?;
        brynja_core::copy_secret_region(destination, source)
            .map_err(|_| Sha1BackendError::Quarantined)?;
        owner.buffered = [u8::try_from(end).map_err(|_| Sha1BackendError::Quarantined)?];
        if end == 64 {
            executor.compress(owner)?;
        }
        input = input.get(count..).ok_or(Sha1BackendError::Quarantined)?;
    }
    owner.message_length = total.to_be_bytes();
    Ok(())
}

pub(super) fn finish(
    owner: &mut Sha1Owner,
    tail: BitString<'_>,
    executor: &Executor,
) -> Result<(), Error> {
    let additional = u64::try_from(tail.bit_len()).map_err(|_| Sha1Error::MessageTooLong)?;
    let total = crate::engine::admit_bits(owner.bits(), additional)?;
    let (bytes, partial) = tail.split_borrowed();
    update(owner, bytes, executor)?;
    let offset = owner.buffered();
    let (last, valid) = partial.unwrap_or((&0, 0));
    if offset >= 64 || valid > 7 {
        return Err(Sha1BackendError::Quarantined.into());
    }
    let destination = owner
        .block
        .get_mut(offset)
        .ok_or(Sha1BackendError::Quarantined)?;
    brynja_core::copy_secret_region(
        core::slice::from_mut(destination),
        core::slice::from_ref(last),
    )
    .map_err(|_| Sha1BackendError::Quarantined)?;
    brynja_core::apply_secret_byte_mask(destination, 0xff, 0x80 >> valid);
    if offset >= 56 {
        executor.compress(owner)?;
    }
    for (byte, shift) in owner
        .block
        .iter_mut()
        .skip(56)
        .zip([56, 48, 40, 32, 24, 16, 8, 0])
    {
        *byte = u8::try_from((total >> shift) & 0xff).map_err(|_| Sha1BackendError::Quarantined)?;
    }
    executor.compress(owner)?;
    brynja_core::copy_secret_region(&mut owner.output_staging, &owner.chaining_state)
        .map_err(|_| Sha1BackendError::Quarantined)?;
    Ok(())
}
