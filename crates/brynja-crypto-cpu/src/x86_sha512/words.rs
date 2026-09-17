use crate::static_execution::Error;

pub(super) fn offset(base: usize, back: usize) -> Result<usize, Error> {
    base.checked_sub(back).ok_or(Error::InternalDomain)
}

#[cfg(feature = "hardened-execution")]
pub(super) fn read(bytes: &[u8], index: usize) -> Result<u64, Error> {
    bytes
        .as_chunks::<8>()
        .0
        .get(index)
        .copied()
        .map(u64::from_be_bytes)
        .ok_or(Error::InternalDomain)
}

#[cfg(feature = "hardened-execution")]
pub(super) fn write(bytes: &mut [u8], index: usize, value: u64) -> Result<(), Error> {
    let word = bytes
        .as_chunks_mut::<8>()
        .0
        .get_mut(index)
        .ok_or(Error::InternalDomain)?;
    *word = value.to_be_bytes();
    Ok(())
}

#[cfg(feature = "hardened-execution")]
pub(super) fn expand(schedule: &mut [u8; 640], block: &[u8; 128]) -> Result<(), Error> {
    schedule[..128].copy_from_slice(block);
    for index in 16..80 {
        let x = read(schedule, offset(index, 15)?)?;
        let y = read(schedule, offset(index, 2)?)?;
        let value = read(schedule, offset(index, 16)?)?
            .wrapping_add(x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7))
            .wrapping_add(read(schedule, offset(index, 7)?)?)
            .wrapping_add(y.rotate_right(19) ^ y.rotate_right(61) ^ (y >> 6));
        write(schedule, index, value)?;
    }
    Ok(())
}

#[cfg(feature = "hardened-execution")]
pub(super) fn round(chunk: usize) -> Result<usize, Error> {
    chunk
        .checked_mul(4)
        .filter(|base| base.checked_add(3).is_some_and(|last| last < 80))
        .ok_or(Error::InternalDomain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_sha512_offsets_reject_underflow() {
        assert_eq!(offset(16, 16), Ok(0));
        assert_eq!(offset(16, 17), Err(Error::InternalDomain));
        assert_eq!(offset(0, usize::MAX), Err(Error::InternalDomain));
    }

    #[test]
    #[cfg(feature = "hardened-execution")]
    fn dedicated_sha512_round_and_word_domains_fail_closed() -> Result<(), Error> {
        for chunk in 0..20 {
            assert_eq!(round(chunk)?, chunk * 4);
        }
        for chunk in [20, 21, usize::MAX / 4, usize::MAX] {
            assert_eq!(round(chunk), Err(Error::InternalDomain));
        }
        let mut bytes = [0xa5; 640];
        write(&mut bytes, 79, u64::MAX)?;
        assert_eq!(read(&bytes, 79)?, u64::MAX);
        let before = bytes;
        for index in [80, 81, usize::MAX] {
            assert_eq!(read(&bytes, index), Err(Error::InternalDomain));
            assert_eq!(write(&mut bytes, index, 0), Err(Error::InternalDomain));
            assert_eq!(bytes, before);
        }
        assert_eq!(read(&[0; 7], 0), Err(Error::InternalDomain));
        assert_eq!(write(&mut [0; 7], 0, 1), Err(Error::InternalDomain));
        Ok(())
    }
}
