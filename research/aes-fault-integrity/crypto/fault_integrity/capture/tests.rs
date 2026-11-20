use super::*;

#[test]
fn exact_captures_cover_lengths_alignments_and_canaries() -> Result<(), Error> {
    let mut input = [0; 80];
    for (byte, value) in input.iter_mut().zip(0u8..80) {
        *byte = value;
    }
    for offset in 0usize..16 {
        for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 24, 31, 32, 33, 48] {
            let mut first = [0x91; 80];
            let mut second = [0x92; 80];
            let end = offset.checked_add(len).ok_or(Error::SecretMemory)?;
            let source = input.get(offset..end).ok_or(Error::SecretMemory)?;
            pair(
                source,
                first.get_mut(offset..end).ok_or(Error::SecretMemory)?,
                second.get_mut(offset..end).ok_or(Error::SecretMemory)?,
            )?;
            assert_eq!(first.get(offset..end), Some(source));
            assert_eq!(second.get(offset..end), Some(source));
            assert!(
                first
                    .get(..offset)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .chain(first.get(end..).ok_or(Error::SecretMemory)?)
                    .all(|v| *v == 0x91)
            );
            assert!(
                second
                    .get(..offset)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .chain(second.get(end..).ok_or(Error::SecretMemory)?)
                    .all(|v| *v == 0x92)
            );
        }
    }
    Ok(())
}

#[test]
fn inconsistent_lengths_reject_before_either_write() {
    for (first_len, second_len) in [(15, 16), (16, 15), (17, 16), (16, 17)] {
        let mut first = [0x91; 17];
        let mut second = [0x92; 17];
        if let (Some(a), Some(b)) = (first.get_mut(..first_len), second.get_mut(..second_len)) {
            assert!(pair(&[0x42; 16], a, b).is_err());
        }
        assert_eq!(first, [0x91; 17]);
        assert_eq!(second, [0x92; 17]);
    }
}

#[test]
fn disjoint_borrows_in_one_allocation_are_supported() -> Result<(), Error> {
    let mut allocation = [0x42; 48];
    let (input, outputs) = allocation.split_at_mut(16);
    let (first, second) = outputs.split_at_mut(16);
    first.fill(0x91);
    second.fill(0x92);
    pair(input, first, second)?;
    assert_eq!(allocation, [0x42; 48]);
    Ok(())
}
