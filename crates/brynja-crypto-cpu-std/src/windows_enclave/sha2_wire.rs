use super::Error;

pub(super) fn header(
    sequence: u64,
    algorithm: u64,
    input: &[u8],
    last: u8,
) -> Result<[u8; 48], Error> {
    if sequence == 0
        || input.len() > 1024
        || last > 8
        || (input.is_empty() && last != 0)
        || (!input.is_empty() && last == 0)
    {
        return Err(Error::Bounds);
    }
    let source = if input.is_empty() {
        0
    } else {
        input.as_ptr() as usize
    };
    source.checked_add(input.len()).ok_or(Error::Bounds)?;
    let mut bytes = [0; 48];
    for (word, destination) in [
        6,
        sequence,
        algorithm,
        u64::try_from(input.len()).map_err(|_| Error::Bounds)?,
        u64::from(last),
        u64::try_from(source).map_err(|_| Error::Bounds)?,
    ]
    .into_iter()
    .zip(bytes.chunks_exact_mut(8))
    {
        destination.copy_from_slice(&word.to_le_bytes());
    }
    Ok(bytes)
}

pub(super) fn receipt(
    low: usize,
    operation: usize,
    length: usize,
    value: [usize; 7],
) -> Result<(), Error> {
    if matches!(operation, 0 | 3) {
        return if value == [0; 7] {
            Ok(())
        } else {
            Err(Error::Protocol)
        };
    }
    let [header, payload, clear, headers, payloads, exports, error] = value;
    if !matches!(operation, 11..=16)
        || length > 1024
        || (!matches!(operation, 12 | 13) && length != 0)
        || clear != 1
        || headers != 1
        || payloads != usize::from(length != 0)
        || exports != usize::from(operation == 15)
        || error != 0
        || !super::protocol::regions(low, [header, payload], [48, 1024])
    {
        return Err(Error::Protocol);
    }
    Ok(())
}
