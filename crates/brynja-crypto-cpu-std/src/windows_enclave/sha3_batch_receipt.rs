use super::Error;
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
    if !matches!(operation, 90..=99)
        || length > 1024
        || (!matches!(operation, 92 | 93 | 95 | 96) && length != 0)
        || clear != 1
        || headers != 1
        || payloads != usize::from(length != 0)
        || exports != usize::from(matches!(operation, 98))
        || error != 0
        || !super::protocol::regions(low, [header, payload], [288, 1024])
    {
        return Err(Error::Protocol);
    }
    Ok(())
}
