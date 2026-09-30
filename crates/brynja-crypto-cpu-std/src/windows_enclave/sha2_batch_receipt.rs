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
    if !matches!(operation, 80..=86)
        || length > 1024
        || (!matches!(operation, 82 | 83) && length != 0)
        || clear != 1
        || headers != 1
        || payloads != usize::from(length != 0)
        || exports != usize::from(matches!(operation, 85))
        || error != 0
        || !super::protocol::regions(low, [header, payload], [128, 1024])
    {
        return Err(Error::Protocol);
    }
    Ok(())
}
