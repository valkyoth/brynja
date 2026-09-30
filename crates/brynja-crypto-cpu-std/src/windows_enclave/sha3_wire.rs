use super::Error;
#[derive(Clone, Copy, Default)]
pub(super) struct Request {
    pub op: usize,
    pub sequence: u64,
    pub algorithm: u64,
    pub last: u8,
    pub width: usize,
    pub terminal: bool,
    pub name_bits: u128,
    pub custom_bits: u128,
}
impl Request {
    pub fn header(self, input: &[u8]) -> Result<[u8; 96], Error> {
        let payload = matches!(self.op, 22 | 23 | 29 | 30);
        if !matches!(self.op, 21..=31)
            || self.sequence == 0
            || input.len() > 1024
            || self.width > 1024
            || self.last > 8
            || (!payload && !input.is_empty())
            || (!matches!(self.op, 21 | 24 | 25 | 28) && self.algorithm != 0)
            || (!matches!(self.op, 25 | 27) && self.width != 0)
            || (self.op != 27 && self.terminal)
            || (self.op != 28 && (self.name_bits != 0 || self.custom_bits != 0))
            || (!payload && !matches!(self.op, 25 | 27) && self.last != 0)
            || (payload
                && ((input.is_empty() && self.last != 0) || (!input.is_empty() && self.last == 0)))
            || (self.op == 22 && self.last != if input.is_empty() { 0 } else { 8 })
        {
            return Err(Error::Bounds);
        }
        let source = if input.is_empty() {
            0
        } else {
            input.as_ptr() as usize
        };
        source.checked_add(input.len()).ok_or(Error::Bounds)?;
        let (n, s) = (self.name_bits.to_le_bytes(), self.custom_bits.to_le_bytes());
        let mut header = [0; 96];
        for (word, bytes) in [
            7,
            self.sequence,
            self.algorithm,
            u64::try_from(input.len()).map_err(|_| Error::Bounds)?,
            u64::from(self.last),
            u64::try_from(source).map_err(|_| Error::Bounds)?,
            u64::try_from(self.width).map_err(|_| Error::Bounds)?,
            u64::from(self.terminal),
        ]
        .into_iter()
        .zip(header.chunks_exact_mut(8))
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        header
            .get_mut(64..80)
            .ok_or(Error::Bounds)?
            .copy_from_slice(&n);
        header
            .get_mut(80..96)
            .ok_or(Error::Bounds)?
            .copy_from_slice(&s);
        Ok(header)
    }
}
#[cfg(any(
    test,
    all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    )
))]
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
    if !matches!(operation, 21..=31)
        || length > 1024
        || (!matches!(operation, 22 | 23 | 29 | 30) && length != 0)
        || clear != 1
        || headers != 1
        || payloads != usize::from(length != 0)
        || exports != usize::from(operation == 25)
        || error != 0
        || !super::protocol::regions(low, [header, payload], [96, 1024])
    {
        return Err(Error::Protocol);
    }
    Ok(())
}
