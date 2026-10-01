use super::Error;
#[derive(Clone, Copy, Default)]
pub(super) struct Request {
    pub op: usize,
    pub sequence: u64,
    pub algorithm: u64,
    pub last: u8,
    /// FINISH: exact output bits; SQUEEZE/EXPORT: bytes.
    pub width: usize,
    pub terminal: bool,
    pub key_bits: u128,
    pub custom_bits: u128,
}
impl Request {
    pub fn header(self, input: &[u8]) -> Result<[u8; 96], Error> {
        let payload = matches!(self.op, 41 | 43 | 45 | 46 | 49);
        let names = matches!(self.op, 40 | 48 | 49 | 50);
        if !matches!(self.op, 40..=51)
            || self.sequence == 0
            || input.len() > 1024
            || self.width > if self.op == 46 { 8192 } else { 1024 }
            || self.last > 8
            || (!payload && !input.is_empty())
            || (names && !(1..=4).contains(&self.algorithm))
            || (!names && self.algorithm != 0)
            || (!matches!(self.op, 46..=48) && self.width != 0)
            || (self.op != 47 && self.terminal)
            || (self.op != 40 && self.key_bits != 0)
            || (!matches!(self.op, 40 | 50) && self.custom_bits != 0)
            || (!payload && !matches!(self.op, 47 | 48) && self.last != 0)
            || (payload
                && ((input.is_empty() && self.last != 0) || (!input.is_empty() && self.last == 0)))
            || (self.op == 45 && self.last != if input.is_empty() { 0 } else { 8 })
            || (matches!(self.op, 47 | 48)
                && ((self.width == 0 && self.last != 0) || (self.width != 0 && self.last == 0)))
        {
            return Err(Error::Bounds);
        }
        let source = if input.is_empty() {
            0
        } else {
            input.as_ptr() as usize
        };
        source.checked_add(input.len()).ok_or(Error::Bounds)?;
        let mut header = [0; 96];
        for (word, bytes) in [
            8,
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
            .copy_from_slice(&self.key_bits.to_le_bytes());
        header
            .get_mut(80..96)
            .ok_or(Error::Bounds)?
            .copy_from_slice(&self.custom_bits.to_le_bytes());
        Ok(header)
    }
    pub fn output_width(self) -> Option<usize> {
        match self.op {
            48 => Some(self.width),
            49 => Some(1),
            _ => None,
        }
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
    receipt_width(low, operation, length, value, 96)
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
pub(super) fn receipt_width(
    low: usize,
    operation: usize,
    length: usize,
    value: [usize; 7],
    header_bytes: usize,
) -> Result<(), Error> {
    if matches!(operation, 0 | 3) {
        return if value == [0; 7] {
            Ok(())
        } else {
            Err(Error::Protocol)
        };
    }
    let [header, payload, clear, headers, payloads, exports, error] = value;
    if !matches!(operation, 40..=51)
        || length > 1024
        || (!matches!(operation, 41 | 43 | 45 | 46 | 49) && length != 0)
        || clear != 1
        || headers != 1
        || payloads != usize::from(length != 0)
        || exports != usize::from(matches!(operation, 48 | 49))
        || error != 0
        || !super::protocol::regions(low, [header, payload], [header_bytes, 1024])
    {
        return Err(Error::Protocol);
    }
    Ok(())
}
