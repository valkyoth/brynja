//! Version-twelve ParallelHash public metadata; no secret bytes in the header.
use super::Error;
#[derive(Clone, Copy, Default)]
pub(super) struct Request {
    pub op: usize,
    pub sequence: u64,
    pub algorithm: u64,
    pub block: u64,
    pub budget: u64,
    pub custom_bits: u128,
    pub last: u8,
    pub width: usize,
    pub output_last: u8,
    pub terminal: bool,
}
impl Request {
    pub fn header(self, input: &[u8]) -> Result<[u8; 112], Error> {
        let payload = matches!(self.op, 101 | 103 | 104);
        let begin = matches!(self.op, 100 | 108);
        let named = begin || self.op == 106;
        let shaped = matches!(self.op, 104..=106 | 108);
        if !(100..=108).contains(&self.op)
            || self.sequence == 0
            || input.len() > 1024
            || self.width > 1024
            || self.last > 8
            || self.output_last > 8
            || (!payload && (!input.is_empty() || self.last != 0))
            || (payload && (input.is_empty() != (self.last == 0)))
            || (self.op == 103 && self.last != if input.is_empty() { 0 } else { 8 })
            || (named && !(1..=4).contains(&self.algorithm))
            || (!named && self.algorithm != 0)
            || (begin && self.block == 0)
            || (!begin && (self.block != 0 || self.budget != 0 || self.custom_bits != 0))
            || (!shaped && (self.width != 0 || self.output_last != 0))
            || ((self.width == 0) != (self.output_last == 0))
            || (self.op != 105 && self.terminal)
            || (self.op == 105
                && !self.terminal
                && self.output_last != if self.width == 0 { 0 } else { 8 })
        {
            return Err(Error::Bounds);
        }
        let source = if input.is_empty() {
            0
        } else {
            input.as_ptr() as usize
        };
        source.checked_add(input.len()).ok_or(Error::Bounds)?;
        let mut header = [0; 112];
        for (word, bytes) in [
            12,
            self.sequence,
            self.algorithm,
            self.block,
            self.budget,
            0,
            0,
            u64::try_from(input.len()).map_err(|_| Error::Bounds)?,
            u64::from(self.last),
            u64::try_from(self.width).map_err(|_| Error::Bounds)?,
            u64::from(self.output_last),
            u64::from(self.terminal),
            u64::try_from(source).map_err(|_| Error::Bounds)?,
            0,
        ]
        .into_iter()
        .zip(header.chunks_exact_mut(8))
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        header
            .get_mut(40..56)
            .ok_or(Error::Bounds)?
            .copy_from_slice(&self.custom_bits.to_le_bytes());
        Ok(header)
    }
    pub fn output_width(self) -> Option<usize> {
        if self.op == 106 {
            Some(self.width)
        } else {
            None
        }
    }
}
