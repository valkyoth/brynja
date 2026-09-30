//! Candidate host encoder; not yet integrated into the shipping session API.
//! Version-nine TupleHash metadata. No secret bytes are stored in this header.
use super::Error;
#[derive(Clone, Copy, Default)]
pub(super) struct Request {
    pub op: usize,
    pub sequence: u64,
    pub algorithm: u64,
    pub last: u8,
    /// Output bytes, including a possible partial final byte.
    pub width: usize,
    pub terminal: bool,
    pub item_bits: u128,
    pub custom_bits: u128,
}
impl Request {
    pub fn header(self, input: &[u8]) -> Result<[u8; 96], Error> {
        let payload = matches!(self.op, 61 | 64);
        let named = matches!(self.op, 60 | 68 | 69);
        let shaped = matches!(self.op, 66..=68);
        if !(60..=70).contains(&self.op)
            || self.sequence == 0
            || input.len() > 1024
            || self.width > 1024
            || self.last > 8
            || (!payload && !input.is_empty())
            || (named && !(1..=4).contains(&self.algorithm))
            || (!named && self.algorithm != 0)
            || (!shaped && self.width != 0)
            || (self.op != 67 && self.terminal)
            || (self.op != 63 && self.item_bits != 0)
            || (!matches!(self.op, 60 | 69) && self.custom_bits != 0)
            || (!payload && !shaped && self.last != 0)
            || (payload && (input.is_empty() != (self.last == 0)))
            || (shaped && ((self.width == 0) != (self.last == 0)))
            || (self.op == 67 && !self.terminal && self.last != if self.width == 0 { 0 } else { 8 })
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
            9,
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
            .copy_from_slice(&self.item_bits.to_le_bytes());
        header
            .get_mut(80..96)
            .ok_or(Error::Bounds)?
            .copy_from_slice(&self.custom_bits.to_le_bytes());
        Ok(header)
    }
    pub fn output_width(self) -> Option<usize> {
        if self.op == 68 {
            Some(self.width)
        } else {
            None
        }
    }
}
