//! Actual version-eleven host encoder, shared with the isolated worker tests.
use super::Error;
#[derive(Clone, Copy, Default)]
pub(super) struct Request {
    pub op: usize,
    pub sequence: u64,
    pub slot: usize,
    pub last: u8,
    pub budget: u64,
    pub name_bits: u128,
    pub custom_bits: u128,
    pub plan: [[u64; 3]; 8],
}
impl Request {
    pub fn header(self, input: &[u8]) -> Result<[u8; 288], Error> {
        let payload = matches!(self.op, 92 | 93 | 95 | 96);
        let planned = matches!(self.op, 90 | 98);
        if !(90..=99).contains(&self.op)
            || self.sequence == 0
            || input.len() > 1024
            || self.slot >= 8
            || (!matches!(self.op, 91..=96) && self.slot != 0)
            || self.last > 8
            || (!payload && (!input.is_empty() || self.last != 0))
            || (payload && (input.is_empty() != (self.last == 0)))
            || (self.op == 95 && self.last != if input.is_empty() { 0 } else { 8 })
            || (self.op != 90 && self.budget != 0)
            || (self.op != 91 && (self.name_bits != 0 || self.custom_bits != 0))
            || (!planned && self.plan != [[0; 3]; 8])
        {
            return Err(Error::Bounds);
        }
        let mut width = 0_u64;
        let mut active = false;
        for [id, bytes, last] in self.plan {
            let fixed = match id {
                0 | 5..=8 => None,
                1 => Some(28),
                2 => Some(32),
                3 => Some(48),
                4 => Some(64),
                _ => return Err(Error::Bounds),
            };
            if (id == 0 && (bytes != 0 || last != 0))
                || bytes > 1024
                || last > 8
                || ((bytes == 0) != (last == 0))
                || fixed.is_some_and(|n| n != bytes || last != 8)
            {
                return Err(Error::Bounds);
            }
            width = width.checked_add(bytes).ok_or(Error::Bounds)?;
            active |= id != 0;
        }
        if planned && (!active || width > 1024) {
            return Err(Error::Bounds);
        }
        let source = if input.is_empty() {
            0
        } else {
            input.as_ptr() as usize
        };
        source.checked_add(input.len()).ok_or(Error::Bounds)?;
        let mut header = [0; 288];
        for (word, chunk) in [
            11,
            self.sequence,
            u64::try_from(self.slot).map_err(|_| Error::Bounds)?,
            u64::try_from(input.len()).map_err(|_| Error::Bounds)?,
            u64::from(self.last),
            u64::try_from(source).map_err(|_| Error::Bounds)?,
            self.budget,
            0,
        ]
        .iter()
        .zip(header.chunks_exact_mut(8))
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        header
            .get_mut(64..80)
            .ok_or(Error::Bounds)?
            .copy_from_slice(&self.name_bits.to_le_bytes());
        header
            .get_mut(80..96)
            .ok_or(Error::Bounds)?
            .copy_from_slice(&self.custom_bits.to_le_bytes());
        for (word, chunk) in self.plan.iter().flatten().zip(
            header
                .get_mut(96..)
                .ok_or(Error::Bounds)?
                .chunks_exact_mut(8),
        ) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Ok(header)
    }
    pub fn output_width(self) -> Option<usize> {
        if self.op == 98 { Some(1024) } else { None }
    }
}
