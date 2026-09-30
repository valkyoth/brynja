//! Public version-ten metadata shared with the worker parity fixture.
use super::Error;
#[derive(Clone, Copy, Default)]
pub(super) struct Request {
    pub op: usize,
    pub sequence: u64,
    pub slot: usize,
    pub last: u8,
    pub budget: u64,
    pub plan: [u64; 8],
}
impl Request {
    pub fn header(self, input: &[u8]) -> Result<[u8; 128], Error> {
        let payload = matches!(self.op, 82 | 83);
        let planned = matches!(self.op, 80 | 85);
        if !(80..=86).contains(&self.op)
            || self.sequence == 0
            || input.len() > 1024
            || self.slot >= 8
            || (!matches!(self.op, 81..=83) && self.slot != 0)
            || self.last > 8
            || (!payload && (!input.is_empty() || self.last != 0))
            || (payload && (input.is_empty() != (self.last == 0)))
            || (self.op == 82 && self.last != if input.is_empty() { 0 } else { 8 })
            || (self.op != 80 && self.budget != 0)
            || (!planned && self.plan != [0; 8])
            || (planned && self.plan == [0; 8])
        {
            return Err(Error::Bounds);
        }
        for identity in self.plan {
            if !matches!(identity, 0..=6 | 0x1001..=0x117f | 0x1181..=0x11ff) {
                return Err(Error::Bounds);
            }
        }
        let source = if input.is_empty() {
            0
        } else {
            input.as_ptr() as usize
        };
        source.checked_add(input.len()).ok_or(Error::Bounds)?;
        let mut words = [0_u64; 16];
        words.get_mut(..8).ok_or(Error::Bounds)?.copy_from_slice(&[
            10,
            self.sequence,
            u64::try_from(self.slot).map_err(|_| Error::Bounds)?,
            u64::try_from(input.len()).map_err(|_| Error::Bounds)?,
            u64::from(self.last),
            u64::try_from(source).map_err(|_| Error::Bounds)?,
            self.budget,
            0,
        ]);
        words
            .get_mut(8..)
            .ok_or(Error::Bounds)?
            .copy_from_slice(&self.plan);
        let mut header = [0; 128];
        for (word, chunk) in words.iter().zip(header.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Ok(header)
    }
    pub fn output_width(self) -> Option<usize> {
        if self.op == 85 { Some(512) } else { None }
    }
}
