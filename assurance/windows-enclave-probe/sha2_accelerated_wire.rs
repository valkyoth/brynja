//! Explicit version-thirteen SHA-NI protocol. No scalar or optional route flag.
use super::{Error, Operation, Owner, narrow};

pub struct Request {
    op: usize,
    sequence: u64,
    identity: u64,
    pub length: usize,
    pub source: usize,
    last: u8,
}
impl Request {
    pub fn decode(op: usize, header: &[u8; 64]) -> Result<Self, Error> {
        let mut words = [0; 8];
        for (word, bytes) in words.iter_mut().zip(header.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*bytes);
        }
        let [
            version,
            sequence,
            identity,
            length,
            last,
            source,
            route,
            reserved,
        ] = words;
        if version != 13 || route != 1 || reserved != 0 || sequence == 0 {
            return Err(Error::Identity);
        }
        if !matches!(op, 11..=16) || length > 1024 {
            return Err(Error::Length);
        }
        let length = usize::try_from(length).map_err(|_| Error::Length)?;
        let source = usize::try_from(source).map_err(|_| Error::Length)?;
        let last = u8::try_from(last).map_err(|_| Error::Bits)?;
        if (source == 0) != (length == 0) || source.checked_add(length).is_none() {
            return Err(Error::Length);
        }
        if matches!(op, 11 | 14 | 15) {
            narrow(identity)?;
        } else if identity != 0 {
            return Err(Error::Identity);
        }
        if !matches!(op, 12 | 13) && (length != 0 || last != 0) {
            return Err(Error::Length);
        }
        if op == 12 && last != if length == 0 { 0 } else { 8 } {
            return Err(Error::Bits);
        }
        if op == 13
            && if length == 0 {
                last != 0
            } else {
                !(1..=8).contains(&last)
            }
        {
            return Err(Error::Bits);
        }
        Ok(Self {
            op,
            sequence,
            identity,
            length,
            source,
            last,
        })
    }
    /// Payload must be the separately OS-copied bounded snapshot. This function
    /// never dereferences the untrusted address stored in `source`.
    pub fn execute(
        self,
        owner: &mut Owner<'_>,
        input: &[u8],
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        let mut guard = Operation {
            owner,
            complete: false,
        };
        if input.len() != self.length {
            return Err(Error::Length);
        }
        let result = match self.op {
            11 => guard.owner.begin(self.sequence, self.identity),
            12 => guard.owner.update(self.sequence, input),
            13 => guard.owner.finish(self.sequence, input, self.last),
            14 => guard.owner.rehash(self.sequence, self.identity),
            15 => guard
                .owner
                .export_public(self.sequence, self.identity, copy),
            16 => guard.owner.cancel(self.sequence),
            _ => Err(Error::Identity),
        };
        guard.complete = result.is_ok();
        result
    }
}
