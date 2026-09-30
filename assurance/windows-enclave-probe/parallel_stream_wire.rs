//! Version-twelve copied metadata; validate before touching caller payload.
use super::{Bits, Error, Owner, shape};
pub const VERSION: u64 = 12;
pub const HEADER_BYTES: usize = 112;
pub const BEGIN: usize = 100;
pub const CUSTOM: usize = 101;
pub const SETUP: usize = 102;
pub const UPDATE: usize = 103;
pub const FINISH: usize = 104;
pub const SQUEEZE: usize = 105;
pub const EXPORT: usize = 106;
pub const CANCEL: usize = 107;
pub const REHASH: usize = 108;
pub struct Header {
    operation: usize,
    sequence: u64,
    identity: u64,
    block: u64,
    budget: u64,
    custom: u128,
    length: usize,
    last: u8,
    width: usize,
    output_last: u8,
    terminal: bool,
    source: usize,
}
impl Header {
    pub fn decode(operation: usize, bytes: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        let mut words = [0_u64; 14];
        for (value, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *value = u64::from_le_bytes(chunk.try_into().map_err(|_| Error::Length)?);
        }
        let [
            version,
            sequence,
            identity,
            block,
            budget,
            cl,
            ch,
            length,
            last,
            width,
            output_last,
            terminal,
            source,
            reserved,
        ] = words;
        let custom = u128::from(cl) | (u128::from(ch) << 64);
        let payload = matches!(operation, CUSTOM | UPDATE | FINISH);
        let sized = matches!(operation, FINISH | SQUEEZE | EXPORT | REHASH);
        if version != VERSION
            || !(BEGIN..=REHASH).contains(&operation)
            || sequence == 0
            || reserved != 0
            || length > 1024
            || width > 1024
            || last > 8
            || output_last > 8
            || terminal > 1
            || (payload && ((length == 0) != (last == 0)))
            || (!payload && (length != 0 || last != 0))
            || ((length == 0) != (source == 0))
            || (operation == UPDATE && last != if length == 0 { 0 } else { 8 })
            || (matches!(operation, BEGIN | EXPORT | REHASH) && !(1..=4).contains(&identity))
            || (!matches!(operation, BEGIN | EXPORT | REHASH) && identity != 0)
            || (matches!(operation, BEGIN | REHASH) && block == 0)
            || (!matches!(operation, BEGIN | REHASH) && (block != 0 || budget != 0 || custom != 0))
            || (!sized && (width != 0 || output_last != 0))
            || (operation != SQUEEZE && terminal != 0)
            || (operation == SQUEEZE
                && terminal == 0
                && output_last != if width == 0 { 0 } else { 8 })
        {
            return Err(Error::Length);
        }
        let length = usize::try_from(length).map_err(|_| Error::Length)?;
        let source = usize::try_from(source).map_err(|_| Error::Length)?;
        source.checked_add(length).ok_or(Error::Length)?;
        let width = usize::try_from(width).map_err(|_| Error::Length)?;
        let output_last = u8::try_from(output_last).map_err(|_| Error::Bits)?;
        shape(width, output_last)?;
        Ok(Self {
            operation,
            sequence,
            identity,
            block,
            budget,
            custom,
            length,
            last: u8::try_from(last).map_err(|_| Error::Bits)?,
            width,
            output_last,
            terminal: terminal == 1,
            source,
        })
    }
    pub fn source(&self) -> usize {
        self.source
    }
    pub fn length(&self) -> usize {
        self.length
    }
    pub fn execute(
        self,
        owner: &mut Owner,
        input: &[u8],
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        let mut guard = super::Operation {
            owner,
            complete: false,
        };
        let result = self.dispatch(guard.owner, input, copy);
        guard.complete = result.is_ok();
        result
    }
    fn dispatch(
        self,
        owner: &mut Owner,
        input: &[u8],
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        if input.len() != self.length {
            return Err(Error::Length);
        }
        let n = self.sequence;
        match self.operation {
            BEGIN => owner.begin(n, self.identity, self.block, self.custom, self.budget),
            CUSTOM => owner.custom(n, Bits::new(input, self.last).map_err(|_| Error::Bits)?),
            SETUP => owner.finish_custom(n),
            UPDATE => owner.update(n, input),
            FINISH => owner.finish(
                n,
                Bits::new(input, self.last).map_err(|_| Error::Bits)?,
                self.width,
                self.output_last,
            ),
            SQUEEZE => owner.squeeze(n, self.width, self.output_last, self.terminal),
            EXPORT => owner.export(n, self.identity, self.width, self.output_last, copy),
            CANCEL => owner.cancel(n),
            REHASH => owner.rehash(
                n,
                self.identity,
                self.block,
                self.custom,
                self.budget,
                (self.width, self.output_last),
            ),
            _ => Err(Error::State),
        }
    }
}
