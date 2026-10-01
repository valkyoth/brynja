//! Version-sixteen public metadata decoder; never dereferences input addresses.
//! The native adapter must decode before copying payload and quarantine on
//! header/copy failure. This component is not itself an OS boundary.
use super::{Bits, Error, Owner};
pub const VERSION: u64 = 16;
pub const HEADER_BYTES: usize = 112;
pub const BEGIN: usize = 60;
pub const CUSTOM: usize = 61;
pub const CUSTOM_END: usize = 62;
pub const ITEM_BEGIN: usize = 63;
pub const FRAGMENT: usize = 64;
pub const ITEM_END: usize = 65;
pub const FINISH: usize = 66;
pub const SQUEEZE: usize = 67;
pub const EXPORT: usize = 68;
pub const REHASH: usize = 69;
pub const CANCEL: usize = 70;
pub struct Header {
    operation: usize,
    sequence: u64,
    identity: u64,
    length: usize,
    last: u8,
    source: usize,
    width: usize,
    terminal: bool,
    item_bits: u128,
    custom_bits: u128,
}
impl Header {
    pub fn decode(operation: usize, bytes: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        let mut words = [0_u64; 14];
        for (value, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *value = u64::from_le_bytes(bytes.try_into().map_err(|_| Error::Length)?);
        }
        let [
            version,
            sequence,
            identity,
            length,
            last,
            source,
            width,
            terminal,
            item_low,
            item_high,
            custom_low,
            custom_high,
            route,
            reserved,
        ] = words;
        let payload = matches!(operation, CUSTOM | FRAGMENT);
        let names = matches!(operation, BEGIN | EXPORT | REHASH);
        let shaped = matches!(operation, FINISH | SQUEEZE | EXPORT);
        if version != VERSION
            || route != 1
            || reserved != 0
            || !(BEGIN..=CANCEL).contains(&operation)
            || sequence == 0
            || length > 1024
            || width > 1024
            || last > 8
            || terminal > 1
            || (!payload && length != 0)
            || ((length == 0) != (source == 0))
            || (names && !(1..=4).contains(&identity))
            || (!names && identity != 0)
            || (!shaped && width != 0)
            || (operation != SQUEEZE && terminal != 0)
            || (operation != ITEM_BEGIN && (item_low != 0 || item_high != 0))
            || (!matches!(operation, BEGIN | REHASH) && (custom_low != 0 || custom_high != 0))
            || (!payload && !shaped && last != 0)
        {
            return Err(Error::Length);
        }
        if payload && ((length == 0 && last != 0) || (length != 0 && last == 0)) {
            return Err(Error::Bits);
        }
        if shaped && ((width == 0 && last != 0) || (width != 0 && last == 0)) {
            return Err(Error::Bits);
        }
        if operation == SQUEEZE && terminal == 0 && last != if width == 0 { 0 } else { 8 } {
            return Err(Error::Bits);
        }
        let source = usize::try_from(source).map_err(|_| Error::Length)?;
        let length = usize::try_from(length).map_err(|_| Error::Length)?;
        source.checked_add(length).ok_or(Error::Length)?;
        Ok(Self {
            operation,
            sequence,
            identity,
            length,
            source,
            last: u8::try_from(last).map_err(|_| Error::Bits)?,
            width: usize::try_from(width).map_err(|_| Error::Length)?,
            terminal: terminal != 0,
            item_bits: u128::from(item_low) | (u128::from(item_high) << 64),
            custom_bits: u128::from(custom_low) | (u128::from(custom_high) << 64),
        })
    }
    pub fn source(&self) -> usize {
        self.source
    }
    pub fn length(&self) -> usize {
        self.length
    }
    /// Only the trusted adapter may supply the copy seam. Only EXPORT calls it.
    pub fn execute(
        self,
        owner: &mut Owner<'_>,
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
        owner: &mut Owner<'_>,
        input: &[u8],
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        if input.len() != self.length {
            return Err(Error::Length);
        }
        let payload = matches!(self.operation, CUSTOM | FRAGMENT);
        let bits =
            Bits::new(input, if payload { self.last } else { 0 }).map_err(|_| Error::Bits)?;
        let n = self.sequence;
        match self.operation {
            BEGIN => owner.begin(n, self.identity, self.custom_bits),
            CUSTOM => owner.custom(n, bits),
            CUSTOM_END => owner.finish_custom(n),
            ITEM_BEGIN => owner.begin_item(n, self.item_bits),
            FRAGMENT => owner.fragment(n, bits),
            ITEM_END => owner.finish_item(n),
            FINISH => owner.finish(n, self.width, self.last),
            SQUEEZE => owner.squeeze(n, self.width, self.last, self.terminal),
            EXPORT => owner.export(n, self.identity, self.width, self.last, copy),
            REHASH => owner.rehash(n, self.identity, self.custom_bits),
            CANCEL => owner.cancel(n),
            _ => Err(Error::State),
        }
    }
}
