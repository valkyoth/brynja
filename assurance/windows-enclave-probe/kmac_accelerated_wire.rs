//! Version-fifteen accelerated private worker wire protocol. Decode public metadata before
//! asking the OS to copy any payload. No raw pointer is dereferenced here.
use super::{Error, Owner};
use brynja_mac_kmac::Fips202BitString;

pub const VERSION: u64 = 15;
pub const HEADER_BYTES: usize = 112;
pub const BEGIN: usize = 40;
pub const CUSTOM: usize = 41;
pub const CUSTOM_END: usize = 42;
pub const KEY: usize = 43;
pub const SETUP_END: usize = 44;
pub const UPDATE: usize = 45;
pub const FINISH: usize = 46;
pub const SQUEEZE: usize = 47;
pub const EXPORT: usize = 48;
pub const VERIFY: usize = 49;
pub const REKEY: usize = 50;
pub const CANCEL: usize = 51;

pub struct Header {
    operation: usize,
    sequence: u64,
    identity: u64,
    length: usize,
    last: u8,
    source: usize,
    width: usize,
    terminal: bool,
    key_bits: u128,
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
            key_low,
            key_high,
            custom_low,
            custom_high,
            route,
            reserved,
        ] = words;
        let payload = matches!(operation, CUSTOM | KEY | UPDATE | FINISH | VERIFY);
        let names = matches!(operation, BEGIN | EXPORT | VERIFY | REKEY);
        let shaped = matches!(operation, FINISH | SQUEEZE | EXPORT);
        if version != VERSION
            || route != 1
            || reserved != 0
            || !(BEGIN..=CANCEL).contains(&operation)
            || sequence == 0
            || length > 1024
            || width > if operation == FINISH { 8192 } else { 1024 }
            || last > 8
            || terminal > 1
            || (!payload && length != 0)
            || (names && !(1..=4).contains(&identity))
            || (!names && identity != 0)
            || (!shaped && width != 0)
            || (operation != SQUEEZE && terminal != 0)
            || (operation != BEGIN && (key_low != 0 || key_high != 0))
            || (!matches!(operation, BEGIN | REKEY) && (custom_low != 0 || custom_high != 0))
            || (!payload && !shaped && last != 0)
            || ((length == 0) != (source == 0))
        {
            return Err(Error::Length);
        }
        // FINISH uses last for the input tail and width for the exact OUTPUT
        // BIT length. SQUEEZE/EXPORT instead use width bytes plus last bits.
        if payload && ((length == 0 && last != 0) || (length != 0 && last == 0)) {
            return Err(Error::Bits);
        }
        if operation == UPDATE && last != if length == 0 { 0 } else { 8 } {
            return Err(Error::Bits);
        }
        if matches!(operation, EXPORT | SQUEEZE)
            && ((width == 0 && last != 0) || (width != 0 && last == 0))
        {
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
            last: u8::try_from(last).map_err(|_| Error::Bits)?,
            source,
            width: usize::try_from(width).map_err(|_| Error::Length)?,
            terminal: terminal != 0,
            key_bits: u128::from(key_low) | (u128::from(key_high) << 64),
            custom_bits: u128::from(custom_low) | (u128::from(custom_high) << 64),
        })
    }
    pub fn source(&self) -> usize {
        self.source
    }
    pub fn length(&self) -> usize {
        self.length
    }
    /// Only the admitted worker adapter may supply this fixed OS-copy callback.
    /// VERIFY exports one explicit public decision byte, never retained bytes.
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
        let payload = matches!(self.operation, CUSTOM | KEY | UPDATE | FINISH | VERIFY);
        let bits = Fips202BitString::new(input, if payload { self.last } else { 0 })
            .map_err(|_| Error::Bits)?;
        let n = self.sequence;
        match self.operation {
            BEGIN => owner.begin_setup(n, self.identity, self.key_bits, self.custom_bits),
            CUSTOM => owner.customization(n, bits),
            CUSTOM_END => owner.finish_customization(n),
            KEY => owner.key(n, bits),
            SETUP_END => owner.finish_setup(n),
            UPDATE => owner.update(n, input),
            FINISH => owner.finish(
                n,
                bits,
                self.width.div_ceil(8),
                if self.width == 0 {
                    0
                } else {
                    u8::try_from(self.width.saturating_sub(1) % 8)
                        .map_err(|_| Error::Bits)?
                        .checked_add(1)
                        .ok_or(Error::Bits)?
                },
            ),
            SQUEEZE => owner.squeeze(n, self.width, self.last, self.terminal),
            EXPORT => owner.export(n, self.identity, self.width, self.last, copy),
            VERIFY => {
                let matched = owner.verify(n, self.identity, bits)?;
                if copy(&[u8::from(matched)]) {
                    Ok(())
                } else {
                    Err(Error::Copy)
                }
            }
            REKEY => owner.rekey_setup(n, self.identity, self.custom_bits),
            CANCEL => owner.cancel(n),
            _ => Err(Error::State),
        }
    }
}
