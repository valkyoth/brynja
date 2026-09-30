//! Version-ten metadata; validated before any caller payload is copied.
//! The fixed enclave adapter, not application code, owns the copy seam.
use super::{Algorithm, Error, Owner};
pub const VERSION: u64 = 10;
pub const HEADER_BYTES: usize = 128;
pub const BEGIN: usize = 80;
pub const START: usize = 81;
pub const UPDATE: usize = 82;
pub const FINISH: usize = 83;
pub const SEAL: usize = 84;
pub const EXPORT: usize = 85;
pub const CANCEL: usize = 86;
pub struct Header {
    operation: usize,
    sequence: u64,
    slot: usize,
    length: usize,
    last: u8,
    source: usize,
    budget: u64,
    plan: [u64; 8],
}
impl Header {
    pub fn decode(operation: usize, bytes: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        let mut words = [0_u64; 16];
        for (value, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *value = u64::from_le_bytes(bytes.try_into().map_err(|_| Error::Length)?);
        }
        let [
            version,
            sequence,
            slot,
            length,
            last,
            source,
            budget,
            reserved,
            a,
            b,
            c,
            d,
            e,
            f,
            g,
            h,
        ] = words;
        let plan = [a, b, c, d, e, f, g, h];
        let payload = matches!(operation, UPDATE | FINISH);
        let planned = matches!(operation, BEGIN | EXPORT);
        if version != VERSION
            || !(BEGIN..=CANCEL).contains(&operation)
            || sequence == 0
            || reserved != 0
            || length > 1024
            || last > 8
            || (!payload && (length != 0 || last != 0))
            || ((length == 0) != (source == 0))
            || (payload && ((length == 0) != (last == 0)))
            || (operation == UPDATE && last != if length == 0 { 0 } else { 8 })
            || (!matches!(operation, START | UPDATE | FINISH) && slot != 0)
            || slot >= 8
            || (operation != BEGIN && budget != 0)
            || (!planned && plan != [0; 8])
            || (planned && plan == [0; 8])
        {
            return Err(Error::Length);
        }
        for identity in plan {
            if identity != 0 {
                Algorithm::decode(identity)?;
            }
        }
        let source = usize::try_from(source).map_err(|_| Error::Length)?;
        let length = usize::try_from(length).map_err(|_| Error::Length)?;
        source.checked_add(length).ok_or(Error::Length)?;
        Ok(Self {
            operation,
            sequence,
            slot: usize::try_from(slot).map_err(|_| Error::Length)?,
            length,
            last: u8::try_from(last).map_err(|_| Error::Bits)?,
            source,
            budget,
            plan,
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
        copy: impl FnOnce(&[u8; 512]) -> bool,
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
        copy: impl FnOnce(&[u8; 512]) -> bool,
    ) -> Result<(), Error> {
        if input.len() != self.length {
            return Err(Error::Length);
        }
        let n = self.sequence;
        match self.operation {
            BEGIN => owner.begin(n, self.plan, self.budget),
            START => owner.start(n, self.slot),
            UPDATE => owner.update(n, self.slot, input),
            FINISH => owner.finish(n, self.slot, input, self.last),
            SEAL => owner.seal(n),
            EXPORT => owner.export(n, self.plan, copy),
            CANCEL => owner.cancel(n),
            _ => Err(Error::State),
        }
    }
}
