//! Version-seventeen request metadata, validated before copying caller payload.
//! Only the fixed enclave OS-copy adapter may supply the export seam.
use super::{Error, Owner, Slot};

pub const VERSION: u64 = 17;
pub const HEADER_BYTES: usize = 304;
pub const BEGIN: usize = 90;
pub const START: usize = 91;
pub const NAME: usize = 92;
pub const CUSTOM: usize = 93;
pub const SETUP: usize = 94;
pub const UPDATE: usize = 95;
pub const FINISH: usize = 96;
pub const SEAL: usize = 97;
pub const EXPORT: usize = 98;
pub const CANCEL: usize = 99;

pub struct Header {
    operation: usize,
    sequence: u64,
    slot: usize,
    length: usize,
    last: u8,
    source: usize,
    budget: u64,
    name: u128,
    custom: u128,
    plan: [Slot; 8],
}
impl Header {
    pub fn decode(operation: usize, bytes: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        let mut words = [0_u64; 38];
        for (value, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *value = u64::from_le_bytes(chunk.try_into().map_err(|_| Error::Length)?);
        }
        let metadata: [u64; 12] = words
            .get(..12)
            .ok_or(Error::Length)?
            .try_into()
            .map_err(|_| Error::Length)?;
        let [
            version,
            sequence,
            slot,
            length,
            last,
            source,
            budget,
            reserved,
            nl,
            nh,
            sl,
            sh,
        ] = metadata;
        let name = u128::from(nl) | (u128::from(nh) << 64);
        let custom = u128::from(sl) | (u128::from(sh) << 64);
        let mut plan = [Slot::default(); 8];
        for (slot, triple) in plan
            .iter_mut()
            .zip(words.get(12..36).ok_or(Error::Length)?.chunks_exact(3))
        {
            let [identity, width, last]: [u64; 3] = triple.try_into().map_err(|_| Error::Length)?;
            *slot = Slot {
                identity,
                width: usize::try_from(width).map_err(|_| Error::Length)?,
                last: u8::try_from(last).map_err(|_| Error::Bits)?,
            };
            slot.validate()?;
        }
        let payload = matches!(operation, NAME | CUSTOM | UPDATE | FINISH);
        let planned = matches!(operation, BEGIN | EXPORT);
        if words.get(36) != Some(&1)
            || words.get(37) != Some(&0)
            || version != VERSION
            || !(BEGIN..=CANCEL).contains(&operation)
            || sequence == 0
            || reserved != 0
            || length > 1024
            || last > 8
            || (!payload && (length != 0 || last != 0))
            || ((length == 0) != (source == 0))
            || (payload && ((length == 0) != (last == 0)))
            || (operation == UPDATE && last != if length == 0 { 0 } else { 8 })
            || (!matches!(operation, START | NAME | CUSTOM | SETUP | UPDATE | FINISH) && slot != 0)
            || slot >= 8
            || (operation != BEGIN && budget != 0)
            || (operation != START && (name != 0 || custom != 0))
            || (!planned && plan != [Slot::default(); 8])
        {
            return Err(Error::Length);
        }
        if planned {
            Owner::validate_plan(&plan)?;
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
            name,
            custom,
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
        owner: &mut Owner<'_>,
        input: &[u8],
        copy: impl FnOnce(&[u8; 1024]) -> bool,
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
        copy: impl FnOnce(&[u8; 1024]) -> bool,
    ) -> Result<(), Error> {
        if input.len() != self.length {
            return Err(Error::Length);
        }
        let n = self.sequence;
        match self.operation {
            BEGIN => owner.begin(n, self.plan, self.budget),
            START => owner.start(n, self.slot, self.name, self.custom),
            NAME | CUSTOM => {
                owner.setup_chunk(n, self.slot, self.operation == NAME, input, self.last)
            }
            SETUP => owner.finish_setup(n, self.slot),
            UPDATE => owner.update(n, self.slot, input),
            FINISH => owner.finish(n, self.slot, input, self.last),
            SEAL => owner.seal(n),
            EXPORT => owner.export(n, self.plan, copy),
            CANCEL => owner.cancel(n),
            _ => Err(Error::State),
        }
    }
}
