//! Private version-fourteen AVX2 protocol, distinct from scalar version seven.
//! Decoding validates metadata before any OS payload copy; it never follows a
//! host pointer. Only explicit public export invokes the fixed copy-out seam.
use super::{Algorithm, Error, Fips202BitString, Operation, Owner};

pub const HEADER_BYTES: usize = 112;
pub struct Request {
    op: usize,
    sequence: u64,
    identity: u64,
    pub length: usize,
    pub source: usize,
    width: usize,
    last: u8,
    terminal: bool,
    name_bits: u128,
    custom_bits: u128,
}
impl Request {
    pub fn decode(op: usize, header: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        let mut words = [0; 14];
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
            width,
            terminal,
            nlow,
            nhigh,
            slow,
            shigh,
            route,
            reserved,
        ] = words;
        if version != 14 || route != 1 || reserved != 0 || sequence == 0 {
            return Err(Error::Identity);
        }
        if !matches!(op, 21..=31) || length > 1024 || width > 1024 {
            return Err(Error::Length);
        }
        if last > 8 || terminal > 1 {
            return Err(Error::Bits);
        }
        let length = usize::try_from(length).map_err(|_| Error::Length)?;
        let source = usize::try_from(source).map_err(|_| Error::Length)?;
        let width = usize::try_from(width).map_err(|_| Error::Length)?;
        let last = u8::try_from(last).map_err(|_| Error::Bits)?;
        if (source == 0) != (length == 0) || source.checked_add(length).is_none() {
            return Err(Error::Length);
        }
        let payload = matches!(op, 22 | 23 | 29 | 30);
        if !payload && length != 0 {
            return Err(Error::Length);
        }
        if matches!(op, 21 | 24 | 25 | 28) {
            let algorithm = Algorithm::decode(identity).map_err(|_| Error::Identity)?;
            if op == 28 && !matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256) {
                return Err(Error::Identity);
            }
        } else if identity != 0 {
            return Err(Error::Identity);
        }
        if (!matches!(op, 25 | 27) && width != 0) || (op != 27 && terminal != 0) {
            return Err(Error::Length);
        }
        if op != 28 && (nlow != 0 || nhigh != 0 || slow != 0 || shigh != 0) {
            return Err(Error::Length);
        }
        if !payload && !matches!(op, 25 | 27) && last != 0 {
            return Err(Error::Bits);
        }
        let bit_width = if payload { length } else { width };
        if (payload || matches!(op, 25 | 27))
            && ((bit_width == 0 && last != 0) || (bit_width != 0 && last == 0))
        {
            return Err(Error::Bits);
        }
        if op == 22 && last != if length == 0 { 0 } else { 8 } {
            return Err(Error::Bits);
        }
        Ok(Self {
            op,
            sequence,
            identity,
            length,
            source,
            width,
            last,
            terminal: terminal == 1,
            name_bits: u128::from(nlow) | (u128::from(nhigh) << 64),
            custom_bits: u128::from(slow) | (u128::from(shigh) << 64),
        })
    }

    /// `input` is the separately OS-copied snapshot, not the address in source.
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
        let empty = Fips202BitString::new(&[], 0).map_err(|_| Error::Bits)?;
        let result = match self.op {
            21 => guard
                .owner
                .begin(self.sequence, self.identity, empty, empty),
            22 => guard.owner.update(self.sequence, input),
            23 => guard.owner.finish(self.sequence, input, self.last),
            24 => guard
                .owner
                .rehash(self.sequence, self.identity, empty, empty),
            25 => {
                guard
                    .owner
                    .export_public(self.sequence, self.identity, self.width, self.last, copy)
            }
            26 => guard.owner.cancel(self.sequence),
            27 => guard
                .owner
                .squeeze(self.sequence, self.width, self.last, self.terminal),
            28 => guard.owner.setup(
                self.sequence,
                self.identity,
                self.name_bits,
                self.custom_bits,
            ),
            29 | 30 => guard
                .owner
                .setup_chunk(self.sequence, self.op == 29, input, self.last),
            31 => guard.owner.finish_setup(self.sequence),
            _ => Err(Error::Identity),
        };
        guard.complete = result.is_ok();
        result
    }
}
