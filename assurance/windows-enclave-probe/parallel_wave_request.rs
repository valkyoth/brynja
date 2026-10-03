//! Private copied-input metadata, not a shipping wire ABI or pointer authority.
use super::Error;

pub const MAGIC: u64 = 0x4252_594e_5048_5749;
pub const HEADER_BYTES: usize = 128;

#[derive(Clone, Copy)]
pub struct Request {
    pub identity: u64,
    pub block: usize,
    pub input_bits: usize,
    pub custom_bits: usize,
    pub output_bits: usize,
    pub(super) input_source: usize,
    pub(super) custom_source: usize,
}

pub(super) fn width(bits: usize) -> Result<usize, Error> {
    (bits / 8)
        .checked_add(usize::from(!bits.is_multiple_of(8)))
        .ok_or(Error::Bounds)
}
pub(super) fn last(bits: usize) -> u8 {
    if bits == 0 {
        0
    } else {
        ((bits - 1) % 8 + 1) as u8
    }
}
pub(super) fn source(address: usize, length: usize) -> Result<(), Error> {
    if (length == 0) != (address == 0) {
        return Err(Error::Bounds);
    }
    address.checked_add(length).ok_or(Error::Bounds)?;
    Ok(())
}

impl Request {
    pub fn decode(header: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        let mut words = [0_u64; 16];
        for (word, bytes) in words.iter_mut().zip(header.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*bytes);
        }
        let [
            magic,
            version,
            identity,
            block,
            input_bits,
            custom_bits,
            output_bits,
            input_source,
            custom_source,
            route,
            r0,
            r1,
            r2,
            r3,
            r4,
            r5,
        ] = words;
        if magic != MAGIC
            || version != 1
            || !(1..=4).contains(&identity)
            || !(1..=1024).contains(&block)
            || custom_bits > 8192
            || output_bits > 8192
            || route != 1
            || [r0, r1, r2, r3, r4, r5] != [0; 6]
        {
            return Err(Error::Bounds);
        }
        let convert = |word| usize::try_from(word).map_err(|_| Error::Bounds);
        let block = convert(block)?;
        let input_bits = convert(input_bits)?;
        let custom_bits = convert(custom_bits)?;
        let output_bits = convert(output_bits)?;
        let input_source = convert(input_source)?;
        let custom_source = convert(custom_source)?;
        let limit = block
            .checked_mul(8)
            .and_then(|n| n.checked_mul(parallel_waves::MAX_LEAVES))
            .ok_or(Error::Bounds)?;
        if input_bits > limit {
            return Err(Error::Bounds);
        }
        source(input_source, width(input_bits)?)?;
        source(custom_source, width(custom_bits)?)?;
        Ok(Self {
            identity,
            block,
            input_bits,
            custom_bits,
            output_bits,
            input_source,
            custom_source,
        })
    }
}
