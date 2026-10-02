//! Private version-22 metadata; validate the whole request before payload copies.
use keccak_simd::{Algorithm, Error, Slot};
pub const HEADER_BYTES: usize = 384;
pub const DIGEST: usize = 100;
pub const EXPORT: usize = 101;
pub const CANCEL: usize = 102;
pub struct Header {
    pub sequence: u64,
    pub budget: u64,
    pub plan: [Slot; 4],
    // Three sources per lane, in message/name/customization order.
    pub lengths: [usize; 12],
    pub last: [u8; 12],
    pub sources: [usize; 12],
}
fn algorithm(code: u64) -> Result<Algorithm, Error> {
    Ok(match code {
        1 => Algorithm::Sha3_224,
        2 => Algorithm::Sha3_256,
        3 => Algorithm::Sha3_384,
        4 => Algorithm::Sha3_512,
        5 => Algorithm::Shake128,
        6 => Algorithm::Shake256,
        7 => Algorithm::Cshake128,
        8 => Algorithm::Cshake256,
        _ => return Err(Error::Identity),
    })
}
impl Header {
    pub fn decode(operation: usize, bytes: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        let mut words = [0_u64; 48];
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().map_err(|_| Error::Length)?);
        }
        if words[0] != 22
            || words[1] == 0
            || words[3] != 2
            || !matches!(operation, DIGEST | EXPORT | CANCEL)
            || (operation != DIGEST && words[2] != 0)
        {
            return Err(Error::State);
        }
        let mut result = Self {
            sequence: words[1],
            budget: words[2],
            plan: [Slot {
                identity: Algorithm::Sha3_256,
                output_bits: 256,
            }; 4],
            lengths: [0; 12],
            last: [0; 12],
            sources: [0; 12],
        };
        for (lane, fields) in words[4..].chunks_exact(11).enumerate() {
            if operation == CANCEL {
                if fields != [0; 11] {
                    return Err(Error::State);
                }
                continue;
            }
            let identity = algorithm(fields[0])?;
            let output_bits = usize::try_from(fields[1]).map_err(|_| Error::Length)?;
            if output_bits > 2048
                || identity
                    .fixed_output_bits()
                    .is_some_and(|bits| bits != output_bits)
            {
                return Err(Error::Length);
            }
            result.plan[lane] = Slot {
                identity,
                output_bits,
            };
            for (part, values) in fields[2..].chunks_exact(3).enumerate() {
                let [length, last, source] =
                    <[u64; 3]>::try_from(values).map_err(|_| Error::Length)?;
                if operation == EXPORT || length == 0 {
                    if values != [0; 3] {
                        return Err(Error::Length);
                    }
                    continue;
                }
                if length > 1024
                    || !(1..=8).contains(&last)
                    || source == 0
                    || (part != 0
                        && !matches!(identity, Algorithm::Cshake128 | Algorithm::Cshake256))
                {
                    return Err(Error::Length);
                }
                let index = lane * 3 + part; // Bounded by the fixed chunks above.
                let length = usize::try_from(length).map_err(|_| Error::Length)?;
                let source = usize::try_from(source).map_err(|_| Error::Length)?;
                source.checked_add(length).ok_or(Error::Length)?;
                result.lengths[index] = length;
                result.last[index] = u8::try_from(last).map_err(|_| Error::Bits)?;
                result.sources[index] = source;
            }
        }
        Ok(result)
    }
}
