//! Private version-21 metadata. Decode every lane before copying any payload.
use sha256_simd::{Algorithm, Error};
pub const HEADER_BYTES: usize = 288;
pub const DIGEST: usize = 100;
pub const EXPORT: usize = 101;
pub const CANCEL: usize = 102;
pub struct Header {
    pub sequence: u64,
    pub budget: u64,
    pub plan: [Algorithm; 8],
    pub lengths: [usize; 8],
    pub last: [u8; 8],
    pub sources: [usize; 8],
}
fn algorithm(code: u64) -> Result<Algorithm, Error> {
    Ok(match code {
        224 => Algorithm::Sha224,
        256 => Algorithm::Sha256,
        _ => return Err(Error::Identity),
    })
}
impl Header {
    pub fn decode(operation: usize, bytes: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        let mut words = [0_u64; 36];
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().map_err(|_| Error::Length)?);
        }
        if words[0] != 21
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
            plan: [Algorithm::Sha256; 8],
            lengths: [0; 8],
            last: [0; 8],
            sources: [0; 8],
        };
        for (lane, fields) in words[4..].chunks_exact(4).enumerate() {
            let [identity, length, last, source] =
                <[u64; 4]>::try_from(fields).map_err(|_| Error::Length)?;
            if operation == CANCEL {
                if fields != [0; 4] {
                    return Err(Error::State);
                }
                continue;
            }
            result.plan[lane] = algorithm(identity)?;
            if operation == EXPORT {
                if length != 0 || last != 0 || source != 0 {
                    return Err(Error::Length);
                }
                continue;
            }
            // Every lane must contain a complete block: no portable-only group.
            if !(64..=1024).contains(&length)
                || !(1..=8).contains(&last)
                || (length == 64 && last != 8)
                || source == 0
            {
                return Err(Error::Length);
            }
            let length = usize::try_from(length).map_err(|_| Error::Length)?;
            let source = usize::try_from(source).map_err(|_| Error::Length)?;
            source.checked_add(length).ok_or(Error::Length)?;
            result.lengths[lane] = length;
            result.last[lane] = u8::try_from(last).map_err(|_| Error::Bits)?;
            result.sources[lane] = source;
        }
        Ok(result)
    }
}
