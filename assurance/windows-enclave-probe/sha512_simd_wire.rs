//! Private version-20 metadata. Decode every lane before copying any payload.
use sha512_simd::{Algorithm, Error};
pub const HEADER_BYTES: usize = 160;
pub const DIGEST: usize = 90;
pub const EXPORT: usize = 91;
pub const CANCEL: usize = 92;
pub struct Header {
    pub sequence: u64,
    pub budget: u64,
    pub plan: [Algorithm; 4],
    pub lengths: [usize; 4],
    pub last: [u8; 4],
    pub sources: [usize; 4],
}
fn algorithm(code: u64) -> Result<Algorithm, Error> {
    Ok(match code {
        512 => Algorithm::Sha384,
        513 => Algorithm::Sha512,
        514 => Algorithm::Sha512_224,
        515 => Algorithm::Sha512_256,
        1..=511 => Algorithm::Sha512T(
            brynja_hash_sha2::Sha512TBits::new(u16::try_from(code).map_err(|_| Error::Identity)?)
                .map_err(|_| Error::Identity)?,
        ),
        _ => return Err(Error::Identity),
    })
}
impl Header {
    pub fn decode(operation: usize, bytes: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        let mut words = [0_u64; 20];
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().map_err(|_| Error::Length)?);
        }
        if words[0] != 20
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
            plan: [Algorithm::Sha512; 4],
            lengths: [0; 4],
            last: [0; 4],
            sources: [0; 4],
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
            if !(128..=1024).contains(&length)
                || !(1..=8).contains(&last)
                || (length == 128 && last != 8)
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
