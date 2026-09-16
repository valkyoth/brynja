//! Bounded public-vector parsing; not an application secret-input interface.
use crate::Result;
use brynja_hash_sha3::{
    Fips202BitString,
    hardened_batch::{Algorithm, Input},
};

pub struct Request {
    pub algorithm: Algorithm,
    message: Vec<u8>,
    name: Vec<u8>,
    custom: Vec<u8>,
    pub bits: [usize; 4],
}

fn bits(bytes: &[u8], n: usize) -> Result<Fips202BitString<'_>> {
    if bytes.len() != n.div_ceil(8) {
        return Err("length mismatch".into());
    }
    let valid = if n == 0 {
        0
    } else {
        u8::try_from((n - 1) % 8 + 1)?
    };
    Fips202BitString::new(bytes, valid).map_err(|e| format!("invalid bits: {e:?}").into())
}
fn hex(text: &str) -> Result<Vec<u8>> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if !text.is_ascii() || !text.len().is_multiple_of(2) || text.len() > 8192 {
        return Err("hex shape".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let s = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(s, 16)?)
        })
        .collect()
}
pub fn parse(text: &str) -> Result<Request> {
    let fields: Vec<_> = text.split_whitespace().collect();
    let [algorithm, m, n, s, o, message, name, custom] = fields.as_slice() else {
        return Err("field count".into());
    };
    let algorithm = match *algorithm {
        "sha3-224" => Algorithm::Sha3_224,
        "sha3-256" => Algorithm::Sha3_256,
        "sha3-384" => Algorithm::Sha3_384,
        "sha3-512" => Algorithm::Sha3_512,
        "shake128" => Algorithm::Shake128,
        "shake256" => Algorithm::Shake256,
        "cshake128" => Algorithm::Cshake128,
        "cshake256" => Algorithm::Cshake256,
        _ => return Err("unknown identity".into()),
    };
    let lengths: Vec<usize> = [m, n, s, o]
        .into_iter()
        .map(|value| value.parse())
        .collect::<std::result::Result<_, _>>()?;
    let [m, n, s, o] = lengths.as_slice() else {
        return Err("length count".into());
    };
    if [m, n, s, o].into_iter().any(|n| *n > 32768) {
        return Err("length bound".into());
    }
    Ok(Request {
        algorithm,
        message: hex(message)?,
        name: hex(name)?,
        custom: hex(custom)?,
        bits: [*m, *n, *s, *o],
    })
}
impl Request {
    pub fn input(&self) -> Result<Input<'_>> {
        let [m, n, s, o] = self.bits;
        Input::with_customization(
            self.algorithm,
            bits(&self.message, m)?,
            bits(&self.name, n)?,
            bits(&self.custom, s)?,
            o,
        )
        .map_err(|e| format!("request: {e:?}").into())
    }
}
