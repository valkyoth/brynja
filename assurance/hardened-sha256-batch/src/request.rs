//! Bounded public test-vector protocol, never a secret-input application.
use brynja_hash_sha2::{
    BitString,
    hardened_batch::{Algorithm, Input},
};

pub struct Request {
    bytes: [Vec<u8>; 8],
    pub metadata: [Option<(Algorithm, usize)>; 8],
}

impl Request {
    pub fn parse(line: &[u8]) -> Result<Self, String> {
        if line.len() > 66_000 {
            return Err("campaign bound".into());
        }
        let text = std::str::from_utf8(line)
            .map_err(|e| e.to_string())?
            .trim_end();
        let slots: Vec<_> = text.split(';').collect();
        if slots.len() != 8 {
            return Err("exactly eight slots required".into());
        }
        let mut request = Self {
            bytes: core::array::from_fn(|_| Vec::new()),
            metadata: [None; 8],
        };
        for ((slot, bytes), meta) in slots
            .iter()
            .zip(&mut request.bytes)
            .zip(&mut request.metadata)
        {
            if *slot == "-" {
                continue;
            }
            let parts: Vec<_> = slot.split(':').collect();
            let [algorithm, bits, hex] = parts.as_slice() else {
                return Err("invalid slot".into());
            };
            let algorithm = match *algorithm {
                "sha224" => Algorithm::Sha224,
                "sha256" => Algorithm::Sha256,
                _ => return Err("identity".into()),
            };
            let bits = bits.parse::<usize>().map_err(|e| e.to_string())?;
            if bits > 32768 || hex.len() > 8192 || hex.len() % 2 != 0 || !hex.is_ascii() {
                return Err("input bound/encoding".into());
            }
            for pair in hex.as_bytes().as_chunks::<2>().0 {
                let pair = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
                bytes.push(u8::from_str_radix(pair, 16).map_err(|e| e.to_string())?);
            }
            if bits.div_ceil(8) != bytes.len() {
                return Err("length mismatch".into());
            }
            *meta = Some((algorithm, bits));
        }
        Ok(request)
    }

    pub fn inputs(&self) -> Result<[Option<Input<'_>>; 8], String> {
        let mut inputs = [None, None, None, None, None, None, None, None];
        for ((bytes, meta), input) in self.bytes.iter().zip(self.metadata).zip(&mut inputs) {
            if let Some((algorithm, length)) = meta {
                let valid = if length == 0 {
                    0
                } else if length % 8 == 0 {
                    8
                } else {
                    u8::try_from(length % 8).map_err(|e| e.to_string())?
                };
                *input = Some(Input::new(
                    algorithm,
                    BitString::new(bytes, valid).map_err(|e| format!("{e:?}"))?,
                ));
            }
        }
        Ok(inputs)
    }

    pub fn destinations<'a>(&self, buffers: &'a mut [[u8; 32]; 8]) -> [Option<&'a mut [u8]>; 8] {
        let [a, b, c, d, e, f, g, h] = buffers;
        let mut slices = [None, None, None, None, None, None, None, None];
        for ((out, buffer), meta) in slices
            .iter_mut()
            .zip([a, b, c, d, e, f, g, h])
            .zip(self.metadata)
        {
            if let Some((algorithm, _)) = meta {
                *out = Some(&mut buffer[..algorithm.output_bytes()]);
            }
        }
        slices
    }

    pub fn cleared(&self, buffers: &[[u8; 32]; 8]) -> bool {
        buffers.iter().zip(self.metadata).all(|(bytes, meta)| {
            let used = meta.map_or(0, |(algorithm, _)| algorithm.output_bytes());
            bytes[..used].iter().all(|byte| *byte == 0)
                && bytes[used..].iter().all(|byte| *byte == 0xa5)
        })
    }
}
