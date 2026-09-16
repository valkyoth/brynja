//! Public generated vectors only, never a confidential-input application.
use crate::Result;
use brynja_hash_parallel::{Fips202BitString, execution::Identity};
use brynja_hash_parallel_std::execution::Request;

pub struct Case {
    identity: Identity,
    custom: Vec<u8>,
    custom_bits: usize,
    message: Vec<u8>,
    message_bits: usize,
    block: usize,
    pub output_bits: usize,
}

pub fn valid(bits: usize) -> Result<u8> {
    if bits == 0 {
        Ok(0)
    } else {
        Ok(u8::try_from((bits - 1) % 8 + 1)?)
    }
}

fn bit_string(bytes: &[u8], bits: usize) -> Result<Fips202BitString<'_>> {
    if bytes.len() != bits.div_ceil(8) {
        return Err("bit length mismatch".into());
    }
    Fips202BitString::new(bytes, valid(bits)?)
        .map_err(|e| format!("noncanonical bits: {e:?}").into())
}

fn hex(text: &str) -> Result<Vec<u8>> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if text.len() > 8192 || !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err("hex shape".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

impl Case {
    pub fn parse(line: &str) -> Result<Self> {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [
            algorithm,
            custom_bits,
            custom,
            message_bits,
            message,
            block,
            output_bits,
        ] = fields.as_slice()
        else {
            return Err("field count".into());
        };
        let identity = match *algorithm {
            "parallel128" => Identity::ParallelHash128,
            "parallel256" => Identity::ParallelHash256,
            "parallelxof128" => Identity::ParallelHashXof128,
            "parallelxof256" => Identity::ParallelHashXof256,
            _ => return Err("unknown identity".into()),
        };
        let case = Self {
            identity,
            custom: hex(custom)?,
            custom_bits: custom_bits.parse()?,
            message: hex(message)?,
            message_bits: message_bits.parse()?,
            block: block.parse()?,
            output_bits: output_bits.parse()?,
        };
        if case.custom_bits > 32768
            || case.message_bits > 32768
            || case.block == 0
            || case.block > 1024
            || case.output_bits > 4095
        {
            return Err("field bound".into());
        }
        Ok(case)
    }

    pub fn request(&self) -> Result<Request<'_>> {
        Ok(Request {
            identity: self.identity,
            input: bit_string(&self.message, self.message_bits)?,
            block_size: self.block,
            customization: bit_string(&self.custom, self.custom_bits)?,
        })
    }

    pub fn leaves(&self) -> usize {
        self.message_bits.div_ceil(8).div_ceil(self.block)
    }
}
