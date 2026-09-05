//! Bounded differential adapter: length-in-bits, canonical hex (or -).
use brynja_legacy_sha1::{BitString, HardenedSha1, PublicDeclassification, sha1_bits};
use std::{
    error::Error,
    io::{self, BufRead, Read},
};

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid bounded SHA-1 request")
}

fn main() -> Result<(), Box<dyn Error>> {
    brynja_sha1_public_api_fixture::acceptance()?;
    let mut input = io::stdin().lock();
    loop {
        // Cap before allocation: do not use unbounded lines/read_line.
        let mut line = Vec::new();
        let mut limited = (&mut input).take(16416);
        if limited.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.len() >= 16416 {
            return Err(invalid().into());
        }
        let text = core::str::from_utf8(&line)?;
        let fields: Vec<_> = text.split_whitespace().collect();
        if fields.len() != 2 {
            return Err(invalid().into());
        }
        let mut fields = fields.into_iter();
        let bits: usize = fields.next().ok_or_else(invalid)?.parse()?;
        if bits > 65536 {
            return Err(invalid().into());
        }
        let encoded = fields.next().ok_or_else(invalid)?;
        let message = if encoded == "-" {
            Vec::new()
        } else {
            if encoded.len() % 2 != 0 {
                return Err(invalid().into());
            }
            encoded
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    let text = core::str::from_utf8(pair).map_err(|_| invalid())?;
                    u8::from_str_radix(text, 16).map_err(|_| invalid())
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        if message.len() != bits.div_ceil(8) {
            return Err(invalid().into());
        }
        let width = if bits == 0 {
            0
        } else {
            u8::try_from((bits - 1) % 8 + 1)?
        };
        let bits = BitString::new(&message, width).map_err(|_| invalid())?;
        let digest = sha1_bits(bits)?;
        let mut hardened = [0; 20];
        HardenedSha1::new().finalize_bits_public(
            bits,
            &mut hardened,
            PublicDeclassification::acknowledge(),
        )?;
        if digest != hardened {
            return Err(invalid().into());
        }
        for byte in digest {
            print!("{byte:02x}");
        }
        println!();
    }
    Ok(())
}
