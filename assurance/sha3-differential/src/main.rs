use std::{
    error::Error,
    fmt::Write as _,
    io::{self, Read as _},
};

use brynja_hash_sha3::{sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256};

const MAX_XOF_OUTPUT_BYTES: usize = 343;

fn main() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let mut output = String::new();
    for (line_number, line) in input.lines().enumerate() {
        let mut fields = line.split_whitespace();
        let algorithm = required(fields.next(), line_number, "algorithm")?;
        let message = decode(required(fields.next(), line_number, "message")?)?;
        let output_length = fields
            .next()
            .map(|value| parse_length(value, line_number))
            .transpose()?;
        if fields.next().is_some() {
            return Err(invalid(line_number, "too many fields").into());
        }
        match algorithm {
            "sha3-224" if output_length.is_none() => append_hex(
                &mut output,
                sha3_224(&message)
                    .map_err(|_| io::Error::other("SHA3-224 length rejected"))?
                    .as_bytes(),
            )?,
            "sha3-256" if output_length.is_none() => append_hex(
                &mut output,
                sha3_256(&message)
                    .map_err(|_| io::Error::other("SHA3-256 length rejected"))?
                    .as_bytes(),
            )?,
            "sha3-384" if output_length.is_none() => append_hex(
                &mut output,
                sha3_384(&message)
                    .map_err(|_| io::Error::other("SHA3-384 length rejected"))?
                    .as_bytes(),
            )?,
            "sha3-512" if output_length.is_none() => append_hex(
                &mut output,
                sha3_512(&message)
                    .map_err(|_| io::Error::other("SHA3-512 length rejected"))?
                    .as_bytes(),
            )?,
            "shake128" => append_xof(&mut output, &message, output_length, shake128, line_number)?,
            "shake256" => append_xof(&mut output, &message, output_length, shake256, line_number)?,
            _ => return Err(invalid(line_number, "algorithm or output length").into()),
        }
        output.push('\n');
    }
    print!("{output}");
    Ok(())
}

fn parse_length(value: &str, line_number: usize) -> Result<usize, io::Error> {
    let length = value
        .parse()
        .map_err(|_| invalid(line_number, "invalid output length"))?;
    if length > MAX_XOF_OUTPUT_BYTES {
        return Err(invalid(
            line_number,
            "output length exceeds campaign limit",
        ));
    }
    Ok(length)
}

fn append_xof<E>(
    rendered: &mut String,
    message: &[u8],
    output_length: Option<usize>,
    xof: fn(&[u8], &mut [u8]) -> Result<(), E>,
    line_number: usize,
) -> Result<(), Box<dyn Error>> {
    let length = output_length.ok_or_else(|| invalid(line_number, "missing output length"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| invalid(line_number, "output allocation failed"))?;
    output.resize(length, 0);
    xof(message, &mut output).map_err(|_| invalid(line_number, "XOF length rejected"))?;
    append_hex(rendered, &output)?;
    Ok(())
}

fn required<'a>(
    value: Option<&'a str>,
    line_number: usize,
    field: &str,
) -> Result<&'a str, io::Error> {
    value.ok_or_else(|| invalid(line_number, field))
}

fn invalid(line_number: usize, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("line {}: {message}", line_number.saturating_add(1)),
    )
}

fn decode(hex: &str) -> Result<Vec<u8>, io::Error> {
    if hex == "-" {
        return Ok(Vec::new());
    }
    if !hex.len().is_multiple_of(2) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "odd hex length"));
    }
    let mut output = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        if let [high, low] = pair {
            output.push((nibble(*high)? << 4) | nibble(*low)?);
        }
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, io::Error> {
    match value {
        b'0'..=b'9' => Ok(value.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(value.saturating_sub(b'a').saturating_add(10)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid hex")),
    }
}

fn append_hex(output: &mut String, bytes: &[u8]) -> Result<(), io::Error> {
    let additional = bytes
        .len()
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("hex output length overflow"))?;
    output
        .try_reserve_exact(additional)
        .map_err(|_| io::Error::other("hex output allocation failed"))?;
    for byte in bytes {
        write!(output, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(())
}
