use std::{
    error::Error,
    fmt::Write as _,
    io::{self, Read as _},
};

use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, sha3_224_bits, sha3_256_bits, sha3_384_bits, sha3_512_bits,
    shake128_bits, shake256_bits,
};

const MAX_CAMPAIGN_BYTES: u64 = 1024 * 1024;
const MAX_CASES: usize = 1_024;
const MAX_MESSAGE_BYTES: usize = 4_096;
const MAX_OUTPUT_BITS: usize = 4_095;

fn main() -> Result<(), Box<dyn Error>> {
    let mut request = String::new();
    io::stdin()
        .take(MAX_CAMPAIGN_BYTES + 1)
        .read_to_string(&mut request)?;
    if request.len() as u64 > MAX_CAMPAIGN_BYTES {
        return Err(invalid(0, "campaign input exceeds limit").into());
    }
    let mut rendered = String::new();
    for (line_number, line) in request.lines().enumerate() {
        if line_number >= MAX_CASES {
            return Err(invalid(line_number, "campaign case limit exceeded").into());
        }
        let mut fields = line.split_whitespace();
        let algorithm = required(fields.next(), line_number, "algorithm")?;
        let input_bits = parse_length(
            required(fields.next(), line_number, "input bits")?,
            MAX_MESSAGE_BYTES * 8,
            line_number,
        )?;
        let output_bits = parse_length(
            required(fields.next(), line_number, "output bits")?,
            MAX_OUTPUT_BITS,
            line_number,
        )?;
        let mut message = decode(
            required(fields.next(), line_number, "message")?,
            MAX_MESSAGE_BYTES,
            line_number,
        )?;
        if fields.next().is_some() {
            return Err(invalid(line_number, "too many fields").into());
        }
        let encoded_bytes = input_bits.saturating_add(7) / 8;
        if message.len() != encoded_bytes {
            return Err(invalid(line_number, "message length mismatch").into());
        }
        let input = Fips202BitString::new(&message, valid_bits(input_bits))
            .map_err(|_| invalid(line_number, "noncanonical message"))?;
        match algorithm {
            "sha3-224" if output_bits == 224 => append_hex(
                &mut rendered,
                sha3_224_bits(input)
                    .map_err(|_| invalid(line_number, "input rejected"))?
                    .as_bytes(),
            )?,
            "sha3-256" if output_bits == 256 => append_hex(
                &mut rendered,
                sha3_256_bits(input)
                    .map_err(|_| invalid(line_number, "input rejected"))?
                    .as_bytes(),
            )?,
            "sha3-384" if output_bits == 384 => append_hex(
                &mut rendered,
                sha3_384_bits(input)
                    .map_err(|_| invalid(line_number, "input rejected"))?
                    .as_bytes(),
            )?,
            "sha3-512" if output_bits == 512 => append_hex(
                &mut rendered,
                sha3_512_bits(input)
                    .map_err(|_| invalid(line_number, "input rejected"))?
                    .as_bytes(),
            )?,
            "shake128" | "shake256" => {
                append_xof(&mut rendered, algorithm, input, output_bits, line_number)?
            }
            _ => return Err(invalid(line_number, "algorithm or output length").into()),
        }
        rendered
            .try_reserve(1)
            .map_err(|_| io::Error::other("render allocation failed"))?;
        rendered.push('\n');
        message.fill(0);
    }
    print!("{rendered}");
    Ok(())
}

fn append_xof(
    rendered: &mut String,
    algorithm: &str,
    input: Fips202BitString<'_>,
    output_bits: usize,
    line: usize,
) -> Result<(), Box<dyn Error>> {
    let bytes = output_bits.saturating_add(7) / 8;
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes)
        .map_err(|_| invalid(line, "output allocation failed"))?;
    output.resize(bytes, 0);
    let destination = Fips202Output::new(&mut output, valid_bits(output_bits))
        .map_err(|_| invalid(line, "output shape rejected"))?;
    if algorithm == "shake128" {
        shake128_bits(input, destination).map_err(|_| invalid(line, "output rejected"))?;
    } else {
        shake256_bits(input, destination).map_err(|_| invalid(line, "output rejected"))?;
    }
    append_hex(rendered, &output)?;
    output.fill(0);
    Ok(())
}

fn parse_length(value: &str, maximum: usize, line: usize) -> Result<usize, io::Error> {
    let parsed = value.parse().map_err(|_| invalid(line, "invalid length"))?;
    if parsed > maximum {
        return Err(invalid(line, "length exceeds campaign limit"));
    }
    Ok(parsed)
}

fn decode(value: &str, maximum: usize, line: usize) -> Result<Vec<u8>, io::Error> {
    if value == "-" {
        return Ok(Vec::new());
    }
    if !value.len().is_multiple_of(2) || value.len() / 2 > maximum {
        return Err(invalid(line, "invalid hex length"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(value.len() / 2)
        .map_err(|_| invalid(line, "message allocation failed"))?;
    for pair in value.as_bytes().chunks_exact(2) {
        let [high, low] = pair else {
            return Err(invalid(line, "invalid hex pair"));
        };
        output.push(nibble(*high, line)?.wrapping_shl(4) | nibble(*low, line)?);
    }
    Ok(output)
}

fn nibble(value: u8, line: usize) -> Result<u8, io::Error> {
    match value {
        b'0'..=b'9' => Ok(value.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(value.saturating_sub(b'a').saturating_add(10)),
        _ => Err(invalid(line, "invalid hex")),
    }
}

fn append_hex(output: &mut String, bytes: &[u8]) -> Result<(), io::Error> {
    let additional = bytes
        .len()
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("hex length overflow"))?;
    output
        .try_reserve(additional)
        .map_err(|_| io::Error::other("hex allocation failed"))?;
    for byte in bytes {
        write!(output, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(())
}

fn valid_bits(bits: usize) -> u8 {
    if bits == 0 {
        0
    } else {
        u8::try_from(bits.saturating_sub(1) % 8)
            .unwrap_or(7)
            .saturating_add(1)
    }
}

fn required<'a>(value: Option<&'a str>, line: usize, field: &str) -> Result<&'a str, io::Error> {
    value.ok_or_else(|| invalid(line, field))
}

fn invalid(line: usize, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("line {}: {message}", line.saturating_add(1)),
    )
}
