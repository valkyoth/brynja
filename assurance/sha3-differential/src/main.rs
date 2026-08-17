use std::{
    error::Error,
    fmt::Write as _,
    io::{self, Read as _},
};

use brynja_hash_sha3::{sha3_224, sha3_256};

fn main() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let mut output = String::new();
    for (line_number, line) in input.lines().enumerate() {
        let mut fields = line.split_whitespace();
        let algorithm = required(fields.next(), line_number, "algorithm")?;
        let message = decode(required(fields.next(), line_number, "message")?)?;
        if fields.next().is_some() {
            return Err(invalid(line_number, "too many fields").into());
        }
        match algorithm {
            "sha3-224" => append_hex(
                &mut output,
                sha3_224(&message)
                    .map_err(|_| io::Error::other("SHA3-224 length rejected"))?
                    .as_bytes(),
            )?,
            "sha3-256" => append_hex(
                &mut output,
                sha3_256(&message)
                    .map_err(|_| io::Error::other("SHA3-256 length rejected"))?
                    .as_bytes(),
            )?,
            _ => return Err(invalid(line_number, "unknown algorithm").into()),
        }
        output.push('\n');
    }
    print!("{output}");
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

fn append_hex(output: &mut String, bytes: &[u8]) -> Result<(), std::fmt::Error> {
    for byte in bytes {
        write!(output, "{byte:02x}")?;
    }
    Ok(())
}
