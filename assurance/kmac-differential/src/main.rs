use std::{
    error::Error,
    fmt::Write as _,
    io::{self, Read as _},
};

use brynja_mac_kmac::{
    Fips202BitString, Fips202Output, Kmac128, Kmac256, KmacPublicDeclassification, KmacXof128,
    KmacXof256,
};

const MAX_CAMPAIGN_BYTES: u64 = 1024 * 1024;
const MAX_CASES: usize = 512;
const MAX_FIELD_BYTES: usize = 4_096;
const MAX_OUTPUT_BITS: usize = 4_095;

fn main() -> Result<(), Box<dyn Error>> {
    let mut request = String::new();
    io::stdin()
        .take(MAX_CAMPAIGN_BYTES.saturating_add(1))
        .read_to_string(&mut request)?;
    if u64::try_from(request.len()).unwrap_or(u64::MAX) > MAX_CAMPAIGN_BYTES {
        return Err(invalid(0, "campaign input exceeds limit").into());
    }
    let mut rendered = String::new();
    for (line, request) in request.lines().enumerate() {
        if line >= MAX_CASES {
            return Err(invalid(line, "campaign case limit exceeded").into());
        }
        evaluate(request, line, &mut rendered)?;
        rendered
            .try_reserve(1)
            .map_err(|_| io::Error::other("render allocation failed"))?;
        rendered.push('\n');
    }
    print!("{rendered}");
    Ok(())
}

fn evaluate(request: &str, line: usize, rendered: &mut String) -> Result<(), Box<dyn Error>> {
    let mut fields = request.split_whitespace();
    let algorithm = required(fields.next(), line, "algorithm")?;
    let key_bits = length(fields.next(), MAX_FIELD_BYTES.saturating_mul(8), line)?;
    let mut key = decode(fields.next(), line)?;
    let custom_bits = length(fields.next(), MAX_FIELD_BYTES.saturating_mul(8), line)?;
    let mut custom = decode(fields.next(), line)?;
    let message_bits = length(fields.next(), MAX_FIELD_BYTES.saturating_mul(8), line)?;
    let mut message = decode(fields.next(), line)?;
    let output_bits = length(fields.next(), MAX_OUTPUT_BITS, line)?;
    if fields.next().is_some() {
        return Err(invalid(line, "too many fields").into());
    }
    let key_input = bit_string(&key, key_bits, line)?;
    let custom_input = bit_string(&custom, custom_bits, line)?;
    let message_input = bit_string(&message, message_bits, line)?;
    let output_bytes = output_bits.saturating_add(7) / 8;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_bytes)
        .map_err(|_| invalid(line, "output allocation failed"))?;
    output.resize(output_bytes, 0);
    dispatch(
        algorithm,
        key_input,
        custom_input,
        message_input,
        output_bits,
        &mut output,
        line,
    )?;
    append_hex(rendered, &output)?;
    output.fill(0);
    key.fill(0);
    custom.fill(0);
    message.fill(0);
    Ok(())
}

fn dispatch(
    algorithm: &str,
    key: Fips202BitString<'_>,
    custom: Fips202BitString<'_>,
    message: Fips202BitString<'_>,
    output_bits: usize,
    output: &mut [u8],
    line: usize,
) -> Result<(), io::Error> {
    let valid = valid_bits(output_bits);
    match algorithm {
        "kmac128" => Kmac128::new_bits_conformance(key, custom)
            .and_then(|state| state.finalize_tag_bits_conformance(message, output, valid))
            .map(|_| ())
            .map_err(|_| invalid(line, "KMAC128 rejected bounded input")),
        "kmac256" => Kmac256::new_bits_conformance(key, custom)
            .and_then(|state| state.finalize_tag_bits_conformance(message, output, valid))
            .map(|_| ())
            .map_err(|_| invalid(line, "KMAC256 rejected bounded input")),
        "kmacxof128" => xof128(key, custom, message, output, valid, line),
        "kmacxof256" => xof256(key, custom, message, output, valid, line),
        _ => Err(invalid(line, "unknown algorithm")),
    }
}

fn xof128(
    key: Fips202BitString<'_>,
    custom: Fips202BitString<'_>,
    message: Fips202BitString<'_>,
    output: &mut [u8],
    valid: u8,
    line: usize,
) -> Result<(), io::Error> {
    let destination =
        Fips202Output::new(output, valid).map_err(|_| invalid(line, "output shape rejected"))?;
    KmacXof128::new_bits_conformance(key, custom)
        .and_then(|state| state.finalize_bits_xof_conformance(message))
        .and_then(|reader| {
            reader.squeeze_final_bits_public(destination, KmacPublicDeclassification::acknowledge())
        })
        .map_err(|_| invalid(line, "KMACXOF128 rejected bounded input"))
}

fn xof256(
    key: Fips202BitString<'_>,
    custom: Fips202BitString<'_>,
    message: Fips202BitString<'_>,
    output: &mut [u8],
    valid: u8,
    line: usize,
) -> Result<(), io::Error> {
    let destination =
        Fips202Output::new(output, valid).map_err(|_| invalid(line, "output shape rejected"))?;
    KmacXof256::new_bits_conformance(key, custom)
        .and_then(|state| state.finalize_bits_xof_conformance(message))
        .and_then(|reader| {
            reader.squeeze_final_bits_public(destination, KmacPublicDeclassification::acknowledge())
        })
        .map_err(|_| invalid(line, "KMACXOF256 rejected bounded input"))
}

fn bit_string(bytes: &[u8], bits: usize, line: usize) -> Result<Fips202BitString<'_>, io::Error> {
    if bytes.len() != bits.saturating_add(7) / 8 {
        return Err(invalid(line, "bit string length mismatch"));
    }
    Fips202BitString::new(bytes, valid_bits(bits))
        .map_err(|_| invalid(line, "noncanonical bit string"))
}

fn length(field: Option<&str>, maximum: usize, line: usize) -> Result<usize, io::Error> {
    let parsed = required(field, line, "length")?
        .parse::<usize>()
        .map_err(|_| invalid(line, "invalid length"))?;
    if parsed > maximum {
        return Err(invalid(line, "length exceeds campaign limit"));
    }
    Ok(parsed)
}

fn decode(field: Option<&str>, line: usize) -> Result<Vec<u8>, io::Error> {
    let value = required(field, line, "hex value")?;
    if value == "-" {
        return Ok(Vec::new());
    }
    if !value.len().is_multiple_of(2) || value.len() / 2 > MAX_FIELD_BYTES {
        return Err(invalid(line, "invalid hex length"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(value.len() / 2)
        .map_err(|_| invalid(line, "field allocation failed"))?;
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

fn valid_bits(bits: usize) -> u8 {
    if bits == 0 {
        0
    } else {
        u8::try_from(bits.saturating_sub(1) % 8)
            .unwrap_or(7)
            .saturating_add(1)
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

fn required<'value>(
    value: Option<&'value str>,
    line: usize,
    label: &str,
) -> Result<&'value str, io::Error> {
    value.ok_or_else(|| invalid(line, label))
}

fn invalid(line: usize, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("line {}: {message}", line.saturating_add(1)),
    )
}
