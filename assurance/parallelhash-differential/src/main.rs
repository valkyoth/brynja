use std::{
    error::Error,
    fmt::Write as _,
    io::{self, Read as _},
};

use brynja_hash_parallel::{
    Fips202BitString, Fips202Output, ParallelHash128, ParallelHash256, ParallelHashXof128,
    ParallelHashXof256,
};

const MAX_CAMPAIGN_BYTES: u64 = 1024 * 1024;
const MAX_CASES: usize = 512;
const MAX_FIELD_BYTES: usize = 4_096;
const MAX_OUTPUT_BITS: usize = 4_095;
const MAX_BLOCK_BYTES: usize = 1_024;

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
            .map_err(|_| invalid(line, "render allocation failed"))?;
        rendered.push('\n');
    }
    print!("{rendered}");
    Ok(())
}

fn evaluate(request: &str, line: usize, rendered: &mut String) -> Result<(), Box<dyn Error>> {
    let mut fields = request.split_whitespace();
    let algorithm = required(fields.next(), line, "algorithm")?;
    let custom_bits = length(fields.next(), MAX_FIELD_BYTES.saturating_mul(8), line)?;
    let mut custom_bytes = decode(fields.next(), line)?;
    let input_bits = length(fields.next(), MAX_FIELD_BYTES.saturating_mul(8), line)?;
    let mut input = decode(fields.next(), line)?;
    let block_size = length(fields.next(), MAX_BLOCK_BYTES, line)?;
    if block_size == 0 {
        return Err(invalid(line, "zero block size").into());
    }
    let output_bits = length(fields.next(), MAX_OUTPUT_BITS, line)?;
    if fields.next().is_some() {
        return Err(invalid(line, "too many fields").into());
    }
    let custom = bit_string(&custom_bytes, custom_bits, line)?;
    let input_bits = bit_string(&input, input_bits, line)?;
    let output_bytes = output_bits.saturating_add(7) / 8;
    let mut output = bounded_vec(output_bytes, line, "output allocation failed")?;
    let mut workspace = bounded_vec(block_size, line, "workspace allocation failed")?;
    run(
        algorithm,
        custom,
        input_bits,
        output_bits,
        &mut workspace,
        &mut output,
        line,
    )?;
    append_hex(rendered, &output)?;
    output.fill(0);
    workspace.fill(0);
    input.fill(0);
    custom_bytes.fill(0);
    Ok(())
}

fn run(
    algorithm: &str,
    custom: Fips202BitString<'_>,
    input: Fips202BitString<'_>,
    output_bits: usize,
    workspace: &mut [u8],
    output: &mut [u8],
    line: usize,
) -> Result<(), io::Error> {
    let valid = valid_bits(output_bits);
    match algorithm {
        "parallel128" => ParallelHash128::new_bits(workspace, custom)
            .map_err(|_| invalid(line, "construction rejected"))?
            .finalize_bits(input, destination(output, valid, line)?)
            .map_err(|_| invalid(line, "fixed output rejected")),
        "parallel256" => ParallelHash256::new_bits(workspace, custom)
            .map_err(|_| invalid(line, "construction rejected"))?
            .finalize_bits(input, destination(output, valid, line)?)
            .map_err(|_| invalid(line, "fixed output rejected")),
        "parallelxof128" => ParallelHashXof128::new_bits(workspace, custom)
            .map_err(|_| invalid(line, "construction rejected"))?
            .finalize_bits_xof(input)
            .map_err(|_| invalid(line, "XOF finalization rejected"))?
            .squeeze_final_bits(destination(output, valid, line)?)
            .map_err(|_| invalid(line, "XOF output rejected")),
        "parallelxof256" => ParallelHashXof256::new_bits(workspace, custom)
            .map_err(|_| invalid(line, "construction rejected"))?
            .finalize_bits_xof(input)
            .map_err(|_| invalid(line, "XOF finalization rejected"))?
            .squeeze_final_bits(destination(output, valid, line)?)
            .map_err(|_| invalid(line, "XOF output rejected")),
        _ => Err(invalid(line, "unknown algorithm")),
    }
}

fn bounded_vec(length: usize, line: usize, message: &str) -> Result<Vec<u8>, io::Error> {
    let mut value = Vec::new();
    value.try_reserve_exact(length).map_err(|_| invalid(line, message))?;
    value.resize(length, 0);
    Ok(value)
}

fn destination<'a>(bytes: &'a mut [u8], valid: u8, line: usize) -> Result<Fips202Output<'a>, io::Error> {
    Fips202Output::new(bytes, valid).map_err(|_| invalid(line, "output shape rejected"))
}

fn bit_string<'a>(bytes: &'a [u8], bits: usize, line: usize) -> Result<Fips202BitString<'a>, io::Error> {
    if bytes.len() != bits.saturating_add(7) / 8 {
        return Err(invalid(line, "bit string length mismatch"));
    }
    Fips202BitString::new(bytes, valid_bits(bits))
        .map_err(|_| invalid(line, "noncanonical bit string"))
}

fn length(field: Option<&str>, maximum: usize, line: usize) -> Result<usize, io::Error> {
    let value = required(field, line, "length")?
        .parse::<usize>()
        .map_err(|_| invalid(line, "invalid length"))?;
    if value > maximum {
        Err(invalid(line, "length exceeds campaign limit"))
    } else {
        Ok(value)
    }
}

fn decode(field: Option<&str>, line: usize) -> Result<Vec<u8>, io::Error> {
    let value = required(field, line, "hex value")?;
    if value == "-" {
        return Ok(Vec::new());
    }
    if !value.len().is_multiple_of(2) || value.len() / 2 > MAX_FIELD_BYTES {
        return Err(invalid(line, "invalid hex length"));
    }
    let mut output = bounded_vec(0, line, "field allocation failed")?;
    output.try_reserve_exact(value.len() / 2).map_err(|_| invalid(line, "field allocation failed"))?;
    for pair in value.as_bytes().chunks_exact(2) {
        let [high, low] = pair else { return Err(invalid(line, "invalid hex pair")); };
        output.push(nibble(*high, line)?.wrapping_shl(4) | nibble(*low, line)?);
    }
    Ok(output)
}

fn nibble(value: u8, line: usize) -> Result<u8, io::Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid(line, "invalid hex")),
    }
}

fn valid_bits(bits: usize) -> u8 {
    if bits == 0 { 0 } else { u8::try_from((bits - 1) % 8).unwrap_or(7) + 1 }
}

fn append_hex(output: &mut String, bytes: &[u8]) -> Result<(), io::Error> {
    output.try_reserve(bytes.len().checked_mul(2).ok_or_else(|| invalid(0, "hex length overflow"))?)
        .map_err(|_| invalid(0, "hex allocation failed"))?;
    for byte in bytes { write!(output, "{byte:02x}").map_err(io::Error::other)?; }
    Ok(())
}

fn required<'a>(value: Option<&'a str>, line: usize, label: &str) -> Result<&'a str, io::Error> {
    value.ok_or_else(|| invalid(line, label))
}

fn invalid(line: usize, message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("line {}: {message}", line.saturating_add(1)))
}
