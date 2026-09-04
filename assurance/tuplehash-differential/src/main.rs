use std::{
    error::Error,
    fmt::Write as _,
    io::{self, Read as _},
};

use brynja_hash_tuple::{
    Fips202BitString, Fips202Output, TupleHash128, TupleHash256, TupleHashXof128,
    TupleHashXof256,
};

const MAX_CAMPAIGN_BYTES: u64 = 1024 * 1024;
const MAX_CASES: usize = 512;
const MAX_FIELD_BYTES: usize = 4_096;
const MAX_ITEMS: usize = 16;
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
        rendered.try_reserve(1).map_err(|_| invalid(line, "render allocation failed"))?;
        rendered.push('\n');
    }
    print!("{rendered}");
    Ok(())
}

fn evaluate(request: &str, line: usize, rendered: &mut String) -> Result<(), Box<dyn Error>> {
    let mut fields = request.split_whitespace();
    let algorithm = required(fields.next(), line, "algorithm")?;
    let custom_bits = length(fields.next(), MAX_FIELD_BYTES.saturating_mul(8), line)?;
    let mut custom = decode(fields.next(), line)?;
    let output_bits = length(fields.next(), MAX_OUTPUT_BITS, line)?;
    let count = length(fields.next(), MAX_ITEMS, line)?;
    let custom_input = bit_string(&custom, custom_bits, line)?;
    let mut items = Vec::new();
    items.try_reserve_exact(count).map_err(|_| invalid(line, "item allocation failed"))?;
    for _ in 0..count {
        let bits = length(fields.next(), MAX_FIELD_BYTES.saturating_mul(8), line)?;
        let bytes = decode(fields.next(), line)?;
        bit_string(&bytes, bits, line)?;
        items.push((bytes, bits));
    }
    if fields.next().is_some() {
        return Err(invalid(line, "too many fields").into());
    }
    let output_bytes = output_bits.saturating_add(7) / 8;
    let mut output = Vec::new();
    output.try_reserve_exact(output_bytes).map_err(|_| invalid(line, "output allocation failed"))?;
    output.resize(output_bytes, 0);
    run(algorithm, custom_input, &items, output_bits, &mut output, line)?;
    append_hex(rendered, &output)?;
    output.fill(0);
    custom.fill(0);
    for (bytes, _) in &mut items { bytes.fill(0); }
    Ok(())
}

fn run(
    algorithm: &str,
    custom: Fips202BitString<'_>,
    items: &[(Vec<u8>, usize)],
    output_bits: usize,
    output: &mut [u8],
    line: usize,
) -> Result<(), io::Error> {
    macro_rules! absorb {
        ($state:expr) => {{
            let mut state = $state.map_err(|_| invalid(line, "construction rejected"))?;
            for (bytes, bits) in items {
                state.push_item_bits(bit_string(bytes, *bits, line)?)
                    .map_err(|_| invalid(line, "item rejected"))?;
            }
            state
        }};
    }
    let valid = valid_bits(output_bits);
    match algorithm {
        "tuple128" => absorb!(TupleHash128::new_bits(custom))
            .finalize_bits(destination(output, valid, line)?)
            .map_err(|_| invalid(line, "fixed output rejected")),
        "tuple256" => absorb!(TupleHash256::new_bits(custom))
            .finalize_bits(destination(output, valid, line)?)
            .map_err(|_| invalid(line, "fixed output rejected")),
        "tuplexof128" => absorb!(TupleHashXof128::new_bits(custom))
            .finalize_xof()
            .map_err(|_| invalid(line, "XOF finalization rejected"))?
            .squeeze_final_bits(destination(output, valid, line)?)
            .map_err(|_| invalid(line, "XOF output rejected")),
        "tuplexof256" => absorb!(TupleHashXof256::new_bits(custom))
            .finalize_xof()
            .map_err(|_| invalid(line, "XOF finalization rejected"))?
            .squeeze_final_bits(destination(output, valid, line)?)
            .map_err(|_| invalid(line, "XOF output rejected")),
        _ => Err(invalid(line, "unknown algorithm")),
    }
}

fn destination<'a>(bytes: &'a mut [u8], valid: u8, line: usize) -> Result<Fips202Output<'a>, io::Error> {
    Fips202Output::new(bytes, valid).map_err(|_| invalid(line, "output shape rejected"))
}

fn bit_string<'a>(bytes: &'a [u8], bits: usize, line: usize) -> Result<Fips202BitString<'a>, io::Error> {
    if bytes.len() != bits.saturating_add(7) / 8 { return Err(invalid(line, "bit string length mismatch")); }
    Fips202BitString::new(bytes, valid_bits(bits)).map_err(|_| invalid(line, "noncanonical bit string"))
}

fn length(field: Option<&str>, maximum: usize, line: usize) -> Result<usize, io::Error> {
    let value = required(field, line, "length")?.parse::<usize>().map_err(|_| invalid(line, "invalid length"))?;
    if value > maximum { Err(invalid(line, "length exceeds campaign limit")) } else { Ok(value) }
}

fn decode(field: Option<&str>, line: usize) -> Result<Vec<u8>, io::Error> {
    let value = required(field, line, "hex value")?;
    if value == "-" { return Ok(Vec::new()); }
    if !value.len().is_multiple_of(2) || value.len() / 2 > MAX_FIELD_BYTES { return Err(invalid(line, "invalid hex length")); }
    let mut output = Vec::new();
    output.try_reserve_exact(value.len() / 2).map_err(|_| invalid(line, "field allocation failed"))?;
    for pair in value.as_bytes().chunks_exact(2) {
        let [high, low] = pair else { return Err(invalid(line, "invalid hex pair")); };
        output.push(nibble(*high, line)?.wrapping_shl(4) | nibble(*low, line)?);
    }
    Ok(output)
}

fn nibble(value: u8, line: usize) -> Result<u8, io::Error> {
    match value { b'0'..=b'9' => Ok(value - b'0'), b'a'..=b'f' => Ok(value - b'a' + 10), _ => Err(invalid(line, "invalid hex")) }
}

fn valid_bits(bits: usize) -> u8 {
    if bits == 0 { 0 } else { u8::try_from((bits - 1) % 8).unwrap_or(7) + 1 }
}

fn append_hex(output: &mut String, bytes: &[u8]) -> Result<(), io::Error> {
    output.try_reserve(bytes.len().checked_mul(2).ok_or_else(|| invalid(0, "hex length overflow"))?).map_err(|_| invalid(0, "hex allocation failed"))?;
    for byte in bytes { write!(output, "{byte:02x}").map_err(io::Error::other)?; }
    Ok(())
}

fn required<'a>(value: Option<&'a str>, line: usize, label: &str) -> Result<&'a str, io::Error> {
    value.ok_or_else(|| invalid(line, label))
}

fn invalid(line: usize, message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("line {}: {message}", line.saturating_add(1)))
}
