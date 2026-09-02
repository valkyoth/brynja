//! Bounded stdin adapter for independent SHA-2 bit-input differential checks.

use std::io::{self, BufRead, Write};

use brynja_hash_sha2::{
    BitString, sha224_bits, sha256_bits, sha384_bits, sha512_224_bits, sha512_256_bits,
    sha512_bits,
};

const MAX_INPUT_LINE_BYTES: usize = 1_200;
const MAX_MESSAGE_BITS: usize = 4_096;

fn main() {
    if let Err(error) = run() {
        eprintln!("SHA-2 bit differential adapter failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), io::Error> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut buffer = [0_u8; MAX_INPUT_LINE_BYTES];
    let mut line_number = 1_usize;
    while let Some(line) = read_bounded_line(&mut reader, &mut buffer, line_number)? {
        let mut fields = line.split(' ');
        let algorithm = fields
            .next()
            .ok_or_else(|| invalid(line_number, "missing algorithm"))?;
        let bit_len = fields
            .next()
            .ok_or_else(|| invalid(line_number, "missing bit length"))?
            .parse::<usize>()
            .map_err(|_| invalid(line_number, "invalid bit length"))?;
        let encoded = fields
            .next()
            .ok_or_else(|| invalid(line_number, "missing message"))?;
        if fields.next().is_some() || bit_len > MAX_MESSAGE_BITS {
            return Err(invalid(line_number, "invalid request shape or bound"));
        }
        let bytes = decode_message(encoded, bit_len, line_number)?;
        let valid = if bit_len == 0 {
            0
        } else {
            u8::try_from((bit_len - 1) % 8 + 1)
                .map_err(|_| invalid(line_number, "invalid final width"))?
        };
        let input = BitString::new(&bytes, valid)
            .map_err(|_| invalid(line_number, "noncanonical message"))?;
        write_digest(&mut stdout, algorithm, input, line_number)?;
        stdout.write_all(b"\n")?;
        line_number = line_number.saturating_add(1);
    }
    stdout.flush()
}

fn read_bounded_line<'line>(
    reader: &mut impl BufRead,
    buffer: &'line mut [u8; MAX_INPUT_LINE_BYTES],
    line_number: usize,
) -> Result<Option<&'line str>, io::Error> {
    let mut length = 0_usize;
    loop {
        let mut byte = [0_u8; 1];
        let read = reader.read(&mut byte)?;
        if read == 0 {
            if length == 0 {
                return Ok(None);
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        let slot = buffer
            .get_mut(length)
            .ok_or_else(|| invalid(line_number, "input line exceeds bound"))?;
        *slot = byte[0];
        length = length.saturating_add(1);
    }
    if length != 0 && buffer.get(length.saturating_sub(1)) == Some(&b'\r') {
        length = length.saturating_sub(1);
    }
    let bytes = buffer
        .get(..length)
        .ok_or_else(|| invalid(line_number, "input line exceeds bound"))?;
    core::str::from_utf8(bytes)
        .map(Some)
        .map_err(|_| invalid(line_number, "input line is not UTF-8"))
}

fn decode_message(encoded: &str, bit_len: usize, line_number: usize) -> Result<Vec<u8>, io::Error> {
    let expected_bytes = bit_len.saturating_add(7) / 8;
    if bit_len == 0 {
        if encoded != "-" {
            return Err(invalid(line_number, "empty message must use dash"));
        }
        return Ok(Vec::new());
    }
    if encoded.len() != expected_bytes.saturating_mul(2) || !encoded.len().is_multiple_of(2) {
        return Err(invalid(line_number, "message length mismatch"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(expected_bytes)
        .map_err(|_| invalid(line_number, "message allocation failed"))?;
    let mut index = 0_usize;
    while index < encoded.len() {
        let high = encoded
            .as_bytes()
            .get(index)
            .copied()
            .and_then(nibble)
            .ok_or_else(|| invalid(line_number, "invalid hexadecimal"))?;
        let low = encoded
            .as_bytes()
            .get(index.saturating_add(1))
            .copied()
            .and_then(nibble)
            .ok_or_else(|| invalid(line_number, "invalid hexadecimal"))?;
        output.push((high << 4) | low);
        index = index.saturating_add(2);
    }
    Ok(output)
}

fn write_digest(
    output: &mut impl Write,
    algorithm: &str,
    input: BitString<'_>,
    line_number: usize,
) -> Result<(), io::Error> {
    macro_rules! hash {
        ($function:ident) => {{
            let digest = $function(input)
                .map_err(|_| invalid(line_number, "algorithm rejected bounded input"))?;
            write_hex(output, digest.as_ref())
        }};
    }
    match algorithm {
        "sha224" => hash!(sha224_bits),
        "sha256" => hash!(sha256_bits),
        "sha384" => hash!(sha384_bits),
        "sha512" => hash!(sha512_bits),
        "sha512_224" => hash!(sha512_224_bits),
        "sha512_256" => hash!(sha512_256_bits),
        _ => Err(invalid(line_number, "unknown algorithm")),
    }
}

fn write_hex(output: &mut impl Write, bytes: &[u8]) -> Result<(), io::Error> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.write_all(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])?;
    }
    Ok(())
}

const fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn invalid(line_number: usize, message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("line {line_number}: {message}"))
}
