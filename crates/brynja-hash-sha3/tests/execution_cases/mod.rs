//! Shared downstream-only acceptance corpus (also included by packaged fixture).
use brynja_hash_sha3::{self as portable, Fips202BitString, Fips202Output, execution as api};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn ensure(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err("SHA-3 execution acceptance mismatch".into())
    }
}

fn valid(bits: usize) -> u8 {
    if bits == 0 {
        0
    } else {
        u8::try_from((bits.saturating_sub(1) % 8).saturating_add(1)).unwrap_or_default()
    }
}

fn hex(text: &str) -> Result<Vec<u8>> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let value = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(value, 16)?)
        })
        .collect()
}

pub fn run<'a>(execution: impl Fn() -> Result<api::Execution<'a>>) -> Result<usize> {
    let mut cases = 0_usize;
    for line in include_str!("../vectors/nist-bit-selected.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [
            algorithm,
            input_length,
            output_length,
            message_hex,
            expected_hex,
        ] = fields.as_slice()
        else {
            return Err("invalid vector fields".into());
        };
        let bits: usize = input_length.parse()?;
        let out_bits: usize = output_length.parse()?;
        let mut message = hex(message_hex)?;
        message.truncate(bits.div_ceil(8));
        let input = Fips202BitString::new(&message, valid(bits)).map_err(|_| "input")?;
        let mut expected = hex(expected_hex)?;
        expected.truncate(out_bits.div_ceil(8));
        macro_rules! fixed {
            ($name:ident) => {{
                let result = api::$name::hash_bits(execution()?, input)?;
                ensure(result.digest.as_bytes().as_slice() == expected)?;
                ensure(result.report.route == execution()?.route())?;
                ensure(result.report.padding_permutations >= 1)?;
            }};
        }
        macro_rules! shake {
            ($name:ident) => {{
                let mut output: Vec<u8> = expected.iter().map(|value| value ^ 0xff).collect();
                let mut scratch = vec![0; output.len()];
                let dest =
                    Fips202Output::new(&mut output, valid(out_bits)).map_err(|_| "output")?;
                let report =
                    api::$name::hash_bits_with_scratch(execution()?, input, dest, &mut scratch)?;
                ensure(output == expected)?;
                ensure(report.route == execution()?.route())?;
            }};
        }
        match *algorithm {
            "sha3-224" => fixed!(Sha3_224),
            "sha3-256" => fixed!(Sha3_256),
            "sha3-384" => fixed!(Sha3_384),
            "sha3-512" => fixed!(Sha3_512),
            "shake128" => shake!(Shake128),
            "shake256" => shake!(Shake256),
            _ => return Err("unknown vector identity".into()),
        }
        cases = cases.saturating_add(1);
    }
    ensure(cases == 76)?;
    // Every rate, suffix collision, partial residue and cross-permutation read.
    for length in [
        0_usize, 1, 71, 72, 73, 103, 104, 105, 135, 136, 137, 143, 144, 145, 167, 168, 169, 335,
        336, 337, 1024,
    ] {
        for tail in 1..=8 {
            let mut message: Vec<u8> = (0..length)
                .map(|i| {
                    u8::try_from(i % 256)
                        .unwrap_or_default()
                        .wrapping_mul(37)
                        .wrapping_add(11)
                })
                .collect();
            let tail_width = if length == 0 { 0 } else { tail };
            if let Some(last) = message.last_mut() {
                *last &= u8::MAX >> 8_u8.saturating_sub(tail);
            }
            let bits = Fips202BitString::new(&message, tail_width).map_err(|_| "tail")?;
            macro_rules! compare_fixed {
                ($name:ident, $function:ident, $rate:expr) => {{
                    let expected = portable::$function(bits).map_err(|_| "portable fixed")?;
                    let complete = if tail < 8 {
                        length.saturating_sub(1)
                    } else {
                        length
                    };
                    let mut stream = api::$name::new(execution()?)?;
                    for chunk in message.get(..complete).ok_or("complete input")?.chunks(13) {
                        stream.update(chunk)?;
                    }
                    ensure(stream.message_bytes() == complete as u128)?;
                    let remaining = Fips202BitString::new(
                        message.get(complete..).ok_or("remaining input")?,
                        if complete == length { 0 } else { tail },
                    )
                    .map_err(|_| "remaining")?;
                    let result = stream.finalize_bits(remaining)?;
                    ensure(result.digest == expected)?;
                    ensure(result.report.route == execution()?.route())?;
                    ensure(result.report.absorb_permutations == (complete / $rate) as u128)?;
                    cases = cases.saturating_add(1);
                }};
            }
            compare_fixed!(Sha3_224, sha3_224_bits, 144);
            compare_fixed!(Sha3_256, sha3_256_bits, 136);
            compare_fixed!(Sha3_384, sha3_384_bits, 104);
            compare_fixed!(Sha3_512, sha3_512_bits, 72);
            macro_rules! compare_xof {
                ($name:ident, $function:ident, $rate:expr) => {{
                    let mut expected = [0; 510];
                    portable::$function(
                        bits,
                        Fips202Output::new(&mut expected, tail).map_err(|_| "dest")?,
                    )
                    .map_err(|_| "portable XOF")?;
                    let mut reader = api::$name::new(execution()?)?.finalize_bits_xof(bits)?;
                    let before = reader.report();
                    let mut rejected = [0xa5; 169];
                    ensure(reader.squeeze(&mut rejected) == Err(api::Error::ScratchTooSmall))?;
                    ensure(
                        rejected == [0xa5; 169]
                            && reader.output_bytes() == 0
                            && reader.report() == before,
                    )?;
                    let mut output = [0xa5; 510];
                    for chunk in output
                        .get_mut(..340)
                        .ok_or("complete output")?
                        .chunks_mut(17)
                    {
                        reader.squeeze(chunk)?;
                    }
                    reader.squeeze(&mut [])?;
                    ensure(reader.output_bytes() == 340)?;
                    let destination =
                        Fips202Output::new(output.get_mut(340..).ok_or("remaining output")?, tail)
                            .map_err(|_| "final dest")?;
                    let report =
                        reader.squeeze_final_bits_with_scratch(destination, &mut [0; 170])?;
                    ensure(output == expected)?;
                    ensure(report.route == execution()?.route())?;
                    ensure(report.squeeze_permutations == (509 / $rate) as u128)?;
                    cases = cases.saturating_add(1);
                }};
            }
            compare_xof!(Shake128, shake128_bits, 168);
            compare_xof!(Shake256, shake256_bits, 136);
        }
    }
    Ok(cases)
}
