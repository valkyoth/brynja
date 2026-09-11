//! Public package-only API acceptance; no implementation-private access.
use brynja_hash_sha3::{Fips202BitString, Fips202Output, execution as api};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn ensure(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err("cSHAKE execution mismatch".into())
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
    if text == "-" {
        return Ok(Vec::new());
    }
    ensure(text.len() <= 8192 && text.len().is_multiple_of(2))?;
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
fn shape(bytes: &[u8], bits: usize) -> Result<api::PublicBits<'_>> {
    ensure(bits <= 32768 && bytes.len() == bits.div_ceil(8))?;
    Ok(api::PublicBits::new(
        Fips202BitString::new(bytes, valid(bits)).map_err(|_| "input shape")?,
    ))
}

pub fn run<'a>(execution: impl Fn() -> Result<api::Execution<'a>>) -> Result<usize> {
    let mut count = 0_usize;
    for line in include_str!("../vectors/cshake-execution.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [algorithm, nb, n, sb, s, xb, x, ob, expected] = fields.as_slice() else {
            return Err("vector fields".into());
        };
        let (nb, sb, xb, ob): (usize, usize, usize, usize) =
            (nb.parse()?, sb.parse()?, xb.parse()?, ob.parse()?);
        let (n, s, x, expected) = (hex(n)?, hex(s)?, hex(x)?, hex(expected)?);
        let (n_bits, s_bits, input) = (shape(&n, nb)?, shape(&s, sb)?, shape(&x, xb)?);
        ensure(ob <= 4096 && expected.len() == ob.div_ceil(8))?;
        macro_rules! check {
            ($name:ident, $rate:literal) => {{
                let route = execution()?.route();
                let mut out: Vec<u8> = expected.iter().map(|b| b ^ 0xff).collect();
                let mut scratch = vec![0; out.len()];
                let dest = Fips202Output::new(&mut out, valid(ob)).map_err(|_| "output shape")?;
                let report = api::$name::hash_bits_with_scratch(
                    execution()?,
                    input,
                    n_bits,
                    s_bits,
                    dest,
                    &mut scratch,
                )?;
                ensure(out == expected && report.route == route)?;
                let mut state = api::$name::new_bits(execution()?, n_bits, s_bits)?;
                ensure(state.is_customized() == (nb != 0 || sb != 0))?;
                let setup = state.setup_bytes();
                // Independent encoded-length arithmetic, including non-aligned N/S.
                let integer_len = |bits: usize| -> usize {
                    let bytes = usize::BITS
                        .saturating_sub(bits.leading_zeros())
                        .div_ceil(8)
                        .max(1);
                    usize::try_from(bytes).unwrap_or_default().saturating_add(1)
                };
                let encoded_bits = 2_usize
                    .saturating_add(integer_len(nb))
                    .saturating_add(integer_len(sb))
                    .saturating_mul(8)
                    .saturating_add(nb)
                    .saturating_add(sb);
                let expected_setup = if nb == 0 && sb == 0 {
                    0
                } else {
                    encoded_bits.div_ceil($rate * 8).saturating_mul($rate)
                };
                ensure(setup == expected_setup as u128 && state.message_bytes() == 0)?;
                ensure(state.report().absorb_permutations == (expected_setup / $rate) as u128)?;
                let whole = xb / 8;
                for chunk in x.get(..whole).ok_or("whole")?.chunks(17) {
                    state.update(api::Public::new(chunk))?;
                }
                ensure(state.message_bytes() == whole as u128)?;
                let tail = shape(x.get(whole..).ok_or("tail")?, xb % 8)?;
                let mut reader = state.finalize_bits_xof(tail)?;
                // Poison outputs again: no-op/partial-write execution must fail.
                for (byte, expected) in out.iter_mut().zip(&expected) {
                    *byte = expected ^ 0xff;
                }
                let whole_out = ob / 8;
                for chunk in out
                    .get_mut(..whole_out)
                    .ok_or("whole output")?
                    .chunks_mut(19)
                {
                    reader.squeeze(chunk)?;
                }
                ensure(reader.output_bytes() == whole_out as u128)?;
                let final_output = out.get_mut(whole_out..).ok_or("output tail")?;
                let final_bits =
                    Fips202Output::new(final_output, valid(ob % 8)).map_err(|_| "final shape")?;
                let streamed = reader.squeeze_final_bits(final_bits)?;
                ensure(out == expected && streamed == report)?;
                if nb.is_multiple_of(8)
                    && sb.is_multiple_of(8)
                    && xb.is_multiple_of(8)
                    && ob.is_multiple_of(8)
                {
                    for (byte, expected) in out.iter_mut().zip(&expected) {
                        *byte = expected ^ 0xff;
                    }
                    let byte_report = api::$name::hash_with_scratch(
                        execution()?,
                        api::Public::new(&x),
                        api::Public::new(&n),
                        api::Public::new(&s),
                        &mut out,
                        &mut scratch,
                    )?;
                    ensure(out == expected && byte_report == report)?;
                }
            }};
        }
        match *algorithm {
            "cshake128" => check!(Cshake128, 168),
            "cshake256" => check!(Cshake256, 136),
            _ => return Err("identity".into()),
        }
        count = count.saturating_add(1);
    }
    ensure(count == 628)?;
    Ok(count)
}
