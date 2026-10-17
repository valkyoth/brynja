"""Bounded CLI adapter for existing ParallelHash execution fixture drivers."""

MAIN = r'''
#![forbid(unsafe_code)]
use std::{fmt::Write as _, io::{self, Read as _}};
use brynja_hash_parallel::{Fips202BitString, execution::Identity};
mod request;
mod execution;
mod scoped_execution;
mod scoped_accelerated;
mod scoped_scheduled_accelerated;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn invalid(line: usize, message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("line {}: {message}", line + 1))
}
fn bounded_vec(size: usize, line: usize, message: &str) -> std::result::Result<Vec<u8>, io::Error> {
    let mut value = Vec::new();
    value.try_reserve_exact(size).map_err(|_| invalid(line, message))?;
    value.resize(size, 0);
    Ok(value)
}
fn valid_bits(bits: usize) -> u8 {
    if bits == 0 { 0 } else { ((bits - 1) % 8 + 1) as u8 }
}
fn bit_string(bytes: &[u8], bits: usize, line: usize) -> std::result::Result<Fips202BitString<'_>, io::Error> {
    if bytes.len() != bits.div_ceil(8) { return Err(invalid(line, "bit length mismatch")); }
    Fips202BitString::new(bytes, valid_bits(bits)).map_err(|_| invalid(line, "noncanonical bits"))
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [mode] = args.as_slice() else { return Err("one route required".into()); };
    if !["portable", "scheduled", "prefer", "required", "static", "stream",
         "stream-prefer", "stream-required", "stream-static", "threads-portable",
         "threads-prefer", "threads-required", "threads-static"].contains(&mode.as_str()) {
        return Err("unknown route".into());
    }
    let scoped = matches!(mode.as_str(), "static" | "stream-static" | "threads-static");
    let mut campaign = String::new();
    io::stdin().take(1_048_577).read_to_string(&mut campaign)?;
    if campaign.len() > 1_048_576 { return Err("campaign bound".into()); }
    let mut rendered = String::new();
    let mut count = 0_usize;
    for (line, input) in campaign.lines().enumerate() {
        count = count.checked_add(1).ok_or("case count")?;
        if count > 512 || input.len() > 17000 { return Err("case bound".into()); }
        let case = request::Case::parse(input)?;
        let request = case.request()?;
        let algorithm = match request.identity {
            Identity::ParallelHash128 => "parallel128",
            Identity::ParallelHash256 => "parallel256",
            Identity::ParallelHashXof128 => "parallelxof128",
            Identity::ParallelHashXof256 => "parallelxof256",
        };
        let size = case.output_bits.div_ceil(8);
        let mut output = vec![0xa5; size + 1];
        execution::run(algorithm, request.customization, request.input, case.output_bits,
                       request.block_size, &mut output[..size], line)?;
        if output[size] != 0xa5 { return Err("output canary".into()); }
        if scoped {
            scoped_accelerated::check(algorithm, request.customization, request.input,
                valid_bits(case.output_bits), request.block_size, &output[..size])?;
            scoped_scheduled_accelerated::check(algorithm, request.customization, request.input,
                valid_bits(case.output_bits), request.block_size, &output[..size])?;
        }
        for byte in &output[..size] { write!(rendered, "{byte:02x}")?; }
        rendered.push('\n');
    }
    print!("{rendered}");
    eprintln!("PARALLELHASH_EXECUTION: cases={count}; mode={mode}; scoped={}", if scoped { count } else { 0 });
    Ok(())
}
'''
