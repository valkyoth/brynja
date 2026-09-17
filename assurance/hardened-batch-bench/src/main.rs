//! Public synthetic workloads only; timing does not establish side-channel safety.
mod common;
mod keccak;
mod sha2;
use common::Result;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 || !["portable", "prefer"].contains(&args[0].as_str()) {
        return Err("expected portable|prefer".into());
    }
    sha2::narrow(&args[0])?;
    sha2::wide(&args[0])?;
    keccak::run(&args[0])?;
    println!(
        "HARDENED_BATCH_BENCHMARK: PASS; cases=640; samples=7; threshold=1; timing=digest,validate,drop; independent_review=NO"
    );
    Ok(())
}
