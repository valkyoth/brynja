//! Bounded hosted adapter; hashing/acceptance library remains no_std.
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(3_000_001)?;
    io::stdin().lock().take(3_000_001).read_to_end(&mut bytes)?;
    if bytes.len() > 3_000_000 {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "corpus exceeds 3000000 bytes").into(),
        );
    }
    let corpus = std::str::from_utf8(&bytes)?;
    let count = brynja_general_sha512_t_consumer::acceptance::run(corpus).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("acceptance failed: {error:?}"),
        )
    })?;
    println!("General SHA-512/t portable public acceptance: PASS");
    println!("parameters: 510; independent cases: {count}");
    println!("ordinary/hardened byte/bit one-shot and streaming: PASS");
    println!("package-external evidence; scalar only; final closure: pending v0.24.29");
    println!("independently verified: NO; FIPS validated: NO");
    Ok(())
}
