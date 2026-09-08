//! Bounded native/QEMU evidence runner; never enables a production backend.
use brynja_crypto_cpu::Sha512BackendSession;
use brynja_hash_sha2::*;
use std::{hint::black_box, io, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    if args.next().is_some() || first.as_ref().is_some_and(|s| s != "--quarantine") {
        return Err(io::Error::other("expected no arguments or --quarantine").into());
    }
    let backend = Sha512BackendSession::for_compiled_target().ok_or_else(|| {
        io::Error::other("required SHA-512 CPU candidate unavailable; no fallback")
    })?;
    if first.is_some() {
        brynja_general_sha512_t_cpu_fixture::quarantine(&backend)
            .map_err(|e| io::Error::other(format!("quarantine failed: {e:?}")))?;
        println!("General SHA-512/t quarantine acceptance: PASS");
        return Ok(());
    }
    let corpus =
        include_str!("../../../crates/brynja-hash-sha2/tests/vectors/general-sha512-t-digest.txt");
    let count = brynja_general_sha512_t_cpu_fixture::run(corpus, &backend)
        .map_err(|e| io::Error::other(format!("acceptance failed: {e:?}")))?;
    if count != 4590 {
        return Err(io::Error::other("incomplete corpus").into());
    }
    println!(
        "General SHA-512/t CPU acceptance: PASS; parameters=510; cases=4590; backend={}",
        backend.backend().as_str()
    );
    let bytes = [0xa5; 16384];
    for t in [1, 9, 224, 256, 511] {
        let p = Sha512TBits::new(t).map_err(|_| io::Error::other("parameter"))?;
        let expected = sha512_t(p, &bytes).map_err(|_| io::Error::other("portable control"))?;
        let start = Instant::now();
        for _ in 0..32 {
            let value = sha512_t_with_backend(p, black_box(&bytes), &backend)
                .map_err(|_| io::Error::other("CPU execution failed"))?;
            if black_box(value) != expected {
                return Err(io::Error::other("CPU mismatch").into());
            }
        }
        println!(
            "t={t} bytes=16384 operations=32 accelerated_ns={}",
            start.elapsed().as_nanos()
        );
    }
    println!(
        "candidate=unadmitted; hardened=portable-only; independently_verified=false; fips_validated=false"
    );
    Ok(())
}
