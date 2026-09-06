use brynja_legacy_sha1::{AcceleratedSha1, BitString, Sha1BackendHealth, Sha1BackendSession, sha1};
use std::{error::Error, hint::black_box, time::Instant};

// Replay the byte-identical v0.24.20 corpus, including its real-file bytes.
#[path = "../../legacy-hash-public-api/src/vectors.rs"]
mod frozen;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() > 1 || args.first().is_some_and(|arg| arg != "--benchmark") {
        return Err("usage: sha1-cpu-public-api [--benchmark]".into());
    }
    let session = Sha1BackendSession::for_compiled_target()
        .map_err(|_| "no compiled evidence session; ordinary builds must stay unadmitted")?;
    assert_eq!(session.health(), Sha1BackendHealth::Healthy);
    for (data, digest, _) in frozen::FILES {
        assert_eq!(
            AcceleratedSha1::hash(&session, data).map_err(|_| "backend hash failed")?,
            *digest
        );
        for partition in [1, 7, 31, 64, 113] {
            let mut state = AcceleratedSha1::new(&session).map_err(|_| "start failed")?;
            for chunk in data.chunks(partition) {
                state.update(chunk).map_err(|_| "stream failed")?;
            }
            assert_eq!(state.finalize().map_err(|_| "finalize failed")?, *digest);
        }
    }
    for (data, width, digest, _) in frozen::BITS {
        let bits = BitString::new(data, *width).map_err(|_| "frozen bit encoding failed")?;
        assert_eq!(
            AcceleratedSha1::hash_bits(&session, bits).map_err(|_| "bit hashing failed")?,
            *digest
        );
    }
    let mut vectors = 0;
    for line in include_str!("../../../crates/brynja-legacy-sha1/tests/vectors/nist.txt").lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split('|').collect();
        let [length, message, digest] = fields.as_slice() else {
            return Err("invalid pinned vector row".into());
        };
        let bits: usize = length.parse()?;
        let bytes = hex(message)?;
        let width = if bits == 0 {
            0
        } else {
            u8::try_from((bits - 1) % 8 + 1)?
        };
        let used = bits.checked_add(7).ok_or("length overflow")? / 8;
        let tail = BitString::new(bytes.get(..used).ok_or("short vector")?, width)
            .map_err(|_| "noncanonical vector")?;
        assert_eq!(
            AcceleratedSha1::hash_bits(&session, tail)
                .map_err(|_| "NIST hashing failed")?
                .as_slice(),
            hex(digest)?
        );
        vectors += 1;
    }
    assert_eq!(vectors, 529);
    println!(
        "SHA-1 CPU acceptance: PASS; backend={}; frozen_cases=20; nist_vectors={vectors}",
        session.backend().as_str()
    );
    println!("candidate=unadmitted; hardened=portable-only; independent-review=NO; FIPS=NO");
    if !args.is_empty() {
        benchmark(&session)?;
    }
    Ok(())
}

fn hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value == "-" {
        return Ok(Vec::new());
    }
    if value.len() > 32768 || value.len() % 2 != 0 {
        return Err("invalid bounded vector hex".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn benchmark(session: &Sha1BackendSession) -> Result<(), Box<dyn Error>> {
    for size in [64, 1024, 16384] {
        for value in [0_u8, 0xa5] {
            let input = vec![value; size];
            let start = Instant::now();
            for _ in 0..32 {
                black_box(sha1(black_box(&input)).map_err(|_| "portable rejected")?);
            }
            let scalar = start.elapsed().as_nanos();
            let start = Instant::now();
            for _ in 0..32 {
                black_box(
                    AcceleratedSha1::hash(session, black_box(&input))
                        .map_err(|_| "candidate rejected")?,
                );
            }
            println!(
                "benchmark bytes={size} pattern={value} samples=32 scalar_ns={scalar} candidate_ns={}",
                start.elapsed().as_nanos()
            );
        }
    }
    println!(
        "timing=exploratory-public-input; NOT-side-channel-approval; migration-safety=unproven"
    );
    Ok(())
}
