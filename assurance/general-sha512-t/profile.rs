//! Fixed local performance samples; never a timing-proof or backend admission.
use brynja_hash_sha2::{Sha512TBits, hardened_sha512_t_secret, sha512_t};
use std::{hint::black_box, io, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() != 1 {
        return Err(io::Error::other("profile takes no arguments").into());
    }
    brynja_general_sha512_t_consumer::resources::check()
        .map_err(|e| io::Error::other(format!("resource check: {e:?}")))?;
    let mut input = [0_u8; 16384];
    let mut output = [0xa5; 64];
    for t in [1, 9, 224, 256, 511] {
        let p = Sha512TBits::new(t).map_err(|_| io::Error::other("parameter"))?;
        for length in [0, 111, 112, 1024, 16384] {
            for pattern in [0, 0xff] {
                input.fill(pattern);
                let message = &input[..length];
                let expected = sha512_t(p, message).map_err(|_| io::Error::other("hash"))?;
                let mut ordinary = [0_u128; 9];
                let mut hardened = [0_u128; 9];
                for (plain_ns, secret_ns) in ordinary.iter_mut().zip(&mut hardened) {
                    let start = Instant::now();
                    for _ in 0..8 {
                        let value = sha512_t(p, black_box(message))
                            .map_err(|_| io::Error::other("ordinary hash"))?;
                        if black_box(value) != expected {
                            return Err(io::Error::other("ordinary output mismatch").into());
                        }
                    }
                    *plain_ns = start.elapsed().as_nanos();
                    let start = Instant::now();
                    for _ in 0..8 {
                        let destination = &mut output[..p.output_bytes()];
                        // Guaranteed incorrect before each invocation: a
                        // stale/no-op write must not match a previous result.
                        for (slot, expected_byte) in destination.iter_mut().zip(expected.as_bytes())
                        {
                            *slot = !expected_byte;
                        }
                        let value = hardened_sha512_t_secret(p, black_box(message), destination)
                            .map_err(|_| io::Error::other("hardened hash"))?;
                        if black_box(value.as_bytes()) != expected.as_bytes() {
                            return Err(io::Error::other("secret output mismatch").into());
                        }
                        drop(value);
                        if destination.iter().any(|byte| *byte != 0) {
                            return Err(io::Error::other("secret output not cleared").into());
                        }
                    }
                    *secret_ns = start.elapsed().as_nanos();
                }
                ordinary.sort_unstable();
                hardened.sort_unstable();
                println!(
                    "t={t} bytes={length} pattern={pattern} samples=9 operations=8 ordinary_median_ns={} hardened_median_ns={}",
                    ordinary[4], hardened[4]
                );
            }
        }
    }
    println!("General SHA-512/t performance profile: PASS; rows=50; scalar-only");
    println!("includes IV derivation, checking and cleanup; not a constant-time proof");
    Ok(())
}
