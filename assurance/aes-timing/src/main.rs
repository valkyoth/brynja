//! Fixed-width, synthetic AES contrasts. No constant-time qualification claim.
#![forbid(unsafe_code)]

use brynja_crypto::aes::{Aes128Key, PublicCiphertext};
use std::{fmt::Write, hint::black_box, time::Instant};

const SAMPLES: usize = 512;
const REPEAT: usize = 4;
const MODES: [&str; 6] = [
    "encrypt-key",
    "encrypt-block",
    "decrypt-key",
    "decrypt-block",
    "public-key",
    "public-block",
];
type Result<T> = std::result::Result<T, String>;

fn operation(mode: &str, secret: &[u8; 16], mut observe: impl FnMut(&[u8])) -> Result<()> {
    let fixed = [0x37; 16];
    let (input_key, input) = if mode.ends_with("-key") {
        (secret, &fixed)
    } else {
        (&fixed, secret)
    };
    let mut storage = [0; 16];
    let mut destination = [0; 16];
    let key = Aes128Key::new(input_key, &mut storage).map_err(|e| format!("{e:?}"))?;
    match mode {
        "encrypt-key" | "encrypt-block" => {
            let block = key
                .encrypt_block(input, &mut destination)
                .map_err(|e| format!("{e:?}"))?;
            observe(block.expose());
        }
        "decrypt-key" | "decrypt-block" => {
            let block = key
                .decrypt_block(input, &mut destination)
                .map_err(|e| format!("{e:?}"))?;
            observe(block.expose());
        }
        "public-key" | "public-block" => {
            key.encrypt_block_public(input, &mut destination, PublicCiphertext::acknowledge())
                .map_err(|e| format!("{e:?}"))?;
            observe(&destination);
        }
        _ => return Err("unknown operation".into()),
    }
    // Key and secret-output owners are dropped inside the measured call.
    Ok(())
}

fn measure(mode: &str, secret: &[u8; 16]) -> Result<u128> {
    let start = Instant::now();
    for _ in 0..REPEAT {
        operation(black_box(mode), black_box(secret), |bytes| {
            black_box(bytes);
        })?;
    }
    Ok(start.elapsed().as_nanos())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 || !matches!(args[0].as_str(), "preflight" | "measure") {
        return Err("expected preflight or measure".into());
    }
    let preflight = args[0] == "preflight";
    let secrets = [[0; 16], [0xff; 16]];
    let mut records = Vec::new();
    for mode in MODES {
        if preflight {
            for (class, secret) in secrets.iter().enumerate() {
                let mut hex = String::new();
                operation(mode, secret, |bytes| {
                    for byte in bytes {
                        write!(hex, "{byte:02x}").expect("String write");
                    }
                })?;
                records.push(format!("VECTOR {mode} {class} {hex}"));
            }
            continue;
        }
        // Exactly 256 AB and 256 BA measured pairs after 32 warmups. Allocation,
        // formatting and stdout occur outside the timed operation repetitions.
        for sample in 0..SAMPLES + 32 {
            let first = sample % 2;
            let mut elapsed = [0; 2];
            for class in [first, 1 - first] {
                elapsed[class] = measure(mode, &secrets[class])?;
            }
            if sample >= 32 {
                records.push(format!(
                    "SAMPLE {mode} {} {} {}",
                    sample - 32,
                    elapsed[0],
                    elapsed[1]
                ));
            }
        }
    }
    for record in records {
        println!("{record}");
    }
    println!("AES_TIMING_END {}", args[0]);
    Ok(())
}
