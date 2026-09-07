use brynja_legacy_md5::{BitString, Md5BackendSession, Md5Batch, Md5BatchControl};
use std::{error::Error, hint::black_box, time::Instant};

#[path = "../../legacy-hash-public-api/src/vectors.rs"]
mod frozen;

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.iter().any(|arg| arg != "--benchmark") || arguments.len() > 1 {
        return Err("expected only optional --benchmark".into());
    }
    let session =
        Md5BackendSession::for_compiled_target().map_err(|_| "no compiled evidence session")?;
    let mut cases = 0_usize;
    // Independent, frozen pre-SIMD acceptance corpus, including arbitrary bits.
    for (data, _, expected) in frozen::FILES {
        check_frozen(
            &session,
            data,
            if data.is_empty() { 0 } else { 8 },
            expected,
        )?;
        cases += 1;
    }
    for (data, width, _, expected) in frozen::BITS {
        check_frozen(&session, data, *width, expected)?;
        cases += 1;
    }
    if cases != 20 {
        return Err("frozen corpus incomplete".into());
    }
    let mut comparisons = 0_usize;
    for length in [
        0_usize, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1024, 4096,
    ] {
        let mut messages: Vec<Vec<u8>> = (0..8)
            .map(|i| {
                (0..length + i)
                    .map(|j| (j.wrapping_mul(97) ^ i) as u8)
                    .collect()
            })
            .collect();
        for valid in 1..=8 {
            for message in &mut messages {
                if let Some(last) = message.last_mut() {
                    *last &= 0xff_u8 << (8 - valid);
                }
            }
            for mask in [0_u16, 1, 15, 85, 127, 128, 240, 254, 255] {
                let mut inputs = [None; 8];
                for (i, (slot, bytes)) in inputs.iter_mut().zip(&messages).enumerate() {
                    if mask & (1 << i) != 0 {
                        *slot = Some(
                            BitString::new(bytes, if bytes.is_empty() { 0 } else { valid })
                                .map_err(|_| "canonical bit input rejected")?,
                        );
                    }
                }
                let mut scalar = [[0; 16]; 8];
                let mut simd = scalar;
                Md5Batch::new().digest(&inputs, &mut scalar, &mut Md5BatchControl::new(1024))?;
                let report = Md5Batch::new().digest_with_backend(
                    &inputs,
                    &mut simd,
                    &mut Md5BatchControl::new(1024),
                    &session,
                )?;
                if scalar != simd {
                    return Err("lane, bit or padding mismatch".into());
                }
                if mask == 255 && length > 64 && report.vector_blocks == 0 {
                    return Err("no vector work performed".into());
                }
                comparisons += 1;
            }
        }
    }
    permutations(&session)?;
    println!(
        "MD5 CPU acceptance: PASS; backend={}; frozen_cases={cases}; batch_comparisons={comparisons}; lane_permutations=16",
        session.backend().as_str()
    );
    println!("candidate=unadmitted; hardened=portable-only; no FIPS or independent review");
    if !arguments.is_empty() {
        benchmark(&session)?;
    }
    Ok(())
}

fn permutations(session: &Md5BackendSession) -> Result<(), Box<dyn Error>> {
    let messages: [Vec<u8>; 8] = core::array::from_fn(|i| vec![i as u8; 129 + i]);
    let mut inputs = [None; 8];
    for (slot, message) in inputs.iter_mut().zip(&messages) {
        *slot = Some(BitString::new(message, 8).map_err(|_| "permutation input rejected")?);
    }
    let mut reference = [[0; 16]; 8];
    Md5Batch::new().digest(&inputs, &mut reference, &mut Md5BatchControl::new(64))?;
    for rotation in 0..8 {
        for reverse in [false, true] {
            let order: [usize; 8] =
                core::array::from_fn(|i| ((if reverse { 7 - i } else { i }) + rotation) % 8);
            let permuted = order.map(|i| inputs[i]);
            let expected = order.map(|i| reference[i]);
            let mut actual = [[0; 16]; 8];
            let report = Md5Batch::new().digest_with_backend(
                &permuted,
                &mut actual,
                &mut Md5BatchControl::new(64),
                session,
            )?;
            if actual != expected || report.vector_blocks != 16 {
                return Err("lane permutation or vector-work mismatch".into());
            }
        }
    }
    Ok(())
}

fn check_frozen(
    session: &Md5BackendSession,
    bytes: &[u8],
    valid: u8,
    expected: &[u8],
) -> Result<(), Box<dyn Error>> {
    let bits = BitString::new(bytes, valid).map_err(|_| "frozen bit input rejected")?;
    let mut actual = [[0xa5; 16]; 8];
    Md5Batch::new().digest_with_backend(
        &[Some(bits); 8],
        &mut actual,
        &mut Md5BatchControl::new(4096),
        session,
    )?;
    for digest in actual {
        if digest.as_slice() != expected {
            return Err("frozen digest mismatch".into());
        }
    }
    Ok(())
}

fn benchmark(session: &Md5BackendSession) -> Result<(), Box<dyn Error>> {
    for length in [64, 1024, 16384] {
        let data = vec![0xa5; length];
        let bits = BitString::new(&data, 8).map_err(|_| "benchmark input rejected")?;
        for active in [1, 4, 8] {
            let inputs = core::array::from_fn(|i| if i < active { Some(bits) } else { None });
            let mut times = [0_u128; 2];
            let mut vector_blocks = 0;
            for (route, time) in times.iter_mut().enumerate() {
                let start = Instant::now();
                for _ in 0..32 {
                    let mut output = [[0; 16]; 8];
                    let mut control = Md5BatchControl::new(4096);
                    let report = if route == 0 {
                        Md5Batch::new().digest(black_box(&inputs), &mut output, &mut control)?
                    } else {
                        Md5Batch::new().digest_with_backend(
                            black_box(&inputs),
                            &mut output,
                            &mut control,
                            session,
                        )?
                    };
                    black_box(output);
                    if route == 1 {
                        vector_blocks = report.vector_blocks;
                    }
                }
                *time = start.elapsed().as_nanos();
            }
            println!(
                "benchmark: bytes={length} active={active} samples=32 scalar_ns={} selected_ns={} vector_blocks={vector_blocks}",
                times[0], times[1]
            );
        }
    }
    Ok(())
}
