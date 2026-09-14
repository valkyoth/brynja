use brynja_hash_sha2::{BitString, Sha256Digest, batch::*};
use std::io::{self, BufRead, Read, Write};
mod benchmark;

fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mode = match args.first().map(String::as_str) {
        Some("portable") => Mode::Portable,
        Some("prefer") => Mode::Prefer,
        Some("required") => Mode::Require,
        _ => return Err("expected portable|prefer|required [--benchmark]".into()),
    };
    let authority =
        brynja_crypto_cpu_std::sha256_batch::Authority::new(mode).map_err(|e| format!("{e:?}"))?;
    let executor = authority.executor(1).map_err(|e| format!("{e:?}"))?;
    if args.get(1).map(String::as_str) == Some("--benchmark") {
        return benchmark::run(&executor);
    }
    if args.len() != 1 {
        return Err("unexpected arguments".into());
    }
    let mut reader = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut total_vector = 0_u64;
    let mut count = 0_usize;
    loop {
        let mut line = Vec::new();
        // Eight slots, each at most 4096 bytes encoded as hex, plus metadata.
        (&mut reader)
            .take(66_001)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if line.is_empty() {
            break;
        }
        if line.len() > 66_000 || count >= 8192 {
            return Err("campaign bound".into());
        }
        count += 1;
        let text = std::str::from_utf8(&line)
            .map_err(|e| e.to_string())?
            .trim_end();
        let slots: Vec<_> = text.split(';').collect();
        if slots.len() != 8 {
            return Err("exactly eight slots required".into());
        }
        let mut storage: [Vec<u8>; 8] = core::array::from_fn(|_| Vec::new());
        let mut metadata = [None; 8];
        for ((slot, bytes), meta) in slots.iter().zip(&mut storage).zip(&mut metadata) {
            if *slot == "-" {
                continue;
            }
            let parts: Vec<_> = slot.split(':').collect();
            let [algorithm, bits, hex] = parts.as_slice() else {
                return Err("invalid slot".into());
            };
            let algorithm = match *algorithm {
                "sha224" => Algorithm::Sha224,
                "sha256" => Algorithm::Sha256,
                _ => return Err("identity".into()),
            };
            let bits = bits.parse::<usize>().map_err(|e| e.to_string())?;
            if bits > 32768 || hex.len() > 8192 || hex.len() % 2 != 0 || !hex.is_ascii() {
                return Err("input bound/encoding".into());
            }
            for pair in hex.as_bytes().chunks_exact(2) {
                let pair = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
                bytes.push(u8::from_str_radix(pair, 16).map_err(|e| e.to_string())?);
            }
            if bits.div_ceil(8) != bytes.len() {
                return Err("length mismatch".into());
            }
            *meta = Some((algorithm, bits));
        }
        let mut inputs = [None; 8];
        for ((bytes, meta), input) in storage.iter().zip(metadata).zip(&mut inputs) {
            if let Some((algorithm, length)) = meta {
                let valid = if length == 0 {
                    0
                } else if length % 8 == 0 {
                    8
                } else {
                    u8::try_from(length % 8).map_err(|e| e.to_string())?
                };
                let bits = BitString::new(bytes, valid).map_err(|e| format!("{e:?}"))?;
                *input = Some(Input::new(algorithm, bits));
            }
        }
        let mut digests = [Some(Digest::Sha256(Sha256Digest::from_bytes([0xa5; 32]))); 8];
        let mut cancelled = || false;
        let mut control = Control::new(520, &mut cancelled);
        let report = executor
            .digest(PublicData::new(&inputs), &mut digests, &mut control)
            .map_err(|e| format!("{e:?}"))?;
        if control.used() != report.vector_blocks + report.scalar_blocks {
            return Err("work accounting".into());
        }
        total_vector += report.vector_calls;
        for (index, digest) in digests.into_iter().enumerate() {
            if index != 0 {
                write!(output, ";").map_err(|e| e.to_string())?;
            }
            match digest {
                Some(Digest::Sha224(digest)) => hex(&mut output, digest.as_bytes())?,
                Some(Digest::Sha256(digest)) => hex(&mut output, digest.as_bytes())?,
                None => write!(output, "-").map_err(|e| e.to_string())?,
            }
        }
        writeln!(output).map_err(|e| e.to_string())?;
    }
    output.flush().map_err(|e| e.to_string())?;
    eprintln!("SHA256_BATCH_ACCEPTANCE: batches={count}; vector_calls={total_vector}");
    Ok(())
}

fn hex(output: &mut impl Write, bytes: &[u8]) -> Result<(), String> {
    for byte in bytes {
        write!(output, "{byte:02x}").map_err(|e| e.to_string())?;
    }
    Ok(())
}
