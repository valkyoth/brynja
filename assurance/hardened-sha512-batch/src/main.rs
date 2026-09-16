//! Prints only public generated test vectors after explicit declassification.
use brynja_crypto_cpu_std::sha512_hardened_batch::{Authority, Mode};
use brynja_hash_sha2::hardened_batch512::{Control, PublicDeclassification, Report, Workspace};
use std::io::{self, BufRead, Read, Write};
mod request;
use request::Request;

fn charge(total: &mut u64, report: Report, used: u64) -> Result<(), String> {
    if report.vector_blocks.checked_add(report.scalar_blocks) != Some(used) {
        return Err("work accounting".into());
    }
    *total = total
        .checked_add(report.vector_calls)
        .ok_or("vector counter overflow")?;
    Ok(())
}

fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("expected portable|prefer|required".into());
    }
    let mode = match args[0].as_str() {
        "portable" => Mode::Portable,
        "prefer" => Mode::Prefer,
        "required" => Mode::Require,
        _ => return Err("expected portable|prefer|required".into()),
    };
    let authority = Authority::new(mode).map_err(|e| format!("{e:?}"))?;
    let executor = authority.executor(1).map_err(|e| format!("{e:?}"))?;
    let mut workspace = Workspace::new();
    let mut reader = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut count = 0_usize;
    let mut total_vector = 0_u64;
    loop {
        let mut line = Vec::new();
        (&mut reader)
            .take(66_001)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if line.is_empty() {
            break;
        }
        if count >= 16384 {
            return Err("campaign bound".into());
        }
        let request = Request::parse(&line)?;
        let inputs = request.inputs()?;
        let mut secret = [[0xa5; 64]; 4];
        let mut public = [[0xa5; 64]; 4];
        let mut cancelled = || false;
        let mut control = Control::new(1024, &mut cancelled);
        let (owned, report) = executor
            .digest_secret(
                &inputs,
                request.destinations(&mut secret),
                &mut workspace,
                &mut control,
            )
            .map_err(|e| format!("{e:?}"))?;
        charge(&mut total_vector, report, control.used())?;
        for (index, meta) in request.metadata.iter().enumerate() {
            if owned.algorithm(index) != meta.map(|(algorithm, _)| algorithm)
                || owned.expose(index).map(<[u8]>::len)
                    != meta.map(|(algorithm, _)| algorithm.output_bytes())
            {
                return Err("secret identity/width".into());
            }
        }
        owned
            .declassify(
                request.destinations(&mut public),
                PublicDeclassification::acknowledge(),
            )
            .map_err(|e| format!("{e:?}"))?;
        if !request.cleared(&secret) {
            return Err("declassification cleanup".into());
        }
        // A second call checks Drop independently of explicit declassification.
        secret = [[0xa5; 64]; 4];
        let mut control = Control::new(1024, &mut cancelled);
        let (owned, report) = executor
            .digest_secret(
                &inputs,
                request.destinations(&mut secret),
                &mut workspace,
                &mut control,
            )
            .map_err(|e| format!("{e:?}"))?;
        charge(&mut total_vector, report, control.used())?;
        for (index, meta) in request.metadata.iter().enumerate() {
            if let Some((algorithm, _)) = meta
                && owned.expose(index) != Some(&public[index][..algorithm.output_bytes()])
            {
                return Err("secret repeat mismatch".into());
            }
        }
        drop(owned);
        if !request.cleared(&secret) {
            return Err("Drop cleanup".into());
        }
        let mut direct = [[0xa5; 64]; 4];
        let mut control = Control::new(1024, &mut cancelled);
        let report = executor
            .digest_public(
                &inputs,
                request.destinations(&mut direct),
                &mut workspace,
                &mut control,
                PublicDeclassification::acknowledge(),
            )
            .map_err(|e| format!("{e:?}"))?;
        charge(&mut total_vector, report, control.used())?;
        if direct != public {
            return Err("public/secret mismatch".into());
        }
        for (index, (bytes, meta)) in public.iter().zip(request.metadata).enumerate() {
            if index != 0 {
                write!(output, ";").map_err(|e| e.to_string())?;
            }
            if let Some((algorithm, _)) = meta {
                for byte in &bytes[..algorithm.output_bytes()] {
                    write!(output, "{byte:02x}").map_err(|e| e.to_string())?;
                }
            } else {
                write!(output, "-").map_err(|e| e.to_string())?;
            }
        }
        writeln!(output).map_err(|e| e.to_string())?;
        count += 1;
    }
    output.flush().map_err(|e| e.to_string())?;
    eprintln!(
        "HARDENED_SHA512_BATCH: batches={count}; vector_calls={total_vector}; profiles=secret,declassified,public; cleanup=drop,declassify"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn report_overflow_is_atomic() {
        let mut total = u64::MAX;
        let report = super::Report {
            vector_calls: 1,
            ..Default::default()
        };
        assert!(super::charge(&mut total, report, 0).is_err());
        assert_eq!(total, u64::MAX);
        assert!(super::charge(&mut total, super::Report::default(), 1).is_err());
    }
}
