//! Only public generated vectors are printed, after explicit declassification.
use brynja_crypto_cpu_std::keccak_hardened_batch::Authority;
use brynja_hash_sha3::hardened_batch::{
    Control, Input, Mode, Report, Sha3PublicDeclassification, Workspace,
};
use std::{
    fmt::Write as _,
    io::{self, Read as _},
};
mod request;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_BYTES: u64 = 8 * 1024 * 1024;

fn destinations<'a>(
    inputs: &[Option<Input<'_>>; 4],
    storage: &'a mut [Vec<u8>; 4],
) -> [Option<&'a mut [u8]>; 4] {
    let [a, b, c, d] = storage;
    let mut output = [None, None, None, None];
    for ((out, bytes), input) in output.iter_mut().zip([a, b, c, d]).zip(inputs) {
        if let Some(input) = input {
            *out = Some(&mut bytes[..input.output_bytes()]);
        }
    }
    output
}

fn cleared(storage: &[Vec<u8>; 4]) -> bool {
    storage.iter().all(|bytes| {
        bytes
            .split_last()
            .is_some_and(|(canary, used)| *canary == 0xa5 && used.iter().all(|byte| *byte == 0))
    })
}

fn charge(total: &mut u64, report: Report, used: u64) -> Result<()> {
    if report
        .vector_permutations
        .checked_add(report.scalar_permutations)
        != Some(used)
        || (report.vector_calls == 0) != report.kernel.is_none()
    {
        return Err("work accounting/route".into());
    }
    *total = total
        .checked_add(report.vector_calls)
        .ok_or("vector counter overflow")?;
    Ok(())
}

fn main() -> Result<()> {
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
    let authority = Authority::new(mode).map_err(|e| format!("authority: {e:?}"))?;
    let executor = authority
        .executor(1)
        .map_err(|e| format!("executor: {e:?}"))?;
    let mut campaign = String::new();
    io::stdin()
        .take(MAX_BYTES + 1)
        .read_to_string(&mut campaign)?;
    if campaign.len() as u64 > MAX_BYTES {
        return Err("campaign bound".into());
    }
    let mut rendered = String::new();
    let mut count = 0_usize;
    let mut total_vector = 0_u64;
    let mut workspace = Workspace::new();
    for line in campaign.lines() {
        count = count.checked_add(1).ok_or("batch counter")?;
        if count > 1024 || line.len() > 100_000 {
            return Err("case bound".into());
        }
        let fields: Vec<_> = line.split(';').collect();
        if fields.len() != 4 {
            return Err("four slots required".into());
        }
        let requests: Vec<_> = fields
            .iter()
            .map(|text| {
                if *text == "-" {
                    Ok(None)
                } else {
                    request::parse(text).map(Some)
                }
            })
            .collect::<Result<_>>()?;
        let mut inputs = [None, None, None, None];
        for (input, request) in inputs.iter_mut().zip(&requests) {
            *input = request.as_ref().map(request::Request::input).transpose()?;
        }
        let buffers = || {
            core::array::from_fn(|i| {
                vec![0xa5; inputs[i].as_ref().map_or(0, Input::output_bytes) + 1]
            })
        };
        let mut secret: [Vec<u8>; 4] = buffers();
        let mut public: [Vec<u8>; 4] = buffers();
        let total = inputs
            .iter()
            .flatten()
            .try_fold(0_usize, |n, input| n.checked_add(input.output_bytes()))
            .ok_or("output bound")?;
        // Extra staging bytes must clear too, not just the used output prefix.
        let mut staging = vec![0x5a; total.checked_add(7).ok_or("staging bound")?];
        let mut cancel = || false;
        let mut control = Control::new(4096, &mut cancel);
        let (owned, report) = executor
            .digest_secret(
                &inputs,
                destinations(&inputs, &mut secret),
                &mut workspace,
                &mut staging,
                &mut control,
            )
            .map_err(|e| format!("secret: {e:?}"))?;
        charge(&mut total_vector, report, control.used())?;
        for (i, input) in inputs.iter().enumerate() {
            if owned.algorithm(i) != input.as_ref().map(Input::algorithm)
                || owned.output_bits(i) != input.as_ref().map(Input::output_bits)
                || owned.expose(i).map(<[u8]>::len) != input.as_ref().map(Input::output_bytes)
            {
                return Err("secret identity/width".into());
            }
        }
        owned
            .declassify(
                destinations(&inputs, &mut public),
                Sha3PublicDeclassification::acknowledge(),
            )
            .map_err(|e| format!("declassify: {e:?}"))?;
        if !cleared(&secret) || staging.iter().any(|byte| *byte != 0) {
            return Err("declassification/staging cleanup".into());
        }
        secret = buffers();
        staging.fill(0x5a);
        let mut control = Control::new(4096, &mut cancel);
        let (owned, report) = executor
            .digest_secret(
                &inputs,
                destinations(&inputs, &mut secret),
                &mut workspace,
                &mut staging,
                &mut control,
            )
            .map_err(|e| format!("secret repeat: {e:?}"))?;
        charge(&mut total_vector, report, control.used())?;
        for (i, input) in inputs.iter().enumerate() {
            if let Some(input) = input
                && owned.expose(i) != Some(&public[i][..input.output_bytes()])
            {
                return Err("secret repeat mismatch".into());
            }
        }
        drop(owned);
        if !cleared(&secret) || staging.iter().any(|byte| *byte != 0) {
            return Err("Drop/staging cleanup".into());
        }
        let mut direct = buffers();
        staging.fill(0x5a);
        let mut control = Control::new(4096, &mut cancel);
        let report = executor
            .digest_public(
                &inputs,
                destinations(&inputs, &mut direct),
                &mut workspace,
                &mut staging,
                &mut control,
                Sha3PublicDeclassification::acknowledge(),
            )
            .map_err(|e| format!("public: {e:?}"))?;
        charge(&mut total_vector, report, control.used())?;
        if direct != public || staging.iter().any(|byte| *byte != 0) {
            return Err("public output/staging mismatch".into());
        }
        for (i, input) in inputs.iter().enumerate() {
            if public[i].last() != Some(&0xa5) {
                return Err("destination canary".into());
            }
            if i != 0 {
                rendered.push(';');
            }
            if let Some(input) = input {
                for byte in &public[i][..input.output_bytes()] {
                    write!(rendered, "{byte:02x}")?;
                }
            } else {
                rendered.push('-');
            }
        }
        rendered.push('\n');
    }
    print!("{rendered}");
    eprintln!(
        "HARDENED_KECCAK_BATCH: batches={count}; vector_calls={total_vector}; profiles=secret,declassified,public; cleanup=drop,declassify,staging"
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
            kernel: Some(brynja_hash_sha3::hardened_batch::Kernel::Avx2),
            ..Default::default()
        };
        assert!(super::charge(&mut total, report, 0).is_err());
        assert_eq!(total, u64::MAX);
        assert!(super::charge(&mut total, super::Report::default(), 1).is_err());
    }
}
