//! Public test vectors through real bounded threaded hardened multibuffer calls.
use brynja_crypto_cpu_std::keccak_hardened_batch::{Authority, Mode};
use brynja_hash_parallel_std::{
    CancellationToken,
    execution::batch::{Config, Executor, Preference, Report},
};
use std::{
    fmt::Write as _,
    io::{self, Read as _},
};
mod request;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn charge(total: &mut u64, calls: u64) -> Result<()> {
    *total = total.checked_add(calls).ok_or("vector counter overflow")?;
    Ok(())
}

fn report_check(report: Report, leaves: usize, workers: usize, width: Option<usize>) -> Result<()> {
    let groups = leaves.div_ceil(4);
    let accelerated = width.map_or(0, |width| leaves / width * width);
    if report.execution.leaves != leaves as u128
        || report.groups != groups as u128
        || report.execution.thread_width != workers.min(groups)
        || report.execution.root.is_some()
        || report.execution.accelerated_leaves != accelerated as u128
        || (report.vector_calls > 0) != (accelerated > 0)
    {
        return Err("leaf/group/thread/route accounting".into());
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("expected portable|prefer|required workers".into());
    }
    let (preference, mode) = match args[0].as_str() {
        "portable" => (Preference::Portable, Mode::Portable),
        "prefer" => (Preference::Prefer, Mode::Prefer),
        "required" => (Preference::Require, Mode::Require),
        _ => return Err("unknown mode".into()),
    };
    let workers: usize = args[1].parse()?;
    if !(1..=3).contains(&workers) {
        return Err("fixture worker bound".into());
    }
    let authority = Authority::new(mode).map_err(|e| format!("authority: {e:?}"))?;
    let width = authority
        .kernel()
        .map_err(|e| format!("kernel: {e:?}"))?
        .map(|kernel| kernel.width());
    // Root stays portable: this campaign qualifies multibuffer leaf routing.
    let executor = Executor::new(Config {
        workers,
        max_leaves: 4096,
        root: Preference::Portable,
        leaves: preference,
        minimum_permutations: 1,
        max_group_permutations: 4096,
    })
    .map_err(|e| format!("executor: {e:?}"))?;
    let scoped = brynja_hash_parallel_std::execution::batch::in_place::Executor::new(Config {
        workers,
        max_leaves: 4096,
        root: Preference::Portable,
        leaves: preference,
        minimum_permutations: 1,
        max_group_permutations: 4096,
    })
    .map_err(|e| format!("scoped executor: {e:?}"))?;
    let mut campaign = String::new();
    io::stdin().take(1_048_577).read_to_string(&mut campaign)?;
    if campaign.len() > 1_048_576 {
        return Err("campaign bound".into());
    }
    let mut rendered = String::new();
    let mut count = 0_usize;
    let mut total_vector = 0_u64;
    let mut max_thread_width = 0;
    for line in campaign.lines() {
        count = count.checked_add(1).ok_or("case count")?;
        if count > 512 || line.len() > 17000 {
            return Err("case bound".into());
        }
        let case = request::Case::parse(line)?;
        let request = case.request()?;
        let size = case.output_bits.div_ceil(8);
        let valid = request::valid(case.output_bits)?;
        let mut public = vec![0xa5; size + 1];
        let mut secret = vec![0xa5; size + 1];
        let mut scratch = vec![0x5a; size + 7];
        let cancellation = CancellationToken::new();
        let report = executor
            .hash_public_bits(
                &request,
                &mut public[..size],
                valid,
                &mut scratch,
                &cancellation,
            )
            .map_err(|e| format!("public: {e:?}"))?;
        report_check(report, case.leaves(), workers, width)?;
        charge(&mut total_vector, report.vector_calls)?;
        max_thread_width = max_thread_width.max(report.execution.thread_width);
        if scratch.iter().any(|byte| *byte != 0) || public.last() != Some(&0xa5) {
            return Err("scratch/canary cleanup".into());
        }
        let (owned, secret_report) = executor
            .hash_secret_bits(&request, &mut secret[..size], valid, &cancellation)
            .map_err(|e| format!("secret: {e:?}"))?;
        if owned.expose() != &public[..size] || secret_report != report {
            return Err("secret output/report mismatch".into());
        }
        charge(&mut total_vector, secret_report.vector_calls)?;
        drop(owned);
        if secret[..size].iter().any(|byte| *byte != 0) || secret.last() != Some(&0xa5) {
            return Err("secret Drop/canary cleanup".into());
        }
        let mut scoped_public = vec![0xa5; size];
        scratch.fill(0x5a);
        let scoped_report = scoped
            .hash_public_bits(
                &request,
                &mut scoped_public,
                valid,
                &mut scratch,
                &cancellation,
            )
            .map_err(|e| format!("scoped public: {e:?}"))?;
        if scoped_public != public[..size]
            || scoped_report != report
            || scratch.iter().any(|b| *b != 0)
        {
            return Err("scoped public output/report/clearing mismatch".into());
        }
        charge(&mut total_vector, scoped_report.vector_calls)?;
        let (owned, scoped_report) = scoped
            .hash_secret_bits(&request, &mut secret[..size], valid, &cancellation)
            .map_err(|e| format!("scoped secret: {e:?}"))?;
        if owned.expose() != &public[..size] || scoped_report != report {
            return Err("scoped secret output/report mismatch".into());
        }
        charge(&mut total_vector, scoped_report.vector_calls)?;
        drop(owned);
        if secret[..size].iter().any(|b| *b != 0) || secret.last() != Some(&0xa5) {
            return Err("scoped secret Drop/canary cleanup".into());
        }
        for byte in &public[..size] {
            write!(rendered, "{byte:02x}")?;
        }
        rendered.push('\n');
    }
    print!("{rendered}");
    eprintln!(
        "PARALLELHASH_BATCH_ORACLE: cases={count}; vector_calls={total_vector}; workers={workers}; max_thread_width={max_thread_width}; profiles=public,secret; cleanup=drop,scratch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn vector_counter_is_checked_and_atomic() {
        let mut count = u64::MAX;
        assert!(super::charge(&mut count, 0).is_ok());
        assert!(super::charge(&mut count, 1).is_err());
        assert_eq!(count, u64::MAX);
    }
}
