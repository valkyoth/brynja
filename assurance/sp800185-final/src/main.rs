use std::time::Instant;

mod benchmark;

fn main() {
    let mut args = std::env::args().skip(1);
    let benchmark = match (args.next().as_deref(), args.next()) {
        (None, None) => false,
        (Some("--benchmark"), None) => true,
        _ => {
            eprintln!("usage: brynja-sp800185-final-fixture [--benchmark]");
            std::process::exit(2);
        }
    };
    let started = Instant::now();
    match brynja_sp800185_final_fixture::run() {
        Ok(report) => {
            println!("SP 800-185 execution acceptance: PASS");
            println!("identities: {}", report.identities);
            println!("parallel comparisons: {}", report.parallel_cases);
            println!("bounded failure cases: {}", report.failure_cases);
            println!(
                "unadmitted Keccak candidates: {}",
                report.unadmitted_candidates
            );
            println!("elapsed_ns: {}", started.elapsed().as_nanos());
            println!("family closure: pending reviewed native evidence disposition");
            println!("independently verified: NO; FIPS 140-3 validated: NO");
            if benchmark && let Err(error) = benchmark::run() {
                eprintln!("SP 800-185 benchmark: FAIL: {error}");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("SP 800-185 execution acceptance: FAIL: {error:?}");
            std::process::exit(1);
        }
    }
}
