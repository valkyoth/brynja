fn main() {
    match brynja_hash_final_acceptance_fixture::run() {
        Ok(report) => {
            println!("Combined SHA-2 and SHA-3/SHAKE final acceptance: PASS");
            println!("SHA-2 identities: {}", report.sha2_identities);
            println!("SHA-3/SHAKE identities: {}", report.fips202_identities);
            println!(
                "accelerated candidates inventoried: {}",
                report.backend_candidates
            );
            println!(
                "accelerated backends admitted: {}",
                report.admitted_backends
            );
            println!("SHA-2: Fully implemented; independently verified: NO; FIPS validated: NO");
            println!(
                "SHA-3/SHAKE: Fully implemented; independently verified: NO; FIPS validated: NO"
            );
        }
        Err(error) => {
            eprintln!("Combined SHA-2 and SHA-3/SHAKE final acceptance: FAIL: {error:?}");
            std::process::exit(1);
        }
    }
}
