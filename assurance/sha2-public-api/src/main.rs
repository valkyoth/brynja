fn main() {
    match brynja_sha2_public_api_fixture::run() {
        Ok(report) => {
            println!("Complete SHA-2 public API acceptance: PASS");
            println!("algorithm identities: {}", report.algorithms);
            println!("one-shot results: {}", report.one_shot_results);
            println!("streaming results: {}", report.streaming_results);
            println!("arbitrary-bit results: {}", report.bit_input_results);
            println!("hardened public/secret results: {}", report.hardened_results);
            println!("admitted accelerated backends executed: {}", report.admitted_backends);
            println!(
                "unadmitted accelerated backends skipped: {}",
                report.skipped_unadmitted_backends
            );
            println!("SHA-224: portable scalar; independently verified: NO; FIPS validated: NO");
            println!("SHA-256: portable scalar; independently verified: NO; FIPS validated: NO");
            println!("SHA-384: portable scalar; independently verified: NO; FIPS validated: NO");
            println!("SHA-512: portable scalar; independently verified: NO; FIPS validated: NO");
            println!("SHA-512/224: portable scalar; independently verified: NO; FIPS validated: NO");
            println!("SHA-512/256: portable scalar; independently verified: NO; FIPS validated: NO");
            println!("ordinary states are unkeyed; hardened states own secret-bearing memory");
        }
        Err(error) => {
            eprintln!("Complete SHA-2 public API acceptance: FAIL: {error:?}");
            std::process::exit(1);
        }
    }
}
