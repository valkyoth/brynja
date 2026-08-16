fn main() {
    match brynja_sha256_public_api_fixture::run() {
        Ok(report) => {
            println!("SHA-256 public API acceptance: PASS");
            println!("fixed messages: {}", report.fixed_messages);
            println!("irregular streams: {}", report.streaming_messages);
            println!("admitted accelerated routes: {}", report.admitted_backends);
            println!(
                "unadmitted accelerated routes skipped: {}",
                report.skipped_unadmitted_backends
            );
            println!("independently verified: NO");
            println!("FIPS 140-3 validated: NO");
            println!("unkeyed hash; not authentication, a MAC, or password hashing");
        }
        Err(error) => {
            eprintln!("SHA-256 public API acceptance: FAIL: {error:?}");
            std::process::exit(1);
        }
    }
}
