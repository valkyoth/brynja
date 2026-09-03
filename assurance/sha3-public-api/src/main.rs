fn main() {
    match brynja_sha3_public_api_fixture::run() {
        Ok(report) => {
            println!("Complete SHA-3/SHAKE portable public API acceptance: PASS");
            println!("algorithm identities: {}", report.algorithms);
            println!("fixed-output results: {}", report.fixed_output_results);
            println!("XOF results: {}", report.xof_results);
            println!(
                "incremental squeeze results: {}",
                report.incremental_squeeze_results
            );
            println!("bit-domain results: {}", report.bit_domain_results);
            println!("execution path: portable-only");
            println!("independently verified: NO");
            println!("FIPS 140-3 validated: NO");
            println!("family status: Fully implemented at v0.24.11");
            println!("unkeyed hashes and XOFs; not authentication, MACs, or password hashing");
        }
        Err(error) => {
            eprintln!("Complete SHA-3/SHAKE portable public API acceptance: FAIL: {error:?}");
            std::process::exit(1);
        }
    }
}
