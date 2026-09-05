fn main() {
    match brynja_sp800185_public_api_fixture::run() {
        Ok(report) => {
            println!("SP 800-185 portable public API acceptance: PASS");
            println!("named identities: {}", report.identities);
            println!("official NIST examples: {}", report.official_examples);
            println!("hardened identity profiles: {}", report.hardened_profiles);
            println!("public package layers: {}", report.public_layers);
            println!("execution path: forced portable no_std");
            println!("family status: In progress pending v0.24.17 final acceptance");
            println!("independently verified: NO");
            println!("FIPS 140-3 validated: NO");
        }
        Err(error) => {
            eprintln!("SP 800-185 portable public API acceptance: FAIL: {error:?}");
            std::process::exit(1);
        }
    }
}
