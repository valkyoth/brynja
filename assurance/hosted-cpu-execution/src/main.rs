fn main() {
    match brynja_hosted_cpu_execution_fixture::validate() {
        Ok(count) => {
            println!("Hosted CPU execution acceptance: PASS");
            println!("operational kernels: {count}");
            println!("independently verified: NO; FIPS validated: NO");
        }
        Err(error) => {
            eprintln!("Hosted CPU execution acceptance failed: {error:?}");
            std::process::exit(1);
        }
    }
}
