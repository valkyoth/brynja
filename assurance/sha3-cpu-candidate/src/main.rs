fn main() {
    match brynja_sha3_cpu_candidate_fixture::run() {
        Ok(report) => {
            println!("SHA-3/SHAKE forced CPU candidate differential: PASS");
            println!("backend: {}", report.backend.as_str());
            println!("fixed-output results: {}", report.fixed_output_results);
            println!("XOF results: {}", report.xof_results);
            println!("public dispatch admission: NO");
        }
        Err(error) => {
            eprintln!("SHA-3/SHAKE forced CPU candidate differential: FAIL: {error:?}");
            std::process::exit(1);
        }
    }
}
