//! Installed downstream binary. All inputs are public oracle fixtures.
use brynja_crypto::chacha20::ChaCha20;
mod differential;
mod backend;
use backend::Backend;

fn main() {
    let path = std::env::args_os().nth(1).expect("public corpus path");
    let data = std::fs::read(path).expect("read public corpus");
    match differential::replay(&data) {
        Ok(302) => println!("PASS 302 {}", ChaCha20::NAME),
        Err(reason) => {
            eprintln!("{reason}");
            std::process::exit(2);
        }
        Ok(_) => panic!("incomplete public corpus"),
    }
}
