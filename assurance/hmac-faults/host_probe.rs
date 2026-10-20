//! Compile WITHOUT target features before compiling/executing native fixtures.
fn main() {
    let route = std::env::args().nth(1).expect("explicit route");
    #[cfg(target_arch = "x86_64")]
    let available = match route.as_str() {
        "sha256" => std::is_x86_feature_detected!("sha") && std::is_x86_feature_detected!("sse2"),
        "sha512" => {
            std::is_x86_feature_detected!("sha512")
                && std::is_x86_feature_detected!("avx2")
                && std::is_x86_feature_detected!("avx")
        }
        "keccak" => std::is_x86_feature_detected!("avx2"),
        _ => false,
    };
    #[cfg(target_arch = "aarch64")]
    let available = match route.as_str() {
        "sha256" => {
            std::arch::is_aarch64_feature_detected!("sha2")
                && std::arch::is_aarch64_feature_detected!("neon")
        }
        "sha512" | "keccak" => {
            std::arch::is_aarch64_feature_detected!("sha3")
                && std::arch::is_aarch64_feature_detected!("neon")
        }
        _ => false,
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let available = false;
    assert!(available, "required host instructions unavailable");
    println!("HMAC_HOST_FEATURES: {route}");
}
