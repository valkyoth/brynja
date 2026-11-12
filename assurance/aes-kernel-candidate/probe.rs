//! Baseline-compiled host probe before executing a target-specialized test.
fn main() {
    #[cfg(target_arch = "x86_64")]
    let supported = std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2");
    #[cfg(target_arch = "aarch64")]
    let supported = cfg!(target_endian = "little")
        && std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull")
        && std::arch::is_aarch64_feature_detected!("neon");
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let supported = false;
    if !supported {
        eprintln!("AES static host bundle unavailable; no specialized tests executed");
        std::process::exit(2);
    }
    println!("AES_STATIC_HOST_BUNDLE_PASS");
}
