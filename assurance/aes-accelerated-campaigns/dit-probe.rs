//! Compile without specialized target flags; run before DIT-specialized fixtures.
#![forbid(unsafe_code)]

fn main() {
    #[cfg(target_arch = "aarch64")]
    let supported = cfg!(target_endian = "little")
        && std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull")
        && std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("dit");
    #[cfg(not(target_arch = "aarch64"))]
    let supported = false;
    if !supported {
        eprintln!("AES/DIT host bundle unavailable; no specialized tests executed");
        std::process::exit(2);
    }
    println!("AES_DIT_HOST_BUNDLE_PASS");
}
