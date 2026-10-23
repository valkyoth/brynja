//! Generic binary: check native CPU/OS support before building static routes.
fn main() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("expected exactly one family");
    }
    let family = args[0].as_str();
    #[cfg(target_arch = "x86_64")]
    let supported = match family {
        "sha1" => std::is_x86_feature_detected!("sha") && std::is_x86_feature_detected!("sse2"),
        "md5" => std::is_x86_feature_detected!("avx2"),
        _ => false,
    };
    #[cfg(target_arch = "aarch64")]
    let supported = match family {
        "sha1" => std::arch::is_aarch64_feature_detected!("neon")
            && std::arch::is_aarch64_feature_detected!("sha2"),
        "md5" => std::arch::is_aarch64_feature_detected!("neon"),
        _ => false,
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let supported = false;
    if !supported {
        return Err("required native features unavailable");
    }
    println!("LEGACY_HMAC_HOST_FEATURES: {family}");
    Ok(())
}
