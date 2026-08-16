#![allow(unsafe_code)]

use brynja_crypto_cpu::Sha512Backend;
use brynja_crypto_cpu::{Sha256Backend, Sha256BackendError, Sha256BackendSession};

pub(crate) fn detected_backend() -> Option<Sha256Backend> {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("sha") {
        return Some(Sha256Backend::X86Sha);
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("sha2")
    {
        return Some(Sha256Backend::Aarch64Sha2);
    }
    None
}

pub(crate) fn construct_session(
    backend: Sha256Backend,
) -> Result<Sha256BackendSession, Sha256BackendError> {
    // SAFETY: `detected_backend` is the only caller and returns an identity only
    // after the standard library reports every required target feature on the
    // current architecture. The returned session is thread-bound and performs
    // a direct KAT before exposing compression.
    unsafe { Sha256BackendSession::from_runtime_detection(backend) }
}

pub(crate) fn detected_sha512_backend() -> Option<Sha512Backend> {
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("sha3")
    {
        return Some(Sha512Backend::Aarch64Sha512);
    }
    None
}
