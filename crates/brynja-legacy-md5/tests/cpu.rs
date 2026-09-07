//! Ordinary dependency builds cannot execute unadmitted SIMD candidates.
#![cfg(feature = "cpu")]
use brynja_legacy_md5::{Md5Backend, Md5BackendError, Md5BackendSession};

#[test]
fn ordinary_dependency_build_cannot_execute_a_candidate() {
    assert!(!Md5Backend::X86Avx2.is_admitted());
    assert!(!Md5Backend::Aarch64Neon.is_admitted());
    assert!(matches!(
        Md5BackendSession::for_compiled_target().err(),
        Some(Md5BackendError::NotAdmitted | Md5BackendError::MissingFeatures)
    ));
}
