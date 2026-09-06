//! Ordinary-build admission rejection, separate from candidate unit tests.
#![cfg(feature = "cpu")]
use brynja_legacy_sha1::{Sha1BackendError, Sha1BackendSession};

#[test]
fn ordinary_library_build_cannot_enter_candidate_instructions() {
    // The dependency is built without cfg(test), unlike the kernel unit tests.
    if !cfg!(all(feature = "cpu-evidence", brynja_sha1_cpu_evidence)) {
        let compiled = cfg!(any(
            all(
                any(target_arch = "x86", target_arch = "x86_64"),
                target_feature = "sha",
                target_feature = "sse2"
            ),
            all(
                target_arch = "aarch64",
                target_endian = "little",
                target_feature = "neon",
                target_feature = "sha2"
            )
        ));
        let expected = if compiled {
            Sha1BackendError::NotAdmitted
        } else {
            Sha1BackendError::MissingFeatures
        };
        assert_eq!(
            Sha1BackendSession::for_compiled_target().err(),
            Some(expected)
        );
    }
}
