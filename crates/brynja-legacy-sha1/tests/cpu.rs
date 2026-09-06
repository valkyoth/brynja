//! Ordinary-build admission rejection, separate from candidate unit tests.
#![cfg(feature = "cpu")]
use brynja_legacy_sha1::{Sha1BackendError, Sha1BackendSession};

#[test]
fn ordinary_library_build_cannot_enter_candidate_instructions() {
    // The dependency is built without cfg(test), unlike the kernel unit tests.
    if !cfg!(brynja_cpu_evidence) {
        assert!(matches!(
            Sha1BackendSession::for_compiled_target().err(),
            Some(Sha1BackendError::NotAdmitted | Sha1BackendError::MissingFeatures)
        ));
    }
}
