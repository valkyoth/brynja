//! Opt-in standard-library CPU detection for accelerated Brynja SHA-256.
//!
//! This adapter performs host feature detection, creates one caller-owned
//! KAT-gated backend session, and exposes scalar-fallback or required-
//! acceleration modes. It is not used by the `brynja` facade, default feature
//! graph, protocol engines, or future FIPS module.

mod runtime_detection;

use brynja_crypto_cpu::{
    Sha256Backend, Sha256BackendError, Sha256BackendHealth, Sha256BackendReport,
    Sha256BackendSession,
};
use brynja_hash_sha2::{Sha256, Sha256AcceleratedError, Sha256Digest, Sha256Error};

/// Why one runtime SHA-256 backend was selected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RuntimeSha256Selection {
    /// Runtime feature detection and the direct KAT admitted acceleration.
    Accelerated,
    /// No compatible complete feature bundle was observed; scalar is active.
    ScalarNoFeature,
    /// A detected backend failed its KAT; scalar is active.
    ScalarBackendQuarantined,
    /// A backend was detected but native evidence has not admitted it.
    ScalarBackendUnadmitted,
}

/// Secret-free report for one runtime selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeSha256Report {
    selection: RuntimeSha256Selection,
    backend: Option<Sha256Backend>,
    backend_report: Option<Sha256BackendReport>,
}

impl RuntimeSha256Report {
    /// Returns the selection outcome.
    #[must_use]
    pub const fn selection(self) -> RuntimeSha256Selection {
        self.selection
    }

    /// Returns the detected backend, if any.
    #[must_use]
    pub const fn backend(self) -> Option<Sha256Backend> {
        self.backend
    }

    /// Returns its KAT and health report, if a session was constructed.
    #[must_use]
    pub const fn backend_report(self) -> Option<Sha256BackendReport> {
        self.backend_report
    }
}

/// Closed runtime SHA-256 failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RuntimeSha256Error {
    /// Required acceleration is unavailable or failed its startup KAT.
    RequiredAccelerationUnavailable,
    /// The input exceeds SHA-256's byte-oriented message domain.
    MessageTooLong,
    /// The selected caller-owned session is quarantined.
    BackendQuarantined,
    /// The selected backend no longer matches this architecture.
    WrongArchitecture,
    /// The backend implementation lacks complete native admission evidence.
    BackendNotAdmitted,
    /// A newer backend failure is unknown to this adapter version.
    BackendUnavailable,
}

/// Reusable caller-owned runtime backend selection.
///
/// This value is deliberately neither `Send` nor `Sync`, matching the exact
/// current-thread feature observation used to enter ISA-specific code.
pub struct RuntimeSha256Backend {
    session: Option<Sha256BackendSession>,
    report: RuntimeSha256Report,
}

impl RuntimeSha256Backend {
    /// Detects acceleration and otherwise selects portable scalar SHA-256.
    #[must_use]
    pub fn opportunistic() -> Self {
        let Some(backend) = runtime_detection::detected_backend() else {
            return Self::scalar(RuntimeSha256Selection::ScalarNoFeature, None, None);
        };
        match runtime_detection::construct_session(backend) {
            Ok(session) if session.health() == Sha256BackendHealth::Healthy => {
                let report = RuntimeSha256Report {
                    selection: RuntimeSha256Selection::Accelerated,
                    backend: Some(backend),
                    backend_report: Some(session.report()),
                };
                Self {
                    session: Some(session),
                    report,
                }
            }
            Ok(session) => Self::scalar(
                RuntimeSha256Selection::ScalarBackendQuarantined,
                Some(backend),
                Some(session.report()),
            ),
            Err(Sha256BackendError::NotAdmitted) => Self::scalar(
                RuntimeSha256Selection::ScalarBackendUnadmitted,
                Some(backend),
                None,
            ),
            Err(_) => Self::scalar(
                RuntimeSha256Selection::ScalarBackendQuarantined,
                Some(backend),
                None,
            ),
        }
    }

    /// Requires a detected, KAT-healthy accelerated backend or fails closed.
    pub fn required() -> Result<Self, RuntimeSha256Error> {
        let selected = Self::opportunistic();
        if selected.report.selection == RuntimeSha256Selection::Accelerated {
            Ok(selected)
        } else {
            Err(RuntimeSha256Error::RequiredAccelerationUnavailable)
        }
    }

    /// Returns the current non-authorizing selection report.
    #[must_use]
    pub fn report(&self) -> RuntimeSha256Report {
        match self.session.as_ref() {
            Some(session) => RuntimeSha256Report {
                backend_report: Some(session.report()),
                ..self.report
            },
            None => self.report,
        }
    }

    /// Starts an empty streaming SHA-256 operation using this selection.
    #[must_use]
    pub fn start(&self) -> RuntimeSha256<'_> {
        RuntimeSha256 {
            state: Sha256::new(),
            backend: self,
        }
    }

    /// Hashes one complete byte slice using this selection.
    pub fn hash(&self, input: &[u8]) -> Result<Sha256Digest, RuntimeSha256Error> {
        let mut state = self.start();
        state.update(input)?;
        state.finalize()
    }

    fn scalar(
        selection: RuntimeSha256Selection,
        backend: Option<Sha256Backend>,
        backend_report: Option<Sha256BackendReport>,
    ) -> Self {
        Self {
            session: None,
            report: RuntimeSha256Report {
                selection,
                backend,
                backend_report,
            },
        }
    }
}

impl Default for RuntimeSha256Backend {
    fn default() -> Self {
        Self::opportunistic()
    }
}

/// Streaming SHA-256 state bound to one reusable runtime selection.
pub struct RuntimeSha256<'backend> {
    state: Sha256,
    backend: &'backend RuntimeSha256Backend,
}

impl RuntimeSha256<'_> {
    /// Returns the number of message bytes accepted so far.
    #[must_use]
    pub const fn message_bytes(&self) -> u64 {
        self.state.message_bytes()
    }

    /// Absorbs the complete input or rejects it before changing visible state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), RuntimeSha256Error> {
        match self.backend.session.as_ref() {
            Some(session) => self
                .state
                .update_with_backend(input, session)
                .map_err(map_accelerated_error),
            None => self.state.update(input).map_err(map_scalar_error),
        }
    }

    /// Consumes this state and returns the exact digest.
    pub fn finalize(self) -> Result<Sha256Digest, RuntimeSha256Error> {
        match self.backend.session.as_ref() {
            Some(session) => self
                .state
                .finalize_with_backend(session)
                .map_err(map_accelerated_error),
            None => Ok(self.state.finalize()),
        }
    }
}

fn map_scalar_error(error: Sha256Error) -> RuntimeSha256Error {
    match error {
        Sha256Error::MessageTooLong => RuntimeSha256Error::MessageTooLong,
        _ => RuntimeSha256Error::BackendUnavailable,
    }
}

fn map_accelerated_error(error: Sha256AcceleratedError) -> RuntimeSha256Error {
    match error {
        Sha256AcceleratedError::MessageTooLong => RuntimeSha256Error::MessageTooLong,
        Sha256AcceleratedError::WrongArchitecture => RuntimeSha256Error::WrongArchitecture,
        Sha256AcceleratedError::BackendNotAdmitted => RuntimeSha256Error::BackendNotAdmitted,
        Sha256AcceleratedError::BackendQuarantined => RuntimeSha256Error::BackendQuarantined,
        Sha256AcceleratedError::BackendUnavailable => RuntimeSha256Error::BackendUnavailable,
        _ => RuntimeSha256Error::BackendUnavailable,
    }
}

/// Detects the host backend and hashes one complete byte slice.
pub fn sha256(input: &[u8]) -> Result<(Sha256Digest, RuntimeSha256Report), RuntimeSha256Error> {
    let backend = RuntimeSha256Backend::opportunistic();
    let digest = backend.hash(input)?;
    Ok((digest, backend.report()))
}

/// Whether host runtime CPU detection is implemented.
pub const RUNTIME_DETECTION_IMPLEMENTED: bool = true;

/// Whether the required no_std CPU package contains SHA-256 candidate code.
pub const CPU_BACKEND_IMPLEMENTED: bool = brynja_crypto_cpu::IMPLEMENTED;

#[cfg(test)]
mod tests {
    use super::{
        CPU_BACKEND_IMPLEMENTED, RUNTIME_DETECTION_IMPLEMENTED, RuntimeSha256Backend,
        RuntimeSha256Selection, sha256,
    };

    #[test]
    fn runtime_one_shot_matches_sha256_abc() {
        let result = sha256(b"abc");
        assert!(result.is_ok());
        let Ok((digest, report)) = result else {
            return;
        };
        assert_eq!(
            digest.as_bytes(),
            &[
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert!(matches!(
            report.selection(),
            RuntimeSha256Selection::Accelerated
                | RuntimeSha256Selection::ScalarNoFeature
                | RuntimeSha256Selection::ScalarBackendUnadmitted
        ));
    }

    #[test]
    fn irregular_streaming_matches_portable() {
        let backend = RuntimeSha256Backend::opportunistic();
        let mut state = backend.start();
        for chunk in b"runtime dispatch preserves streaming boundaries".chunks(3) {
            assert_eq!(state.update(chunk), Ok(()));
        }
        let accelerated = state.finalize();
        let portable = brynja_hash_sha2::sha256(b"runtime dispatch preserves streaming boundaries");
        assert_eq!(
            accelerated,
            portable.map_err(|_| super::RuntimeSha256Error::MessageTooLong)
        );
    }

    #[test]
    fn runtime_contract_is_active() {
        assert!(core::hint::black_box(RUNTIME_DETECTION_IMPLEMENTED));
        assert!(core::hint::black_box(CPU_BACKEND_IMPLEMENTED));
    }
}
