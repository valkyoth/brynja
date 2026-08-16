use brynja_crypto_cpu::Sha512Backend;
use brynja_hash_sha2::{
    Sha384Digest, Sha512_224Digest, Sha512_256Digest, Sha512Digest, sha384, sha512, sha512_224,
    sha512_256,
};

/// Why the runtime SHA-512-family selector uses its current route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RuntimeSha512Selection {
    /// No compatible complete feature bundle was observed; scalar is active.
    ScalarNoFeature,
    /// A candidate feature bundle exists but has no native admission.
    ScalarBackendUnadmitted,
}

/// Secret-free report for the SHA-512-family runtime decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeSha512Report {
    selection: RuntimeSha512Selection,
    backend: Option<Sha512Backend>,
}

impl RuntimeSha512Report {
    /// Returns the exact selection outcome.
    #[must_use]
    pub const fn selection(self) -> RuntimeSha512Selection {
        self.selection
    }

    /// Returns the detected candidate identity, if any.
    #[must_use]
    pub const fn backend(self) -> Option<Sha512Backend> {
        self.backend
    }
}

/// Closed runtime SHA-512-family failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RuntimeSha512Error {
    /// Required acceleration is not admitted.
    RequiredAccelerationUnavailable,
    /// The input exceeds the selected algorithm's message domain.
    MessageTooLong,
}

/// Reusable runtime selection for SHA-384, SHA-512 and SHA-512/t.
///
/// This milestone intentionally falls back to scalar on x86_64 and for every
/// unadmitted AArch64 or RISC-V candidate. The report makes that decision
/// visible and never promotes feature detection into authorization.
pub struct RuntimeSha512Backend {
    report: RuntimeSha512Report,
}

impl RuntimeSha512Backend {
    /// Detects a candidate feature bundle and selects the admitted route.
    #[must_use]
    pub fn opportunistic() -> Self {
        match crate::runtime_detection::detected_sha512_backend() {
            Some(backend) => Self {
                report: RuntimeSha512Report {
                    selection: RuntimeSha512Selection::ScalarBackendUnadmitted,
                    backend: Some(backend),
                },
            },
            None => Self {
                report: RuntimeSha512Report {
                    selection: RuntimeSha512Selection::ScalarNoFeature,
                    backend: None,
                },
            },
        }
    }

    /// Rejects until one SHA-512-family backend has native admission.
    pub fn required() -> Result<Self, RuntimeSha512Error> {
        Err(RuntimeSha512Error::RequiredAccelerationUnavailable)
    }

    /// Returns the current non-authorizing selection report.
    #[must_use]
    pub const fn report(&self) -> RuntimeSha512Report {
        self.report
    }

    /// Hashes one complete input with SHA-384 through the selected route.
    pub fn sha384(&self, input: &[u8]) -> Result<Sha384Digest, RuntimeSha512Error> {
        sha384(input).map_err(|_| RuntimeSha512Error::MessageTooLong)
    }

    /// Hashes one complete input with SHA-512 through the selected route.
    pub fn sha512(&self, input: &[u8]) -> Result<Sha512Digest, RuntimeSha512Error> {
        sha512(input).map_err(|_| RuntimeSha512Error::MessageTooLong)
    }

    /// Hashes one complete input with SHA-512/224 through the selected route.
    pub fn sha512_224(&self, input: &[u8]) -> Result<Sha512_224Digest, RuntimeSha512Error> {
        sha512_224(input).map_err(|_| RuntimeSha512Error::MessageTooLong)
    }

    /// Hashes one complete input with SHA-512/256 through the selected route.
    pub fn sha512_256(&self, input: &[u8]) -> Result<Sha512_256Digest, RuntimeSha512Error> {
        sha512_256(input).map_err(|_| RuntimeSha512Error::MessageTooLong)
    }
}

impl Default for RuntimeSha512Backend {
    fn default() -> Self {
        Self::opportunistic()
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeSha512Backend, RuntimeSha512Error, RuntimeSha512Selection};

    #[test]
    fn all_four_identities_use_an_honestly_reported_selection() {
        let backend = RuntimeSha512Backend::opportunistic();
        assert!(matches!(
            backend.report().selection(),
            RuntimeSha512Selection::ScalarNoFeature
                | RuntimeSha512Selection::ScalarBackendUnadmitted
        ));
        assert!(backend.sha384(b"abc").is_ok());
        assert!(backend.sha512(b"abc").is_ok());
        assert!(backend.sha512_224(b"abc").is_ok());
        assert!(backend.sha512_256(b"abc").is_ok());
        assert!(matches!(
            RuntimeSha512Backend::required(),
            Err(RuntimeSha512Error::RequiredAccelerationUnavailable)
        ));
    }
}
