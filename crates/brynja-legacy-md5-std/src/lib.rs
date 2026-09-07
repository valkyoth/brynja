//! Optional host selection for collision-broken legacy MD5.
//!
//! Detection is observational, not execution authority. No backend is admitted;
//! opportunistic operations use the portable leaf, and required acceleration
//! fails before hashing. The safe adapter cannot mint the migration authority
//! needed by the experimental instruction sessions. No global registration,
//! affinity changes, process policy, allocation or external dependency is added.

use brynja_legacy_md5::{BitString, Md5, Md5Backend, Md5Error};

/// Public, non-authorizing reason for portable selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    /// No complete compiler/CPU bundle is reported on this architecture.
    ScalarNoFeatures,
    /// The detected instruction candidate lacks reviewed admission evidence.
    ScalarNotAdmitted,
    /// A future admission still needs a reviewed migration-safe host authority.
    ScalarNoExecutionAuthority,
}

/// Secret-free host observation; not a certificate or execution permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Candidate detected by the host feature mechanism, if any.
    pub detected: Option<Md5Backend>,
    /// Why this operation remains portable.
    pub selection: Selection,
}

/// Required acceleration cannot be authorized by a CPU observation alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredAccelerationUnavailable;

/// Explicit reusable host selection. No accelerated session can be forged here.
pub struct RuntimeMd5Backend {
    report: Report,
}

impl RuntimeMd5Backend {
    /// Observes the host and chooses portable fallback while admission is absent.
    pub fn opportunistic() -> Self {
        let detected = detected_backend();
        let selection = match detected {
            None => Selection::ScalarNoFeatures,
            Some(backend) if !backend.is_admitted() => Selection::ScalarNotAdmitted,
            Some(_) => Selection::ScalarNoExecutionAuthority,
        };
        Self {
            report: Report {
                detected,
                selection,
            },
        }
    }

    /// Fails closed: no safe migration-qualified acceleration authority exists.
    pub fn required() -> Result<Self, RequiredAccelerationUnavailable> {
        Err(RequiredAccelerationUnavailable)
    }

    /// Returns the selection observation; this grants no backend capability.
    pub const fn report(&self) -> Report {
        self.report
    }

    /// Hashes eight ordered slots portably, atomically and within caller limits.
    pub fn batch(
        &self,
        inputs: &[Option<BitString<'_>>; 8],
        output: &mut [[u8; 16]; 8],
        control: &mut brynja_legacy_md5::Md5BatchControl<'_>,
    ) -> Result<brynja_legacy_md5::Md5BatchReport, brynja_legacy_md5::Md5BatchError> {
        brynja_legacy_md5::Md5Batch::new().digest(inputs, output, control)
    }

    /// Starts an ordinary public-data stream. Hardened owners use the leaf API.
    pub fn start(&self) -> Md5 {
        Md5::new()
    }

    /// Hashes a complete public byte message using the selected portable route.
    pub fn hash(&self, bytes: &[u8]) -> Result<[u8; 16], Md5Error> {
        brynja_legacy_md5::md5(bytes)
    }

    /// Hashes a canonical complete public bit message using the portable route.
    pub fn hash_bits(&self, bits: BitString<'_>) -> Result<[u8; 16], Md5Error> {
        brynja_legacy_md5::md5_bits(bits)
    }
}

impl Default for RuntimeMd5Backend {
    fn default() -> Self {
        Self::opportunistic()
    }
}

fn detected_backend() -> Option<Md5Backend> {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        return Some(Md5Backend::X86Avx2);
    }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("neon") {
        return Some(Md5Backend::Aarch64Neon);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_is_observational_and_required_fails_closed() {
        let selected = RuntimeMd5Backend::opportunistic();
        assert_eq!(
            RuntimeMd5Backend::required().err(),
            Some(RequiredAccelerationUnavailable)
        );
        assert!(matches!(
            selected.report().selection,
            Selection::ScalarNoFeatures | Selection::ScalarNotAdmitted
        ));
        let mut state = selected.start();
        assert_eq!(state.update(b"a"), Ok(()));
        assert_eq!(state.update(b"bc"), Ok(()));
        assert_eq!(selected.hash(b"abc"), Ok(state.finalize()));
        let bits = BitString::new(&[0xa0], 3);
        assert!(bits.is_ok());
        if let Ok(bits) = bits {
            assert_eq!(selected.hash_bits(bits), brynja_legacy_md5::md5_bits(bits));
        }
    }
}
