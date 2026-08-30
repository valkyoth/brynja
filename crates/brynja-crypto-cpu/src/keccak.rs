#![allow(unsafe_code)]

use core::{cell::Cell, marker::PhantomData};

use crate::keccak_constants::ZERO_STATE_RESULT;

/// One implemented Keccak-f\[1600\] instruction-backend identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KeccakBackend {
    /// x86_64 AVX2 vector operations.
    X86Avx2,
    /// AArch64 NEON and dedicated SHA-3 operations.
    Aarch64Sha3,
}

impl KeccakBackend {
    /// Returns the stable backend identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86Avx2 => "x86-avx2-keccak",
            Self::Aarch64Sha3 => "aarch64-sha3-keccak",
        }
    }

    /// Returns the complete target-feature bundle required for execution.
    #[must_use]
    pub const fn required_features(self) -> &'static [&'static str] {
        match self {
            Self::X86Avx2 => &["avx2"],
            Self::Aarch64Sha3 => &["neon", "sha3"],
        }
    }

    /// Reports whether complete evidence currently admits public dispatch.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        false
    }
}

/// Caller-owned health of one exact Keccak backend session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KeccakBackendHealth {
    /// The direct zero-state KAT is running.
    Testing,
    /// The direct KAT passed.
    Healthy,
    /// This session permanently rejected the backend.
    Quarantined,
}

/// Closed accelerated Keccak backend failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KeccakBackendError {
    /// The backend belongs to another architecture.
    WrongArchitecture,
    /// The implementation lacks complete admission evidence.
    NotAdmitted,
    /// The direct startup KAT failed permanently.
    Quarantined,
}

/// Secret-free report for one caller-owned Keccak session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeccakBackendReport {
    backend: KeccakBackend,
    health: KeccakBackendHealth,
    generation: u64,
}

impl KeccakBackendReport {
    /// Returns the exact backend identity.
    #[must_use]
    pub const fn backend(self) -> KeccakBackend {
        self.backend
    }

    /// Returns the current health state.
    #[must_use]
    pub const fn health(self) -> KeccakBackendHealth {
        self.health
    }

    /// Returns the caller-owned health generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Non-forgeable, thread-bound Keccak-f\[1600\] candidate session.
///
/// The permutation entry is available only to repository evidence builds.
/// Ordinary consumers cannot obtain a raw permutation API or activate either
/// unadmitted backend.
pub struct KeccakBackendSession {
    backend: KeccakBackend,
    health: Cell<KeccakBackendHealth>,
    generation: Cell<u64>,
    _thread_bound: PhantomData<*mut ()>,
}

impl KeccakBackendSession {
    /// Selects an admitted backend proven by compile-time target features.
    ///
    /// Both v0.24.4 candidates are unadmitted, so this returns `None` until a
    /// later reviewed evidence decision changes that disposition.
    #[must_use]
    pub fn for_compiled_target() -> Option<Self> {
        let backend = compiled_backend()?;
        Self::construct(backend, false).ok()
    }

    /// Constructs an unadmitted session only for commit-bound evidence.
    ///
    /// # Safety
    ///
    /// The evidence runner must prove every required feature on the executing
    /// logical CPU, prevent migration to an incompatible CPU, and retain exact
    /// runner provenance. A false claim can execute an unsupported instruction.
    #[cfg(brynja_cpu_evidence)]
    pub unsafe fn for_candidate_evidence(
        backend: KeccakBackend,
    ) -> Result<Self, KeccakBackendError> {
        Self::construct(backend, false)
    }

    /// Returns the selected backend identity.
    #[must_use]
    pub const fn backend(&self) -> KeccakBackend {
        self.backend
    }

    /// Returns the current health state.
    #[must_use]
    pub fn health(&self) -> KeccakBackendHealth {
        self.health.get()
    }

    /// Returns a non-authorizing health report.
    #[must_use]
    pub fn report(&self) -> KeccakBackendReport {
        KeccakBackendReport {
            backend: self.backend,
            health: self.health.get(),
            generation: self.generation.get(),
        }
    }

    /// Applies the KAT-tested permutation in a repository evidence build.
    #[cfg(brynja_cpu_evidence)]
    pub fn permute_for_evidence(&self, state: &mut [u64; 25]) -> Result<(), KeccakBackendError> {
        self.ensure_healthy()?;
        permute_direct(self.backend, state)
    }

    #[cfg(any(test, brynja_cpu_evidence))]
    fn ensure_healthy(&self) -> Result<(), KeccakBackendError> {
        if self.health.get() == KeccakBackendHealth::Healthy {
            Ok(())
        } else {
            Err(KeccakBackendError::Quarantined)
        }
    }

    fn construct(backend: KeccakBackend, corrupt_answer: bool) -> Result<Self, KeccakBackendError> {
        require_architecture(backend)?;
        if !backend.is_admitted() && !cfg!(any(test, brynja_cpu_evidence)) {
            return Err(KeccakBackendError::NotAdmitted);
        }
        let session = Self {
            backend,
            health: Cell::new(KeccakBackendHealth::Testing),
            generation: Cell::new(1),
            _thread_bound: PhantomData,
        };
        let mut state = [0_u64; 25];
        permute_direct(backend, &mut state)?;
        session.generation.set(2);
        session
            .health
            .set(if state == ZERO_STATE_RESULT && !corrupt_answer {
                KeccakBackendHealth::Healthy
            } else {
                KeccakBackendHealth::Quarantined
            });
        Ok(session)
    }

    #[cfg(test)]
    fn for_test(backend: KeccakBackend, corrupt_answer: bool) -> Result<Self, KeccakBackendError> {
        Self::construct(backend, corrupt_answer)
    }

    #[cfg(test)]
    fn permute_for_test(&self, state: &mut [u64; 25]) -> Result<(), KeccakBackendError> {
        self.ensure_healthy()?;
        permute_direct(self.backend, state)
    }
}

fn require_architecture(backend: KeccakBackend) -> Result<(), KeccakBackendError> {
    match backend {
        KeccakBackend::X86Avx2 if cfg!(target_arch = "x86_64") => Ok(()),
        KeccakBackend::Aarch64Sha3 if cfg!(target_arch = "aarch64") => Ok(()),
        KeccakBackend::X86Avx2 | KeccakBackend::Aarch64Sha3 => {
            Err(KeccakBackendError::WrongArchitecture)
        }
    }
}

fn compiled_backend() -> Option<KeccakBackend> {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    return Some(KeccakBackend::X86Avx2);
    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha3"
    ))]
    return Some(KeccakBackend::Aarch64Sha3);
    #[allow(unreachable_code)]
    None
}

fn permute_direct(backend: KeccakBackend, state: &mut [u64; 25]) -> Result<(), KeccakBackendError> {
    #[cfg(target_arch = "x86_64")]
    if backend == KeccakBackend::X86Avx2 {
        crate::x86_avx2_keccak::permute(state);
        return Ok(());
    }
    #[cfg(target_arch = "aarch64")]
    if backend == KeccakBackend::Aarch64Sha3 {
        crate::aarch64_sha3_keccak::permute(state);
        return Ok(());
    }
    let _ = (backend, state);
    Err(KeccakBackendError::WrongArchitecture)
}

#[cfg(test)]
mod tests {
    use super::{
        KeccakBackend, KeccakBackendError, KeccakBackendHealth, KeccakBackendSession,
        ZERO_STATE_RESULT,
    };

    #[test]
    fn wrong_architecture_is_rejected_before_instruction_use() {
        let unavailable = if cfg!(target_arch = "x86_64") {
            KeccakBackend::Aarch64Sha3
        } else {
            KeccakBackend::X86Avx2
        };
        assert_eq!(
            KeccakBackendSession::for_test(unavailable, false).map(|_| ()),
            Err(KeccakBackendError::WrongArchitecture)
        );
    }

    #[test]
    fn supported_candidate_passes_kat_and_quarantines_corruption() {
        let Some(backend) = supported_backend() else {
            return;
        };
        let healthy = KeccakBackendSession::for_test(backend, false);
        assert!(healthy.is_ok());
        let Ok(healthy) = healthy else {
            return;
        };
        assert_eq!(healthy.health(), KeccakBackendHealth::Healthy);
        let mut state = [0_u64; 25];
        assert_eq!(healthy.permute_for_test(&mut state), Ok(()));
        assert_eq!(state, ZERO_STATE_RESULT);

        let quarantined = KeccakBackendSession::for_test(backend, true);
        assert!(quarantined.is_ok());
        let Ok(quarantined) = quarantined else {
            return;
        };
        assert_eq!(quarantined.health(), KeccakBackendHealth::Quarantined);
        assert_eq!(
            quarantined.permute_for_test(&mut [0_u64; 25]),
            Err(KeccakBackendError::Quarantined)
        );
    }

    #[test]
    fn supported_candidate_matches_portable_permutation_corpus() {
        let Some(backend) = supported_backend() else {
            return;
        };
        let session = KeccakBackendSession::for_test(backend, false);
        assert!(session.is_ok());
        let Ok(session) = session else {
            return;
        };
        let mut seed = 0x8f3f_73b5_cf1c_9ade_u64;
        for _ in 0..1_024 {
            let mut accelerated = [0_u64; 25];
            for lane in &mut accelerated {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *lane = seed;
            }
            let mut expected = accelerated;
            reference_permute(&mut expected);
            assert_eq!(session.permute_for_test(&mut accelerated), Ok(()));
            assert_eq!(accelerated, expected);
        }
    }

    fn supported_backend() -> Option<KeccakBackend> {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("avx2") {
            return Some(KeccakBackend::X86Avx2);
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon")
            && std::arch::is_aarch64_feature_detected!("sha3")
        {
            return Some(KeccakBackend::Aarch64Sha3);
        }
        None
    }

    fn reference_permute(state: &mut [u64; 25]) {
        use crate::keccak_constants::{PI_DESTINATIONS, ROTATION_OFFSETS, ROUND_CONSTANTS};

        for constant in ROUND_CONSTANTS {
            let mut columns = [0_u64; 5];
            for (x, parity) in columns.iter_mut().enumerate() {
                *parity = state
                    .iter()
                    .skip(x)
                    .step_by(5)
                    .fold(0_u64, |combined, lane| combined ^ lane);
            }
            let [c0, c1, c2, c3, c4] = columns;
            let theta = [
                c4 ^ c1.rotate_left(1),
                c0 ^ c2.rotate_left(1),
                c1 ^ c3.rotate_left(1),
                c2 ^ c4.rotate_left(1),
                c3 ^ c0.rotate_left(1),
            ];
            for row in state.chunks_exact_mut(5) {
                for (lane, adjustment) in row.iter_mut().zip(theta) {
                    *lane ^= adjustment;
                }
            }
            let mut rearranged = [0_u64; 25];
            for ((lane, rotation), destination) in
                state.iter().zip(ROTATION_OFFSETS).zip(PI_DESTINATIONS)
            {
                if let Some(target) = rearranged.get_mut(destination) {
                    *target = lane.rotate_left(rotation);
                }
            }
            for (target, source) in state.chunks_exact_mut(5).zip(rearranged.chunks_exact(5)) {
                if let ([a0, a1, a2, a3, a4], [b0, b1, b2, b3, b4]) = (target, source) {
                    *a0 = b0 ^ ((!b1) & b2);
                    *a1 = b1 ^ ((!b2) & b3);
                    *a2 = b2 ^ ((!b3) & b4);
                    *a3 = b3 ^ ((!b4) & b0);
                    *a4 = b4 ^ ((!b0) & b1);
                }
            }
            if let Some(first) = state.first_mut() {
                *first ^= constant;
            }
        }
    }
}
