#![allow(unsafe_code)]

use core::{cell::Cell, marker::PhantomData};

/// One implemented SHA-256 instruction-backend identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha256Backend {
    /// x86_64 SHA extensions.
    X86Sha,
    /// AArch64 Advanced SIMD and SHA2 extensions.
    Aarch64Sha2,
    /// RISC-V 64-bit scalar Zknh extension.
    RiscVScalarCrypto,
}

impl Sha256Backend {
    /// Returns the stable backend identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86Sha => "x86-sha",
            Self::Aarch64Sha2 => "aarch64-sha2",
            Self::RiscVScalarCrypto => "riscv-scalar-crypto",
        }
    }

    /// Returns the complete target-feature bundle required for execution.
    #[must_use]
    pub const fn required_features(self) -> &'static [&'static str] {
        match self {
            Self::X86Sha => &["sha"],
            Self::Aarch64Sha2 => &["neon", "sha2"],
            Self::RiscVScalarCrypto => &["zknh"],
        }
    }

    /// Reports whether commit-bound native evidence currently admits execution.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        match self {
            Self::X86Sha | Self::Aarch64Sha2 | Self::RiscVScalarCrypto => false,
        }
    }
}

/// Caller-owned health of one exact SHA-256 backend session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha256BackendHealth {
    /// A direct startup KAT is running.
    Testing,
    /// The direct startup KAT passed.
    Healthy,
    /// The backend is permanently unavailable in this session.
    Quarantined,
}

/// Closed accelerated SHA-256 failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha256BackendError {
    /// The selected backend is for another target architecture.
    WrongArchitecture,
    /// The implementation exists but lacks complete native admission evidence.
    NotAdmitted,
    /// The session is permanently quarantined.
    Quarantined,
}

/// Secret-free report for one caller-owned backend session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha256BackendReport {
    backend: Sha256Backend,
    health: Sha256BackendHealth,
    generation: u64,
}

impl Sha256BackendReport {
    /// Returns the exact backend identity.
    #[must_use]
    pub const fn backend(self) -> Sha256Backend {
        self.backend
    }

    /// Returns the current health state.
    #[must_use]
    pub const fn health(self) -> Sha256BackendHealth {
        self.health
    }

    /// Returns the caller-owned health generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Non-forgeable, thread-bound SHA-256 backend session.
///
/// Construction runs a direct known-answer test before `compress` can execute.
/// A failed KAT permanently quarantines this session. The raw-pointer marker
/// makes runtime evidence local to the constructing thread.
pub struct Sha256BackendSession {
    backend: Sha256Backend,
    health: Cell<Sha256BackendHealth>,
    generation: Cell<u64>,
    _thread_bound: PhantomData<*mut ()>,
}

impl Sha256BackendSession {
    /// Selects a backend only from complete compile-time target features.
    ///
    /// This is the safe static `no_std` path. It returns `None` when the build
    /// does not prove a complete admitted feature bundle.
    #[must_use]
    pub fn for_compiled_target() -> Option<Self> {
        let backend = compiled_backend()?;
        Self::construct(backend, false).ok()
    }

    /// Constructs a session from a reviewed runtime feature observation.
    ///
    /// # Safety
    ///
    /// The caller must have just established every feature returned by
    /// [`Sha256Backend::required_features`] for the current architecture and
    /// must ensure the executing thread cannot migrate to an incompatible CPU
    /// during construction or later `compress` calls. A false attestation can
    /// execute an unsupported instruction and terminate the process.
    pub unsafe fn from_runtime_detection(
        backend: Sha256Backend,
    ) -> Result<Self, Sha256BackendError> {
        Self::construct(backend, false)
    }

    /// Constructs a candidate session solely for commit-bound native evidence.
    ///
    /// # Safety
    ///
    /// The evidence runner must establish the complete feature and operating-
    /// state bundle on the current CPU, retain the runner's provenance, and
    /// treat every result as non-authorizing until a later reviewed policy
    /// commit admits the backend. False evidence may execute an unsupported
    /// instruction and terminate the process.
    #[cfg(brynja_cpu_evidence)]
    pub unsafe fn for_candidate_evidence(
        backend: Sha256Backend,
    ) -> Result<Self, Sha256BackendError> {
        Self::construct(backend, false)
    }

    /// Returns the selected backend identity.
    #[must_use]
    pub const fn backend(&self) -> Sha256Backend {
        self.backend
    }

    /// Returns the current health state.
    #[must_use]
    pub fn health(&self) -> Sha256BackendHealth {
        self.health.get()
    }

    /// Returns a non-authorizing health report.
    #[must_use]
    pub fn report(&self) -> Sha256BackendReport {
        Sha256BackendReport {
            backend: self.backend,
            health: self.health.get(),
            generation: self.generation.get(),
        }
    }

    /// Verifies that this session remains admitted before caller state changes.
    pub fn ensure_healthy(&self) -> Result<(), Sha256BackendError> {
        if self.health.get() == Sha256BackendHealth::Healthy {
            Ok(())
        } else {
            Err(Sha256BackendError::Quarantined)
        }
    }

    /// Compresses one exact SHA-256 block through the tested backend.
    pub fn compress(
        &self,
        state: &mut [u32; 8],
        block: &[u8; 64],
    ) -> Result<(), Sha256BackendError> {
        self.ensure_healthy()?;
        compress_direct(self.backend, state, block)
    }

    fn construct(backend: Sha256Backend, corrupt_answer: bool) -> Result<Self, Sha256BackendError> {
        require_architecture(backend)?;
        if !backend.is_admitted() && !cfg!(any(test, brynja_cpu_evidence)) {
            return Err(Sha256BackendError::NotAdmitted);
        }
        let session = Self {
            backend,
            health: Cell::new(Sha256BackendHealth::Testing),
            generation: Cell::new(1),
            _thread_bound: PhantomData,
        };
        let mut state = initial_state();
        let block = abc_block();
        compress_direct(backend, &mut state, &block)?;
        let passed = state == abc_digest_state() && !corrupt_answer;
        session.generation.set(2);
        session.health.set(if passed {
            Sha256BackendHealth::Healthy
        } else {
            Sha256BackendHealth::Quarantined
        });
        Ok(session)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        backend: Sha256Backend,
        corrupt_answer: bool,
    ) -> Result<Self, Sha256BackendError> {
        Self::construct(backend, corrupt_answer)
    }
}

fn require_architecture(backend: Sha256Backend) -> Result<(), Sha256BackendError> {
    match backend {
        Sha256Backend::X86Sha if cfg!(target_arch = "x86_64") => Ok(()),
        Sha256Backend::Aarch64Sha2 if cfg!(target_arch = "aarch64") => Ok(()),
        Sha256Backend::RiscVScalarCrypto if cfg!(target_arch = "riscv64") => Ok(()),
        Sha256Backend::X86Sha | Sha256Backend::Aarch64Sha2 | Sha256Backend::RiscVScalarCrypto => {
            Err(Sha256BackendError::WrongArchitecture)
        }
    }
}

fn compiled_backend() -> Option<Sha256Backend> {
    #[cfg(all(target_arch = "x86_64", target_feature = "sha"))]
    return Some(Sha256Backend::X86Sha);
    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha2"
    ))]
    return Some(Sha256Backend::Aarch64Sha2);
    #[cfg(all(target_arch = "riscv64", target_feature = "zknh"))]
    return Some(Sha256Backend::RiscVScalarCrypto);
    #[allow(unreachable_code)]
    None
}

fn compress_direct(
    backend: Sha256Backend,
    state: &mut [u32; 8],
    block: &[u8; 64],
) -> Result<(), Sha256BackendError> {
    #[cfg(target_arch = "x86_64")]
    if backend == Sha256Backend::X86Sha {
        crate::x86_sha::compress(state, block);
        return Ok(());
    }
    #[cfg(target_arch = "aarch64")]
    if backend == Sha256Backend::Aarch64Sha2 {
        crate::aarch64_sha2::compress(state, block);
        return Ok(());
    }
    #[cfg(target_arch = "riscv64")]
    if backend == Sha256Backend::RiscVScalarCrypto {
        crate::riscv64_zknh::compress(state, block);
        return Ok(());
    }
    Err(Sha256BackendError::WrongArchitecture)
}

const fn initial_state() -> [u32; 8] {
    [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ]
}

const fn abc_digest_state() -> [u32; 8] {
    [
        0xba78_16bf,
        0x8f01_cfea,
        0x4141_40de,
        0x5dae_2223,
        0xb003_61a3,
        0x9617_7a9c,
        0xb410_ff61,
        0xf200_15ad,
    ]
}

const fn abc_block() -> [u8; 64] {
    let mut block = [0_u8; 64];
    block[0] = b'a';
    block[1] = b'b';
    block[2] = b'c';
    block[3] = 0x80;
    block[63] = 24;
    block
}
