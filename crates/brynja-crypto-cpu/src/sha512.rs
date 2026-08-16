use core::{cell::Cell, marker::PhantomData};

/// One implemented SHA-512-family instruction-backend identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha512Backend {
    /// AArch64 Advanced SIMD and SHA-512 instructions (`sha3` feature).
    Aarch64Sha512,
    /// RISC-V 64-bit scalar Zknh instructions.
    RiscVScalarCrypto,
}

impl Sha512Backend {
    /// Returns the stable backend identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aarch64Sha512 => "aarch64-sha512",
            Self::RiscVScalarCrypto => "riscv-scalar-crypto",
        }
    }

    /// Returns the complete target-feature bundle required for execution.
    #[must_use]
    pub const fn required_features(self) -> &'static [&'static str] {
        match self {
            Self::Aarch64Sha512 => &["neon", "sha3"],
            Self::RiscVScalarCrypto => &["zknh"],
        }
    }

    /// Reports whether commit-bound native evidence currently admits execution.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        false
    }
}

/// Caller-owned health of one exact SHA-512-family backend session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha512BackendHealth {
    /// A direct startup KAT is running.
    Testing,
    /// The direct startup KAT passed.
    Healthy,
    /// The backend is permanently unavailable in this session.
    Quarantined,
}

/// Closed accelerated SHA-512-family failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha512BackendError {
    /// The selected backend is for another target architecture.
    WrongArchitecture,
    /// The implementation exists but lacks complete native admission evidence.
    NotAdmitted,
    /// The session is permanently quarantined.
    Quarantined,
}

/// Secret-free report for one caller-owned backend session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha512BackendReport {
    backend: Sha512Backend,
    health: Sha512BackendHealth,
    generation: u64,
}

impl Sha512BackendReport {
    /// Returns the exact backend identity.
    #[must_use]
    pub const fn backend(self) -> Sha512Backend {
        self.backend
    }

    /// Returns the current health state.
    #[must_use]
    pub const fn health(self) -> Sha512BackendHealth {
        self.health
    }

    /// Returns the caller-owned health generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Non-forgeable, thread-bound SHA-512-family backend session.
///
/// Static construction is available only when the complete target feature is
/// proven by the compiler. Candidate evidence builds use the same route, so no
/// runtime feature claim can activate an unadmitted implementation.
pub struct Sha512BackendSession {
    backend: Sha512Backend,
    health: Cell<Sha512BackendHealth>,
    generation: Cell<u64>,
    _thread_bound: PhantomData<*mut ()>,
}

impl Sha512BackendSession {
    /// Selects a backend only from complete compile-time target features.
    #[must_use]
    pub fn for_compiled_target() -> Option<Self> {
        let backend = compiled_backend()?;
        Self::construct(backend, false).ok()
    }

    /// Returns the selected backend identity.
    #[must_use]
    pub const fn backend(&self) -> Sha512Backend {
        self.backend
    }

    /// Returns the current health state.
    #[must_use]
    pub fn health(&self) -> Sha512BackendHealth {
        self.health.get()
    }

    /// Returns a non-authorizing health report.
    #[must_use]
    pub fn report(&self) -> Sha512BackendReport {
        Sha512BackendReport {
            backend: self.backend,
            health: self.health.get(),
            generation: self.generation.get(),
        }
    }

    /// Verifies that this session remains usable before caller state changes.
    pub fn ensure_healthy(&self) -> Result<(), Sha512BackendError> {
        if self.health.get() == Sha512BackendHealth::Healthy {
            Ok(())
        } else {
            Err(Sha512BackendError::Quarantined)
        }
    }

    /// Compresses one exact SHA-512-family block through the tested backend.
    pub fn compress(
        &self,
        state: &mut [u64; 8],
        block: &[u8; 128],
    ) -> Result<(), Sha512BackendError> {
        self.ensure_healthy()?;
        compress_direct(self.backend, state, block)
    }

    fn construct(backend: Sha512Backend, corrupt_answer: bool) -> Result<Self, Sha512BackendError> {
        require_architecture(backend)?;
        if !backend.is_admitted() && !cfg!(any(test, brynja_cpu_evidence)) {
            return Err(Sha512BackendError::NotAdmitted);
        }
        let session = Self {
            backend,
            health: Cell::new(Sha512BackendHealth::Testing),
            generation: Cell::new(1),
            _thread_bound: PhantomData,
        };
        let mut state = initial_state();
        compress_direct(backend, &mut state, &abc_block())?;
        session.generation.set(2);
        session
            .health
            .set(if state == abc_digest_state() && !corrupt_answer {
                Sha512BackendHealth::Healthy
            } else {
                Sha512BackendHealth::Quarantined
            });
        Ok(session)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn for_test(
        backend: Sha512Backend,
        corrupt_answer: bool,
    ) -> Result<Self, Sha512BackendError> {
        Self::construct(backend, corrupt_answer)
    }
}

fn require_architecture(backend: Sha512Backend) -> Result<(), Sha512BackendError> {
    match backend {
        Sha512Backend::Aarch64Sha512 if cfg!(target_arch = "aarch64") => Ok(()),
        Sha512Backend::RiscVScalarCrypto if cfg!(target_arch = "riscv64") => Ok(()),
        Sha512Backend::Aarch64Sha512 | Sha512Backend::RiscVScalarCrypto => {
            Err(Sha512BackendError::WrongArchitecture)
        }
    }
}

fn compiled_backend() -> Option<Sha512Backend> {
    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha3"
    ))]
    return Some(Sha512Backend::Aarch64Sha512);
    #[cfg(all(target_arch = "riscv64", target_feature = "zknh"))]
    return Some(Sha512Backend::RiscVScalarCrypto);
    #[allow(unreachable_code)]
    None
}

fn compress_direct(
    backend: Sha512Backend,
    state: &mut [u64; 8],
    block: &[u8; 128],
) -> Result<(), Sha512BackendError> {
    #[cfg(target_arch = "aarch64")]
    if backend == Sha512Backend::Aarch64Sha512 {
        crate::aarch64_sha2::compress512(state, block);
        return Ok(());
    }
    #[cfg(target_arch = "riscv64")]
    if backend == Sha512Backend::RiscVScalarCrypto {
        crate::riscv64_zknh::compress512(state, block);
        return Ok(());
    }
    let _ = (backend, state, block);
    Err(Sha512BackendError::WrongArchitecture)
}

const fn initial_state() -> [u64; 8] {
    [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ]
}

const fn abc_digest_state() -> [u64; 8] {
    [
        0xddaf_35a1_9361_7aba,
        0xcc41_7349_ae20_4131,
        0x12e6_fa4e_89a9_7ea2,
        0x0a9e_eee6_4b55_d39a,
        0x2192_992a_274f_c1a8,
        0x36ba_3c23_a3fe_ebbd,
        0x454d_4423_643c_e80e,
        0x2a9a_c94f_a54c_a49f,
    ]
}

const fn abc_block() -> [u8; 128] {
    let mut block = [0_u8; 128];
    block[0] = b'a';
    block[1] = b'b';
    block[2] = b'c';
    block[3] = 0x80;
    block[127] = 24;
    block
}
