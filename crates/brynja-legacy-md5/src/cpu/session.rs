#![allow(unsafe_code)]

use super::{Md5Backend, Md5BackendError, Md5BackendHealth};
use core::{cell::Cell, marker::PhantomData};

const IV: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// Caller-owned, non-cloneable session; neither Send nor Sync.
///
/// A thread-bound marker does NOT prevent OS CPU migration. Ordinary builds
/// reject every candidate before KAT/instruction execution. Admission requires
/// a separately reviewed migration-safe execution authority, not changing a flag.
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_legacy_md5::Md5BackendSession>();
/// ```
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_legacy_md5::Md5BackendSession>();
/// ```
/// ```compile_fail
/// fn cannot_clone(session: brynja_legacy_md5::Md5BackendSession) {
///     let _ = session.clone();
/// }
/// ```
pub struct Md5BackendSession {
    backend: Md5Backend,
    healthy: Cell<bool>,
    revalidate: fn(Md5Backend) -> bool,
    _thread: PhantomData<*mut ()>,
}

impl Md5BackendSession {
    /// Selects only from complete compile-time target features; no OS probing.
    /// Still returns `NotAdmitted` in ordinary builds, even on capable hardware.
    pub fn for_compiled_target() -> Result<Self, Md5BackendError> {
        let backend = compiled_backend().ok_or(Md5BackendError::MissingFeatures)?;
        // SAFETY: The complete compiler feature bundle is a deployment contract
        // for every CPU that can execute this binary, including during migration.
        unsafe { Self::from_runtime_detection(backend, compiled_features) }
    }

    /// Creates a KAT-gated session from an external execution authority.
    ///
    /// # Safety
    /// The authority must guarantee the exact feature bundle on EVERY CPU that
    /// may execute each call, from the check through its last instruction.
    /// A cached detector, one CPUID observation, non-Send marker, or callback
    /// returning true alone cannot establish this. The callback must not panic
    /// and is checked before the KAT and each operation. Production candidates
    /// remain unadmitted; evidence builds are not supported deployment builds.
    pub unsafe fn from_runtime_detection(
        backend: Md5Backend,
        revalidate: fn(Md5Backend) -> bool,
    ) -> Result<Self, Md5BackendError> {
        Self::construct(backend, revalidate, false)
    }

    fn construct(
        backend: Md5Backend,
        revalidate: fn(Md5Backend) -> bool,
        corrupt_kat: bool,
    ) -> Result<Self, Md5BackendError> {
        require_architecture(backend)?;
        if !backend.is_admitted() && !cfg!(all(feature = "cpu-evidence", brynja_md5_cpu_evidence)) {
            return Err(Md5BackendError::NotAdmitted);
        }
        if !revalidate(backend) {
            return Err(Md5BackendError::MissingFeatures);
        }
        let session = Self {
            backend,
            healthy: Cell::new(true),
            revalidate,
            _thread: PhantomData,
        };
        let (mut states, blocks, expected) = super::kat::inputs(IV);
        session.compress(&mut states, &blocks)?;
        if corrupt_kat
            || states
                .iter()
                .zip(expected)
                .take(backend.lane_width())
                .any(|(actual, expected)| *actual != expected)
        {
            session.healthy.set(false);
        }
        Ok(session)
    }

    /// Exact identity; never an approval assertion.
    pub const fn backend(&self) -> Md5Backend {
        self.backend
    }

    /// Current permanent session health.
    pub fn health(&self) -> Md5BackendHealth {
        if self.healthy.get() {
            Md5BackendHealth::Healthy
        } else {
            Md5BackendHealth::Quarantined
        }
    }

    // Interpreter-only failure model: it can never reach an instruction kernel.
    #[cfg(test)]
    pub(crate) fn quarantined_model_for_test() -> Self {
        Self {
            backend: Md5Backend::X86Avx2,
            healthy: Cell::new(false),
            revalidate: |_| false,
            _thread: PhantomData,
        }
    }

    /// Revalidates before any caller state mutation, including buffered updates.
    pub fn ensure_healthy(&self) -> Result<(), Md5BackendError> {
        if !self.healthy.get() {
            return Err(Md5BackendError::Quarantined);
        }
        if !(self.revalidate)(self.backend) {
            self.healthy.set(false);
            return Err(Md5BackendError::MissingFeatures);
        }
        Ok(())
    }

    /// Compresses one full-width group of independent public legacy blocks.
    /// Only the first `backend().lane_width()` slots are read/written; any
    /// remaining slots stay unchanged. The fixed arrays cannot be undersized.
    /// Hardware temporaries are not cleanup-qualified for secret processing.
    pub fn compress(
        &self,
        state: &mut [[u32; 4]; 8],
        block: &[[u8; 64]; 8],
    ) -> Result<(), Md5BackendError> {
        self.ensure_healthy()?;
        #[cfg(target_arch = "x86_64")]
        if self.backend == Md5Backend::X86Avx2 {
            // SAFETY: Session construction requires a migration-safe authority;
            // ensure_healthy rechecks it before this exact fixed-buffer call.
            unsafe {
                super::x86_avx2_md5::compress(state, block);
            }
            return Ok(());
        }
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if self.backend == Md5Backend::Aarch64Neon {
            // SAFETY: The authority covers neon for the entire operation;
            // the input and exclusive output have their exact required widths.
            unsafe {
                super::aarch64_neon_md5::compress(state, block);
            }
            return Ok(());
        }
        let _ = (state, block);
        self.healthy.set(false);
        Err(Md5BackendError::WrongArchitecture)
    }
}

fn require_architecture(backend: Md5Backend) -> Result<(), Md5BackendError> {
    match backend {
        Md5Backend::X86Avx2 if cfg!(target_arch = "x86_64") => Ok(()),
        Md5Backend::Aarch64Neon if cfg!(all(target_arch = "aarch64", target_endian = "little")) => {
            Ok(())
        }
        _ => Err(Md5BackendError::WrongArchitecture),
    }
}

fn compiled_features(backend: Md5Backend) -> bool {
    compiled_backend() == Some(backend)
}

fn compiled_backend() -> Option<Md5Backend> {
    if cfg!(all(target_arch = "x86_64", target_feature = "avx2")) {
        Some(Md5Backend::X86Avx2)
    } else if cfg!(all(
        target_arch = "aarch64",
        target_endian = "little",
        target_feature = "neon"
    )) {
        Some(Md5Backend::Aarch64Neon)
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
