#![allow(unsafe_code)]

use super::{Sha1Backend, Sha1BackendError, Sha1BackendHealth};
use core::{cell::Cell, marker::PhantomData};

const IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
const ABC: [u32; 5] = [0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d];

/// Caller-owned, non-cloneable session; neither Send nor Sync.
///
/// A thread-bound marker does NOT prevent OS CPU migration. Ordinary builds
/// reject every candidate before KAT/instruction execution. Admission requires
/// a separately reviewed migration-safe execution authority, not changing a flag.
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_legacy_sha1::Sha1BackendSession>();
/// ```
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_legacy_sha1::Sha1BackendSession>();
/// ```
pub struct Sha1BackendSession {
    backend: Sha1Backend,
    healthy: Cell<bool>,
    revalidate: fn(Sha1Backend) -> bool,
    _thread: PhantomData<*mut ()>,
}

impl Sha1BackendSession {
    /// Selects only from complete compile-time target features; no OS probing.
    /// Still returns `NotAdmitted` in ordinary builds, even on capable hardware.
    pub fn for_compiled_target() -> Result<Self, Sha1BackendError> {
        let backend = compiled_backend().ok_or(Sha1BackendError::MissingFeatures)?;
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
        backend: Sha1Backend,
        revalidate: fn(Sha1Backend) -> bool,
    ) -> Result<Self, Sha1BackendError> {
        Self::construct(backend, revalidate, ABC)
    }

    fn construct(
        backend: Sha1Backend,
        revalidate: fn(Sha1Backend) -> bool,
        expected: [u32; 5],
    ) -> Result<Self, Sha1BackendError> {
        require_architecture(backend)?;
        if !backend.is_admitted() && !cfg!(all(feature = "cpu-evidence", brynja_sha1_cpu_evidence))
        {
            return Err(Sha1BackendError::NotAdmitted);
        }
        if !revalidate(backend) {
            return Err(Sha1BackendError::MissingFeatures);
        }
        let session = Self {
            backend,
            healthy: Cell::new(true),
            revalidate,
            _thread: PhantomData,
        };
        let mut state = IV;
        let mut block = [0; 64];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        block[63] = 24;
        session.compress(&mut state, &block)?;
        if state != expected {
            session.healthy.set(false);
        }
        Ok(session)
    }

    /// Exact identity; never an approval assertion.
    pub const fn backend(&self) -> Sha1Backend {
        self.backend
    }

    /// Current permanent session health.
    pub fn health(&self) -> Sha1BackendHealth {
        if self.healthy.get() {
            Sha1BackendHealth::Healthy
        } else {
            Sha1BackendHealth::Quarantined
        }
    }

    #[cfg(test)]
    pub(super) fn quarantine_for_test(&self) {
        self.healthy.set(false);
    }

    // Interpreter-only failure model: it can never reach an instruction kernel.
    #[cfg(test)]
    pub(super) fn quarantined_model_for_test() -> Self {
        Self {
            backend: Sha1Backend::X86Sha,
            healthy: Cell::new(false),
            revalidate: |_| false,
            _thread: PhantomData,
        }
    }

    /// Revalidates before any caller state mutation, including buffered updates.
    pub fn ensure_healthy(&self) -> Result<(), Sha1BackendError> {
        if !self.healthy.get() {
            return Err(Sha1BackendError::Quarantined);
        }
        if !(self.revalidate)(self.backend) {
            self.healthy.set(false);
            return Err(Sha1BackendError::MissingFeatures);
        }
        Ok(())
    }

    /// Compresses one complete block of public/unkeyed legacy data.
    /// Hardware temporaries are not cleanup-qualified for secret processing.
    pub fn compress(&self, state: &mut [u32; 5], block: &[u8; 64]) -> Result<(), Sha1BackendError> {
        self.ensure_healthy()?;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if self.backend == Sha1Backend::X86Sha {
            // SAFETY: Session construction requires a migration-safe authority;
            // ensure_healthy rechecks it before this exact fixed-buffer call.
            unsafe {
                super::x86_sha1::compress(state, block);
            }
            return Ok(());
        }
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if self.backend == Sha1Backend::Aarch64Sha1 {
            // SAFETY: The authority covers neon/sha2 for the entire operation;
            // the input and exclusive output have their exact required widths.
            unsafe {
                super::aarch64_sha1::compress(state, block);
            }
            return Ok(());
        }
        let _ = (state, block);
        self.healthy.set(false);
        Err(Sha1BackendError::WrongArchitecture)
    }
}

fn require_architecture(backend: Sha1Backend) -> Result<(), Sha1BackendError> {
    match backend {
        Sha1Backend::X86Sha if cfg!(any(target_arch = "x86", target_arch = "x86_64")) => Ok(()),
        Sha1Backend::Aarch64Sha1
            if cfg!(all(target_arch = "aarch64", target_endian = "little")) =>
        {
            Ok(())
        }
        _ => Err(Sha1BackendError::WrongArchitecture),
    }
}

fn compiled_features(backend: Sha1Backend) -> bool {
    compiled_backend() == Some(backend)
}

fn compiled_backend() -> Option<Sha1Backend> {
    if cfg!(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
        target_feature = "sha"
    )) {
        Some(Sha1Backend::X86Sha)
    } else if cfg!(all(
        target_arch = "aarch64",
        target_endian = "little",
        target_feature = "neon",
        target_feature = "sha2"
    )) {
        Some(Sha1Backend::Aarch64Sha1)
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
