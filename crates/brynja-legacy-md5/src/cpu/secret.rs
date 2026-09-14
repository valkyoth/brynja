//! Distinct hardened operational authority, never converted from ordinary state.
#![allow(unsafe_code)]
use super::{Md5Backend, Md5BackendError, Md5BackendHealth, scratch::Scratch, session};
use core::{cell::Cell, marker::PhantomData};

/// Thread-bound authority for clearing MD5 SIMD storage, not modern/FIPS approval.
/// The historical candidate admission flag does not authorize this distinct API.
/// No raw state or session export exists; ordinary authorities cannot convert.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Authority>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Authority>();
/// ```
/// ```compile_fail
/// fn bound<T: Copy>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Authority>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Authority>();
/// ```
/// ```compile_fail
/// fn bound<T: core::fmt::Debug>() {}
/// bound::<brynja_legacy_md5::hardened_execution::Authority>();
/// ```
pub struct Authority {
    backend: Md5Backend,
    healthy: Cell<bool>,
    revalidate: fn(Md5Backend) -> bool,
    thread: PhantomData<*mut ()>,
}
impl Authority {
    /// Explicit complete-target specialization, not runtime feature detection.
    /// The deployment must retain the feature/OS bundle on every schedulable
    /// CPU, including across hotplug/migration. Revalidation is constant here.
    pub fn for_compiled_target() -> Result<Self, Md5BackendError> {
        let backend = session::compiled_backend().ok_or(Md5BackendError::MissingFeatures)?;
        Self::create(backend, session::compiled_features)
    }
    /// Imports a platform's lifetime-wide authority, never a current-core guess.
    ///
    /// # Safety
    /// The complete backend feature bundle must remain available on EVERY CPU
    /// executing any call throughout this owner's lifetime. AVX2 includes OS
    /// YMM context support. Cached CPUID, affinity alone and !Send do not prove
    /// migration safety. The backend-specific callback must uphold the platform
    /// contract and must not panic. False permanently quarantines the authority.
    pub unsafe fn from_platform(
        backend: Md5Backend,
        revalidate: fn(Md5Backend) -> bool,
    ) -> Result<Self, Md5BackendError> {
        Self::create(backend, revalidate)
    }
    fn create(
        backend: Md5Backend,
        revalidate: fn(Md5Backend) -> bool,
    ) -> Result<Self, Md5BackendError> {
        session::require_architecture(backend)?;
        let authority = Self {
            backend,
            healthy: Cell::new(true),
            revalidate,
            thread: PhantomData,
        };
        authority.ensure_healthy()?;
        // Public, lane-distinct startup vectors exercise the actual secret kernel.
        let (states, blocks, expected) =
            super::kat::inputs([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
        let mut scratch = Scratch::new();
        for (word, packed) in scratch.initial.iter_mut().enumerate() {
            for (lane, dst) in packed
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .enumerate()
                .take(backend.lane_width())
            {
                let value = states
                    .get(lane)
                    .and_then(|s| s.get(word))
                    .ok_or(Md5BackendError::Quarantined)?;
                dst.copy_from_slice(&value.to_le_bytes());
            }
        }
        for (word, packed) in scratch.words.iter_mut().enumerate() {
            for (lane, dst) in packed
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .enumerate()
                .take(backend.lane_width())
            {
                let value = blocks
                    .get(lane)
                    .and_then(|b| b.as_chunks::<4>().0.get(word))
                    .ok_or(Md5BackendError::Quarantined)?;
                dst.copy_from_slice(value);
            }
        }
        authority.compress(&mut scratch)?;
        for (word, packed) in scratch.work.iter().enumerate() {
            for (lane, actual) in packed
                .as_chunks::<4>()
                .0
                .iter()
                .enumerate()
                .take(backend.lane_width())
            {
                let value = expected
                    .get(lane)
                    .and_then(|s| s.get(word))
                    .ok_or(Md5BackendError::Quarantined)?;
                if actual != &value.to_le_bytes() {
                    authority.quarantine();
                    return Err(Md5BackendError::Quarantined);
                }
            }
        }
        Ok(authority)
    }
    /// Diagnostic only, not evidence of work performed by a batch.
    pub const fn backend(&self) -> Md5Backend {
        self.backend
    }
    /// Irreversible local health, not a fresh OS/hypervisor attestation.
    pub fn health(&self) -> Md5BackendHealth {
        if self.healthy.get() {
            Md5BackendHealth::Healthy
        } else {
            Md5BackendHealth::Quarantined
        }
    }
    /// Permanently revokes this owner and all borrowing batches.
    pub fn quarantine(&self) {
        self.healthy.set(false);
    }
    pub(crate) fn ensure_healthy(&self) -> Result<(), Md5BackendError> {
        if !self.healthy.get() {
            return Err(Md5BackendError::Quarantined);
        }
        self.healthy.set(false);
        if !(self.revalidate)(self.backend) {
            return Err(Md5BackendError::MissingFeatures);
        }
        self.healthy.set(true);
        Ok(())
    }
    pub(crate) fn compress(&self, scratch: &mut Scratch) -> Result<(), Md5BackendError> {
        let mut operation = Operation {
            authority: self,
            scratch,
            complete: false,
        };
        self.ensure_healthy()?;
        #[cfg(target_arch = "x86_64")]
        if self.backend == Md5Backend::X86Avx2 {
            // SAFETY: The authority covers full AVX2/OS state for this call;
            // all fixed buffers are exclusively borrowed from clearing scratch.
            unsafe {
                super::x86_secret::compress_secret(operation.scratch)?;
            }
            operation.complete = true;
            return Ok(());
        }
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if self.backend == Md5Backend::Aarch64Neon {
            // SAFETY: The lifetime-wide NEON contract was revalidated and
            // fixed-size owner buffers stay live/exclusive for every access.
            unsafe {
                super::arm_secret::compress_secret(operation.scratch)?;
            }
            operation.complete = true;
            return Ok(());
        }
        let _ = &mut operation;
        Err(Md5BackendError::WrongArchitecture)
    }
}
struct Operation<'a> {
    authority: &'a Authority,
    scratch: &'a mut Scratch,
    complete: bool,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.scratch.wipe();
            self.authority.quarantine();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn rejected_or_panicking_authority_clears_packed_storage_without_instructions() {
        for panic in [false, true] {
            let authority = Authority {
                backend: Md5Backend::X86Avx2,
                healthy: Cell::new(true),
                revalidate: if panic {
                    |_| std::panic::resume_unwind(std::boxed::Box::new("authority unwind"))
                } else {
                    |_| false
                },
                thread: PhantomData,
            };
            let mut scratch = Scratch::new();
            scratch.initial.as_flattened_mut().fill(0xa5);
            scratch.words.as_flattened_mut().fill(0xa5);
            scratch.work.as_flattened_mut().fill(0xa5);
            scratch.temporary.as_flattened_mut().fill(0xa5);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                authority.compress(&mut scratch)
            }));
            assert!(!matches!(result, Ok(Ok(()))));
            assert_eq!(scratch.initial, [[0; 32]; 4]);
            assert_eq!(scratch.words, [[0; 32]; 16]);
            assert_eq!(scratch.work, [[0; 32]; 4]);
            assert_eq!(scratch.temporary, [[0; 32]; 3]);
            assert_eq!(authority.health(), Md5BackendHealth::Quarantined);
            assert_eq!(
                authority.ensure_healthy(),
                Err(Md5BackendError::Quarantined)
            );
        }
    }
}
