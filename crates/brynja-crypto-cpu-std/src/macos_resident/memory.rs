//! Low-level Apple Silicon resident resources, not strict execution admission.
//!
//! **No core-dump exclusion.** These resources never substitute for Linux
//! protected memory or the strict facade. They reuse the resident profile's
//! guarded, locked, fork-excluded mappings and joined worker implementation.
//! Whole owned payloads (including page padding) clear before release; stacks
//! clear after join, including recoverable unwind. Unsupported targets reject.
//!
//! Borrowing resident bytes does not protect caller storage, registers, copies,
//! panic hooks or OS/TLS allocations. Instrumented builds are diagnostic only.
//! Deployment must forbid fork, native thread cancellation and external changes
//! to protections while owners live. Fatal termination, privileged inspection,
//! hibernation and snapshots are outside the contract. Forgetting an owner leaks
//! its mapping. No cryptographic or whole-process guarantee follows from this API.
use super::{Error, require_native, resource::Mapping};

/// Fixed-size guarded/locked clearing storage. Not dump-excluded storage.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>();
/// ```
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>();
/// ```
pub struct ResidentBytes(Mapping);
impl ResidentBytes {
    /// Acquires all protections before exposing initialized bytes. `max` bounds
    /// the complete mapping, including page rounding and two guard pages.
    pub fn new(bytes: usize, max: usize) -> Result<Self, Error> {
        require_native()?;
        Ok(Self(Mapping::new(bytes, max)?))
    }
    /// Explicit borrowed exposure; copies remain the caller's responsibility.
    /// Access from a fork child aborts instead of constructing a stale reference.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.bytes()
    }
    /// Exclusive borrowed access. The allocation never resizes or changes owners.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.0.bytes_mut()
    }
    /// Clears the complete owned payload, not just the requested byte length.
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// Joined resident worker stack. No ordinary-stack or unlocked fallback.
/// ```compile_fail
/// fn bound<T: Send>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::memory::ResidentStack>();
/// ```
/// ```compile_fail
/// fn bound<T: Sync>() {}
/// bound::<brynja_crypto_cpu_std::macos_resident::memory::ResidentStack>();
/// ```
pub struct ResidentStack(Mapping);
impl ResidentStack {
    /// Requires at least 64 KiB, which is an allocation floor, not a worst-case
    /// stack-depth proof. `max` includes guards and page rounding.
    pub fn new(bytes: usize, max: usize) -> Result<Self, Error> {
        require_native()?;
        if bytes < 65536 {
            return Err(Error::InvalidSize);
        }
        Ok(Self(Mapping::new(bytes, max)?))
    }
    /// Synchronously runs and joins one worker, then clears its complete stack.
    /// Only `()` is returned from the callback. Captured values live initially
    /// in an ordinary host job: **never capture secret bytes by value**. Capture
    /// pointers into resident storage and create secret state on the worker.
    /// Borrowed ordinary input buffers are not retroactively made resident.
    ///
    /// Recoverable unwind returns `WorkerPanicked` after joining and clearing.
    /// Join/attribute-destruction failures abort, never return with a live worker.
    /// `panic=abort` cannot run destructors; arbitrary callback copies and
    /// allocations remain outside the resource's clearing guarantee.
    pub fn run<F: FnOnce() + Send>(&mut self, work: F) -> Result<(), Error> {
        self.0.run(work)
    }
}

#[cfg(test)]
mod tests;
