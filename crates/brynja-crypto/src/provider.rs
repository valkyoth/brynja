//! Optional, algorithm-neutral external-key lifecycle and failure contracts.
//!
//! `external-key-provider` does not enable AES or require hardware. Algorithms
//! add exact operation traits separately; no broad "perform crypto" dispatch,
//! implicit backend selection, key export, or fallback exists. An adapter owns
//! its session/key binding and device policy. Trait implementation is trusted
//! repository/application code, not proof of hardware custody or qualification.
//! Core installation/budget contracts remain separate protocol-level admission;
//! this layer does not consume or assert any such authorization automatically.
//!
//! No device I/O, PKCS#11 driver, asynchronous cancellation or time-limit
//! enforcement is bundled. Closing a handle is not destroying a hardware key.

#![forbid(unsafe_code)]

pub use brynja_core::ProviderFailureKind;

/// Value-free operation or output-storage failure, shared across algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The exact operation is not admitted. The adapter was not called.
    NotPermitted,
    /// A prior adapter failure or unwind made this binding terminal.
    Quarantined,
    /// Sanitized failure, including structurally invalid output.
    Provider(ProviderFailureKind),
    /// Clearing output storage could not be admitted or committed.
    SecretMemory,
}

impl From<brynja_core::SecretMemoryError> for Error {
    fn from(_: brynja_core::SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

/// Explicit destruction authority for an adapter that owns its external key.
///
/// Do not implement for borrowed persistent keys. Success asserts actual device
/// destruction, not closing a session or dropping a handle. This is a trusted
/// assertion, not an authenticated receipt or independent hardware attestation.
/// Failure/panic may mean destruction is uncertain: reconcile out of band and
/// never assume retry is safe. Adapter Drop only releases local resources; it
/// must not implicitly destroy a persistent key or retry failed destruction.
pub trait OwnedKeyBackend {
    /// Destroy precisely this owned external key, never a substitute key.
    fn destroy_key(&mut self) -> Result<(), ProviderFailureKind>;
}

/// Algorithm-neutral ownership of one adapter's opaque key/session binding.
///
/// Algorithm-specific owners use this same terminal-failure lifecycle. The
/// adapter may itself borrow a session; the binding never imports/exports key
/// bytes or provides raw-handle replacement or adapter extraction. No Copy,
/// Clone or Debug. Send/Sync follow the backend's auto traits: adapters must
/// encode thread-affine sessions and shared-device synchronization correctly.
/// Backend Drop must release local resources only.
/// Dropping this binding does NOT destroy the external key. Use explicit
/// [`Self::destroy`] for owned keys; borrowed backends do not implement it.
#[must_use = "retain the binding until external-key use is complete"]
pub struct ExternalKey<B> {
    backend: B,
    #[cfg(feature = "hazmat-aes-block")]
    healthy: bool,
}

impl<B> ExternalKey<B> {
    /// Bind an already constructed trusted adapter. No validation/device probing.
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            #[cfg(feature = "hazmat-aes-block")]
            healthy: true,
        }
    }

    // Operation interfaces, not callers, get access to the adapter. Set terminal
    // before calling it so both errors and unwinds prevent subsequent dispatch.
    #[cfg(feature = "hazmat-aes-block")]
    pub(crate) fn execute<T>(
        &mut self,
        operation: impl FnOnce(&mut B) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.healthy {
            return Err(Error::Quarantined);
        }
        self.healthy = false;
        let result = operation(&mut self.backend)?;
        self.healthy = true;
        Ok(result)
    }
}

impl<B: OwnedKeyBackend> ExternalKey<B> {
    /// Destroy an owned device key explicitly, consuming even a failed binding.
    /// Every outcome consumes the binding; errors/panics do not restore use or
    /// trigger automatic retries. Success is the adapter's assertion only.
    pub fn destroy(mut self) -> Result<(), Error> {
        self.backend.destroy_key().map_err(Error::Provider)
    }
}
