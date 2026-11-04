//! Synchronous, explicitly selected AES-128 external-key integration.
//!
//! Requires both `hazmat-aes-block` and `external-key-provider`. No allocation,
//! device library, login, key import/export, fallback or hardware requirement.
//! An adapter binds one session and opaque key together before admission here.
//! It must verify AES-128 identity and actual device permissions; this trait is
//! a trusted cryptographic boundary, not hardware attestation or a sandbox.
//! Public implementations may be software mocks, remote services or devices.
//!
//! Adapters own authentication, handle generation/liveness checks, timeouts,
//! resource limits and native error sanitization. Completion must be synchronous:
//! no retained output pointers or pending writes after return. A timeout does
//! not prove cancellation at the device. This API neither polls nor retries.
//! Failures/unwind quarantine the wrapper; recovering a device/session requires
//! explicit adapter-level reconciliation, not automatic software fallback.
//!
//! Raw blocks are not authenticated message encryption. Future modes should
//! expose native whole-operation providers rather than one device call per block.
//! No PKCS#11 driver, supported hardware list or qualification is claimed here.

#![forbid(unsafe_code)]

use super::{BLOCK_BYTES, PublicCiphertext, Scratch, SecretBlock};
pub use crate::provider::Error;
use crate::provider::{ExternalKey, OwnedKeyBackend};
use brynja_core::{ProviderFailureKind, SecretRegionInitialization};
use core::marker::PhantomData;

/// Exact permitted directions for a previously validated AES-128 key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Permissions {
    /// Encryption only; does not authorize decryption.
    Encrypt,
    /// Decryption only; does not authorize encryption.
    Decrypt,
    /// Both directions explicitly authorized.
    EncryptAndDecrypt,
}

/// Trusted adapter bound to exactly one AES-128 key and its provider/session.
///
/// Construction and key lookup/generation belong to the adapter. Before giving
/// an instance to [`Aes128ProviderKey::new`], validate key type, 128-bit size,
/// usage permissions and, when promised by that adapter, non-exportability.
/// Never substitute another key, provider, mechanism, or software fallback.
/// Revalidate revocable permissions/session identity at each operation. Do not
/// implement this trait for a free raw identifier detached from its provider.
///
/// On success, write exactly one complete block and report `BLOCK_BYTES`.
/// The wrapper checks the reported length, not the truth of an adapter's claims
/// or mathematical correctness. Partial writes on error are permitted: output
/// scratch is guarded and never released. Adapters must clear their own copies
/// and must not expose keys/plaintext in error text, logs or Debug output.
/// Adapter Drop releases local resources, never implicitly destroys a persistent
/// device key. Hardware key destruction is a separate explicit operation.
pub trait Aes128Backend {
    /// Validated maximum permissions, captured at wrapper construction.
    fn permissions(&self) -> Permissions;

    /// Encrypt one block with the bound AES-128 key, without padding or a mode.
    fn encrypt_block(
        &mut self,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) -> Result<usize, ProviderFailureKind>;

    /// Decrypt one block with the bound AES-128 key. No authentication implied.
    fn decrypt_block(
        &mut self,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) -> Result<usize, ProviderFailureKind>;
}

/// Provider-bound AES-128 key with clearing outputs and fail-closed operations.
///
/// Owns the adapter (which may itself borrow a session). No key bytes, adapter
/// extraction, raw handle substitution, Copy, Clone, Debug, Send or Sync API.
/// Drop only drops the adapter. It does NOT destroy the external key. An owned
/// key requires explicit [`Self::destroy`]; a borrowed backend cannot call it.
/// Output ownership is independent of the key's lifetime.
///
/// The application obtains a validated adapter from its chosen device library;
/// this helper accepts that binding without importing any key bytes:
///
/// ```
/// use brynja_crypto::aes::{PublicCiphertext, provider::{Aes128Backend, Aes128ProviderKey, Error}};
/// fn encrypt_with_selected_provider<B: Aes128Backend>(
///     backend: B, input: &[u8; 16], output: &mut [u8; 16],
/// ) -> Result<(), Error> {
///     let mut key = Aes128ProviderKey::new(backend);
///     key.encrypt_block_public(input, output, PublicCiphertext::acknowledge())
/// }
/// ```
#[must_use = "retain this provider binding while using its external key"]
pub struct Aes128ProviderKey<B: Aes128Backend> {
    binding: ExternalKey<B>,
    permissions: Permissions,
}

impl<B: Aes128Backend> Aes128ProviderKey<B> {
    /// Admits a trusted, already validated key/session binding. No device probing.
    /// The backend cannot subsequently be replaced or extracted through this API.
    pub fn new(backend: B) -> Self {
        let permissions = backend.permissions();
        Self {
            binding: ExternalKey::new(backend),
            permissions,
        }
    }

    /// Returns the admitted maximum permissions, not a current device health test.
    pub const fn permissions(&self) -> Permissions {
        self.permissions
    }

    /// Encrypt into clearing caller storage; no mode or authentication.
    /// Every error/unwind clears the admitted destination, including rejection.
    pub fn encrypt_block<'out>(
        &mut self,
        input: &[u8; BLOCK_BYTES],
        output: &'out mut [u8; BLOCK_BYTES],
    ) -> Result<SecretBlock<'out>, Error> {
        self.transform(input, output, false)
    }

    /// Decrypt into clearing caller storage. No public-decryption API exists.
    /// Every error/unwind clears the admitted destination, including rejection.
    pub fn decrypt_block<'out>(
        &mut self,
        input: &[u8; BLOCK_BYTES],
        output: &'out mut [u8; BLOCK_BYTES],
    ) -> Result<SecretBlock<'out>, Error> {
        self.transform(input, output, true)
    }

    /// Explicitly release ciphertext. Public output is unchanged on error/unwind.
    pub fn encrypt_block_public(
        &mut self,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
        _authority: PublicCiphertext,
    ) -> Result<(), Error> {
        let mut scratch = Scratch::<BLOCK_BYTES>::new();
        self.execute(input, &mut scratch.0, false)?;
        output.copy_from_slice(&scratch.0);
        Ok(())
    }

    fn transform<'out>(
        &mut self,
        input: &[u8; BLOCK_BYTES],
        output: &'out mut [u8; BLOCK_BYTES],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, Error> {
        let mut destination = SecretRegionInitialization::begin(output)?;
        let mut scratch = Scratch::<BLOCK_BYTES>::new();
        self.execute(input, &mut scratch.0, inverse)?;
        destination.write(&scratch.0)?;
        Ok(SecretBlock {
            region: destination.finish()?,
            local: PhantomData,
        })
    }

    fn execute(
        &mut self,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
        inverse: bool,
    ) -> Result<(), Error> {
        if matches!(
            (self.permissions, inverse),
            (Permissions::Encrypt, true) | (Permissions::Decrypt, false)
        ) {
            return Err(Error::NotPermitted);
        }
        self.binding.execute(|backend| {
            let written = if inverse {
                backend.decrypt_block(input, output)
            } else {
                backend.encrypt_block(input, output)
            }
            .map_err(Error::Provider)?;
            if written != BLOCK_BYTES {
                return Err(Error::Provider(ProviderFailureKind::InvalidOutput));
            }
            Ok(())
        })
    }
}

impl<B: Aes128Backend + OwnedKeyBackend> Aes128ProviderKey<B> {
    /// Explicitly destroy an owned external key, consuming even a quarantined
    /// binding. Failure never restores use or automatically retries destruction.
    pub fn destroy(self) -> Result<(), Error> {
        self.binding.destroy()
    }
}
