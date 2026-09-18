//! Scoped, caller-owned storage for hardened SHA-2 identities.
//!
//! Active secret storage stays in its borrowed workspace. Finalization moves
//! only a handle; scope exit clears the owner even if that handle is forgotten.
//! This is not a guarantee about compiler-created copies, registers, spills,
//! caller inputs, aborts or platform storage. It uses the existing portable
//! hardened implementation, not optional accelerated dispatch. General SHA-512/t
//! requires the existing default-off `general-sha512-t` feature.
//!
//! ```
//! use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
//! let mut workspace = Sha256Workspace::new();
//! let mut bytes = [0u8; 32];
//! let secret = workspace.with(|mut state| {
//!     state.update(b"abc")?;
//!     state.finalize_secret(&mut bytes)
//! })?;
//! assert_eq!(secret.expose().len(), 32);
//! drop(secret);
//! assert_eq!(bytes, [0; 32]);
//! # Ok::<(), brynja_hash_sha2::HardenedSha2Error>(())
//! ```

use super::{
    HardenedSha2Error, HardenedSha2Owner, PublicDeclassification,
    output::clear_failed_secret_output,
};
use crate::BitString;
use brynja_core::{OwnedSecretRegion, SecretRegionInitialization};
use core::marker::PhantomData;

#[cfg(feature = "general-sha512-t")]
mod general;
#[cfg(feature = "general-sha512-t")]
pub use general::{Sha512T, Sha512TWorkspace};

struct Cleanup<'scope> {
    owner: &'scope mut HardenedSha2Owner,
    keep: bool,
}
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.owner.wipe();
        }
    }
}

fn initialize32(owner: &mut HardenedSha2Owner, initial: [u32; 8]) {
    for (destination, word) in owner.chaining_state.chunks_exact_mut(4).zip(initial) {
        destination.copy_from_slice(&word.to_be_bytes());
    }
}

fn initialize64(owner: &mut HardenedSha2Owner, initial: [u64; 8]) {
    for (destination, word) in owner.chaining_state.chunks_exact_mut(8).zip(initial) {
        destination.copy_from_slice(&word.to_be_bytes());
    }
}

macro_rules! scoped {
    ($workspace:ident, $state:ident, $initial:expr, $width:literal, $new:ident, $initialize:ident,
     $update:ident, $finalize:ident, $message:ident, $family:ident, $length:ident) => {
        /// Opaque storage for one named, portable hardened SHA-2 identity.
        ///
        /// No secret is loaded outside the exclusive `with` scope. The workspace
        /// is secret-free before and after each scope and can then be moved/reused.
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha2::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nlet escaped = w.with(|state| state);\n```")]
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha2::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(|_state| w.with(|_other| ()));\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($workspace), ">();\n```")]
        pub struct $workspace {
            owner: HardenedSha2Owner,
            thread_bound: PhantomData<*mut ()>,
        }
        impl $workspace {
            /// Creates allocation-free storage containing only the public IV.
            #[must_use]
            pub fn new() -> Self {
                Self { owner: HardenedSha2Owner::$new($initial), thread_bound: PhantomData }
            }
            /// Borrows the final storage for a computation. An independent guard
            /// clears it on return or recoverable unwind, including forgotten
            /// handles. A separately borrowed output may outlive this scope.
            pub fn with<R>(&mut self, operation: impl for<'state> FnOnce($state<'state>) -> R) -> R {
                self.owner.wipe();
                // Restore the public IV directly in the cleared allocation.
                // The callback is the first point at which secrets may be loaded.
                $initialize(&mut self.owner, $initial);
                let cleanup = Cleanup { owner: &mut self.owner, keep: false };
                operation($state { owner: &mut *cleanup.owner, active: true, thread_bound: PhantomData })
            }
        }
        impl Default for $workspace { fn default() -> Self { Self::new() } }

        /// Exclusive handle borrowing, rather than owning/moving, secret storage.
        ///
        /// Updates fail closed: errors clear and terminate the state. Finalization
        /// consumes it. No length query or preflight length oracle is exposed.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha2::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[must_use = "finalize or cancel the scoped state"]
        pub struct $state<'state> {
            owner: &'state mut HardenedSha2Owner,
            active: bool,
            thread_bound: PhantomData<*mut ()>,
        }
        impl $state<'_> {
            /// Absorbs complete bytes. Failure/unwind clears the borrowed owner.
            pub fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha2Error> {
                self.check()?;
                self.active = false;
                let mut cleanup = Cleanup { owner: &mut *self.owner, keep: false };
                let result = cleanup.owner.$update(input).map_err(|()| HardenedSha2Error::MessageTooLong);
                if result.is_ok() { cleanup.keep = true; self.active = true; }
                result
            }

            /// Consumes the state and transfers typed secret output ownership.
            /// Any error clears the entire destination and the borrowed state.
            pub fn finalize_secret<'out>(self, destination: &'out mut [u8]) -> Result<OwnedSecretRegion<'out>, HardenedSha2Error> {
                self.secret(None, destination)
            }
            /// Includes a final canonical MSB-first bit string before output.
            pub fn finalize_bits_secret<'out>(self, input: BitString<'_>, destination: &'out mut [u8]) -> Result<OwnedSecretRegion<'out>, HardenedSha2Error> {
                self.secret(Some(input), destination)
            }
            /// Consumes the state and explicitly declassifies its fixed digest.
            /// Failure preserves the public destination and clears the state.
            pub fn finalize_public(self, destination: &mut [u8], authority: PublicDeclassification) -> Result<(), HardenedSha2Error> {
                self.public(None, destination, authority)
            }
            /// Includes a final canonical MSB-first bit string before public output.
            pub fn finalize_bits_public(self, input: BitString<'_>, destination: &mut [u8], authority: PublicDeclassification) -> Result<(), HardenedSha2Error> {
                self.public(Some(input), destination, authority)
            }
            /// Clears the borrowed state without producing output.
            pub fn cancel(self) {}

            fn check(&self) -> Result<(), HardenedSha2Error> {
                if self.active { Ok(()) } else { Err(HardenedSha2Error::StateConsumed) }
            }
            fn stage(&mut self, input: Option<BitString<'_>>) -> Result<(), HardenedSha2Error> {
                self.check()?;
                let (partial, bits) = if let Some(input) = input {
                    let bits = super::$family::$length(self.owner, input).map_err(|()| HardenedSha2Error::MessageTooLong)?;
                    let (complete, partial) = input.split();
                    self.update(complete)?;
                    (partial, bits)
                } else {
                    (None, self.owner.$message().checked_mul(8).ok_or(HardenedSha2Error::MessageTooLong)?)
                };
                self.owner.$finalize(partial, bits, $width);
                self.active = false;
                Ok(())
            }
            fn secret<'out>(mut self, input: Option<BitString<'_>>, destination: &'out mut [u8]) -> Result<OwnedSecretRegion<'out>, HardenedSha2Error> {
                if destination.len() != $width {
                    return Err(clear_failed_secret_output(destination, HardenedSha2Error::OutputLength));
                }
                let mut initialization = SecretRegionInitialization::begin(destination)?;
                self.stage(input)?;
                initialization.write(self.owner.staged($width).ok_or(HardenedSha2Error::OutputLength)?)?;
                initialization.finish().map_err(HardenedSha2Error::from)
            }
            fn public(mut self, input: Option<BitString<'_>>, destination: &mut [u8], _authority: PublicDeclassification) -> Result<(), HardenedSha2Error> {
                if destination.len() != $width { return Err(HardenedSha2Error::OutputLength); }
                self.stage(input)?;
                destination.copy_from_slice(self.owner.staged($width).ok_or(HardenedSha2Error::OutputLength)?);
                Ok(())
            }
        }
        impl Drop for $state<'_> { fn drop(&mut self) { self.owner.wipe(); } }
    };
}

scoped!(
    Sha224Workspace,
    Sha224,
    crate::sha224::INITIAL_STATE,
    28,
    new32,
    initialize32,
    update32,
    finalize32,
    message_bytes32,
    state32,
    finalize_bits_length32
);
scoped!(
    Sha256Workspace,
    Sha256,
    crate::sha256::INITIAL_STATE,
    32,
    new32,
    initialize32,
    update32,
    finalize32,
    message_bytes32,
    state32,
    finalize_bits_length32
);
scoped!(
    Sha384Workspace,
    Sha384,
    crate::sha384::INITIAL_STATE,
    48,
    new64,
    initialize64,
    update64,
    finalize64,
    message_bytes64,
    state64,
    finalize_bits_length64
);
scoped!(
    Sha512Workspace,
    Sha512,
    crate::sha512::INITIAL_STATE,
    64,
    new64,
    initialize64,
    update64,
    finalize64,
    message_bytes64,
    state64,
    finalize_bits_length64
);
scoped!(
    Sha512_224Workspace,
    Sha512_224,
    crate::sha512_t::SHA512_224_INITIAL_STATE,
    28,
    new64,
    initialize64,
    update64,
    finalize64,
    message_bytes64,
    state64,
    finalize_bits_length64
);
scoped!(
    Sha512_256Workspace,
    Sha512_256,
    crate::sha512_t::SHA512_256_INITIAL_STATE,
    32,
    new64,
    initialize64,
    update64,
    finalize64,
    message_bytes64,
    state64,
    finalize_bits_length64
);

#[cfg(test)]
mod tests;
