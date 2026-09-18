//! Scoped, caller-owned storage for hardened SHA-3, SHAKE and cSHAKE.
//!
//! Secret state stays in its borrowed workspace throughout a computation.
//! Only a reference-bearing handle moves into finalization. An outer guard
//! clears every owned region when the callback returns or recoverably unwinds,
//! even if it forgets the handle. A workspace can be reused after that clearing.
//!
//! This prevents semantic moves of the active owner; it does **not** prove
//! erasure of registers, compiler temporaries/spills, caller input, crash dumps,
//! abort paths or platform storage. Absorption/padding/output code still needs
//! separate residue qualification. No independent verification is claimed.
//! These APIs use the portable hardened implementation, not optional CPU dispatch.
//!
//! ```
//! use brynja_hash_sha3::hardened_in_place::Sha3_256Workspace;
//! let mut workspace = Sha3_256Workspace::new();
//! let mut output = [0u8; 32];
//! let digest = workspace.with(|mut state| {
//!     state.update(b"abc")?;
//!     state.finalize_secret(&mut output)
//! })?;
//! assert_eq!(digest.expose().len(), 32);
//! drop(digest); // Clears output; workspace was already cleared on scope exit.
//! assert_eq!(output, [0; 32]);
//! # Ok::<(), brynja_hash_sha3::HardenedSha3Error>(())
//! ```
//!
//! SHAKE and cSHAKE transfer the same borrow to an incremental reader. cSHAKE
//! setup runs inside the scope; its outer result covers setup and its inner
//! result is the callback's return value.
//!
//! ```
//! use brynja_hash_sha3::hardened_in_place::Cshake128Workspace;
//! let mut workspace = Cshake128Workspace::new();
//! let mut output = [0u8; 48];
//! let secret = workspace.with(b"", b"application domain", |mut state| {
//!     state.update(b"message")?;
//!     let mut reader = state.finalize_xof()?;
//!     reader.squeeze_secret(&mut output)
//! })??;
//! assert_eq!(secret.expose().len(), 48);
//! drop(secret);
//! assert_eq!(output, [0; 48]);
//! # Ok::<(), brynja_hash_sha3::HardenedSha3Error>(())
//! ```

use core::marker::PhantomData;

use super::{
    HardenedSha3Error, HardenedSha3SecretOutput, Sha3PublicDeclassification,
    output::{begin_secret, finish_secret},
    owner::HardenedFips202Owner,
    sponge::{SHA3_SUFFIX, SHA3_SUFFIX_BITS},
};
use crate::Fips202BitString;

mod xof;
pub use xof::{
    Cshake128, Cshake128Reader, Cshake128Workspace, Cshake256, Cshake256Reader, Cshake256Workspace,
    Shake128, Shake128Reader, Shake128Workspace, Shake256, Shake256Reader, Shake256Workspace,
};

// This guard belongs to the scope, not to the user-controlled handle. It also
// guards updates: only a successful update may retain the working state.
struct Cleanup<'a, const RATE: usize> {
    owner: &'a mut HardenedFips202Owner<RATE>,
    keep: bool,
}
impl<const RATE: usize> Drop for Cleanup<'_, RATE> {
    fn drop(&mut self) {
        if !self.keep {
            self.owner.wipe();
        }
    }
}

macro_rules! fixed {
    ($workspace:ident, $state:ident, $rate:expr, $width:expr) => {
        /// Caller-owned, opaque storage for one scoped SHA-3 computation.
        ///
        /// No secret can be loaded except through [`Self::with`]. Between
        /// scopes the workspace contains cleared storage and may be moved.
        /// Neither workspace nor state implements Copy/Clone/Debug/Send/Sync.
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ";\nlet mut workspace = ", stringify!($workspace), "::new();\nlet escaped = workspace.with(|state| state);\n```")]
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ";\nlet mut workspace = ", stringify!($workspace), "::new();\nworkspace.with(|_state| workspace.with(|_other| ()));\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($workspace), ">();\n```")]
        pub struct $workspace {
            owner: HardenedFips202Owner<$rate>,
            thread_bound: PhantomData<*mut ()>,
        }

        impl $workspace {
            /// Creates secret-free storage; no allocation or CPU feature needed.
            #[must_use]
            pub fn new() -> Self {
                Self {
                    owner: HardenedFips202Owner::new(),
                    thread_bound: PhantomData,
                }
            }

            /// Runs one computation without moving its live secret storage.
            ///
            /// The state cannot escape the callback. The result may own a
            /// separately borrowed secret output. Scope exit always clears the
            /// workspace, including a forgotten state or recoverable unwind.
            pub fn with<R>(&mut self, operation: impl for<'state> FnOnce($state<'state>) -> R) -> R {
                self.owner.wipe();
                let cleanup = Cleanup { owner: &mut self.owner, keep: false };
                operation($state { owner: &mut *cleanup.owner, active: true, thread_bound: PhantomData })
            }
        }

        impl Default for $workspace {
            fn default() -> Self { Self::new() }
        }

        /// Exclusive reference-bearing state; constructed only by its workspace.
        ///
        /// Consuming this handle never moves the secret owner. Finalization,
        /// cancellation and Drop clear it in place. Failed updates terminate it.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[must_use = "finalize or cancel the scoped state"]
        pub struct $state<'state> {
            owner: &'state mut HardenedFips202Owner<$rate>,
            active: bool,
            thread_bound: PhantomData<*mut ()>,
        }

        impl $state<'_> {
            /// Absorbs input. A failure or recoverable unwind clears the state;
            /// further updates fail with StateConsumed.
            pub fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error> {
                self.check()?;
                self.active = false;
                let mut cleanup = Cleanup { owner: &mut *self.owner, keep: false };
                let result = cleanup.owner.update(input).map_err(|()| HardenedSha3Error::MessageTooLong);
                if result.is_ok() {
                    cleanup.keep = true;
                    self.active = true;
                }
                result
            }

            /// Consumes the handle and transfers secret output ownership.
            /// On any error the entire supplied destination is cleared.
            pub fn finalize_secret<'out>(self, destination: &'out mut [u8])
                -> Result<HardenedSha3SecretOutput<'out>, HardenedSha3Error>
            {
                self.secret(None, destination)
            }

            /// Finishes with a canonical final bit string, including complete
            /// bytes, and transfers secret output ownership.
            pub fn finalize_bits_secret<'out>(self, input: Fips202BitString<'_>, destination: &'out mut [u8])
                -> Result<HardenedSha3SecretOutput<'out>, HardenedSha3Error>
            {
                self.secret(Some(input), destination)
            }

            /// Consumes the handle and explicitly declassifies a fixed digest.
            /// Errors preserve the public destination and clear the state.
            pub fn finalize_public(self, destination: &mut [u8], authority: Sha3PublicDeclassification)
                -> Result<(), HardenedSha3Error>
            {
                self.public(None, destination, authority)
            }

            /// Finishes with a canonical final bit string and explicitly
            /// declassifies the digest. Errors preserve the public destination.
            pub fn finalize_bits_public(self, input: Fips202BitString<'_>, destination: &mut [u8], authority: Sha3PublicDeclassification)
                -> Result<(), HardenedSha3Error>
            {
                self.public(Some(input), destination, authority)
            }

            /// Consumes the handle and clears the state without output.
            pub fn cancel(self) {}

            fn check(&self) -> Result<(), HardenedSha3Error> {
                if self.active { Ok(()) } else { Err(HardenedSha3Error::StateConsumed) }
            }

            fn stage(&mut self, input: Option<Fips202BitString<'_>>) -> Result<(), HardenedSha3Error> {
                self.check()?;
                let partial = if let Some(input) = input {
                    let bits = u128::try_from(input.bit_len()).map_err(|_| HardenedSha3Error::MessageTooLong)?;
                    self.owner.check_message_bits(bits).map_err(|()| HardenedSha3Error::MessageTooLong)?;
                    let (complete, partial) = input.split();
                    self.update(complete)?;
                    partial
                } else { None };
                self.owner.finalize(partial, SHA3_SUFFIX, SHA3_SUFFIX_BITS);
                self.owner.stage_fixed($width);
                self.active = false;
                Ok(())
            }

            fn secret<'out>(mut self, input: Option<Fips202BitString<'_>>, destination: &'out mut [u8])
                -> Result<HardenedSha3SecretOutput<'out>, HardenedSha3Error>
            {
                let length = destination.len();
                let mut initialization = begin_secret(destination)?;
                if length != $width { return Err(HardenedSha3Error::OutputLength); }
                self.stage(input)?;
                let staged = self.owner.staged($width).ok_or(HardenedSha3Error::OutputLength)?;
                initialization.as_mut().ok_or(HardenedSha3Error::SecretMemory)?.write(staged)?;
                finish_secret(initialization)
            }

            fn public(mut self, input: Option<Fips202BitString<'_>>, destination: &mut [u8], _authority: Sha3PublicDeclassification)
                -> Result<(), HardenedSha3Error>
            {
                if destination.len() != $width { return Err(HardenedSha3Error::OutputLength); }
                self.stage(input)?;
                let staged = self.owner.staged($width).ok_or(HardenedSha3Error::OutputLength)?;
                destination.copy_from_slice(staged);
                Ok(())
            }
        }

        impl Drop for $state<'_> {
            fn drop(&mut self) { self.owner.wipe(); }
        }
    };
}

fixed!(Sha3_224Workspace, Sha3_224, 144, 28);
fixed!(Sha3_256Workspace, Sha3_256, 136, 32);
fixed!(Sha3_384Workspace, Sha3_384, 104, 48);
fixed!(Sha3_512Workspace, Sha3_512, 72, 64);

#[cfg(test)]
mod tests;
