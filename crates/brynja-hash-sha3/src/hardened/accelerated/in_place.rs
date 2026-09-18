//! Scoped hardened SHA-3 on an explicitly supplied Keccak session.
//!
//! Workspaces own the sponge, CPU scratch and output staging before accepting
//! secrets. Handles only borrow storage; scope exit clears even a forgotten
//! handle or recoverable unwind. Reuse checks the same authority and never
//! revives quarantine or falls back. Feature/platform requirements are unchanged.
//! This prevents semantic owner moves, not compiler-created copies/spills or
//! whole-API register residue. Abort and caller buffers remain outside the claim.
//!
//! ```
//! use brynja_hash_sha3::hardened_execution::{Error, KeccakSession, in_place::Sha3_256Workspace};
//! use brynja_crypto_cpu::static_execution::{Authority, Kernel};
//! let kernel = if cfg!(target_arch = "aarch64") { Kernel::ArmKeccak } else { Kernel::X86Keccak };
//! // Static deployment must guarantee the complete compiled instruction bundle.
//! let Ok(authority) = Authority::new(kernel) else { return Ok(()); };
//! let mut workspace = Sha3_256Workspace::new(KeccakSession::from_static(&authority).map_err(Error::Backend)?)?;
//! let mut output = [0; 32];
//! let secret = workspace.with(|mut state| {
//!     state.update(b"abc")?;
//!     state.finalize_secret(&mut output)
//! })??;
//! assert_eq!(secret.expose().len(), 32);
//! drop(secret);
//! assert_eq!(output, [0; 32]);
//! # Ok::<(), Error>(())
//! ```

use super::super::output::{begin_secret, finish_secret};
use super::{
    Error, HardenedSha3SecretOutput, KeccakSession, Report, Sha3PublicDeclassification,
    engine::Engine, reader::Stage,
};
use crate::Fips202BitString;
use brynja_core::clear_owned_region;

struct Storage<'authority> {
    engine: Engine<'authority>,
    stage: Stage,
}
impl Storage<'_> {
    fn clear(&mut self) {
        self.engine.cancel();
        let _ = clear_owned_region(&mut self.stage.0);
    }
}
struct Cleanup<'scope, 'authority>(&'scope mut Storage<'authority>);
impl Drop for Cleanup<'_, '_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

macro_rules! fixed {
    ($workspace:ident, $state:ident, $rate:literal, $width:literal) => {
        /// Caller-owned sponge, erasing CPU session scratch and output stage.
        ///
        /// The supplied authority must remain valid for the deployment. Neither
        /// workspace nor state is Copy/Clone/Debug/Send/Sync. No secret input is
        /// accepted by construction; live storage is borrowed inside `with`.
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { let state = w.with(|state| state); }\n```")]
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), ";\nfn overlap(w: &mut ", stringify!($workspace), "<'_>) { w.with(|_state| w.with(|_other| ())); }\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha3::hardened_execution::{Error, KeccakSession, in_place::", stringify!($workspace), "};\nuse brynja_crypto_cpu::static_execution::{Authority, Kernel};\nfn escape() -> Result<", stringify!($workspace), "<'static>, Error> { let a = Authority::new(Kernel::X86Keccak).map_err(Error::Backend)?; ", stringify!($workspace), "::new(KeccakSession::from_static(&a).map_err(Error::Backend)?) }\n```")]
        pub struct $workspace<'authority> { storage: Storage<'authority> }
        impl<'authority> $workspace<'authority> {
            /// Binds the exact existing static/hosted session before secret input.
            pub fn new(session: KeccakSession<'authority>) -> Result<Self, Error> {
                Ok(Self { storage: Storage { engine: Engine::new(session, $rate)?, stage: Stage([0; 168]) } })
            }
            /// Non-authorizing public backend/health metadata, not secret lengths.
            #[must_use]
            pub fn report(&self) -> Report { self.storage.engine.report() }
            /// Runs one borrowed computation and always clears storage afterward.
            ///
            /// The outer result is admission; the inner value is the callback's
            /// result. Admission failure skips the callback and cannot clear
            /// captured destinations it has not received. Secret-output cleanup
            /// starts when finalization receives the destination.
            pub fn with<R>(&mut self, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, Error> {
                self.storage.clear();
                self.storage.engine.restart()?;
                let cleanup = Cleanup(&mut self.storage);
                Ok(operation($state { storage: &mut *cleanup.0 }))
            }
        }

        /// Exclusive borrowed computation; consuming it never moves the engine.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha3::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[must_use = "finalize or cancel the scoped state"]
        pub struct $state<'scope, 'authority> { storage: &'scope mut Storage<'authority> }
        impl $state<'_, '_> {
            /// Absorbs bytes. Every error/unwind clears and terminates the sponge.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                let result = self.storage.engine.update(input);
                if result.is_err() { self.storage.clear(); }
                result
            }
            /// Consumes the handle and clears without output.
            pub fn cancel(self) {}
            /// Typed secret output; every error clears the entire destination.
            pub fn finalize_secret(self, output: &mut [u8]) -> Result<HardenedSha3SecretOutput<'_>, Error> {
                self.finalize_bits_secret(super::empty()?, output)
            }
            /// Canonical final input bits before typed secret output.
            pub fn finalize_bits_secret<'out>(self, input: Fips202BitString<'_>, output: &'out mut [u8]) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                let length = output.len();
                let mut initialization = begin_secret(output)?;
                if length != $width { return Err(Error::OutputLength); }
                self.storage.engine.finish(input, 0x06, 3)?;
                let buffer = self.storage.stage.0.get_mut(..$width).ok_or(Error::OutputLength)?;
                self.storage.engine.read(buffer)?;
                initialization.as_mut().ok_or(Error::SecretMemory)?.write(buffer).map_err(|_| Error::SecretMemory)?;
                finish_secret(initialization).map_err(Error::from)
            }
            /// Explicit public declassification; errors preserve the destination.
            pub fn finalize_public(self, output: &mut [u8], authority: Sha3PublicDeclassification) -> Result<(), Error> {
                self.finalize_bits_public(super::empty()?, output, authority)
            }
            /// Canonical final input bits and transactional public output.
            pub fn finalize_bits_public(self, input: Fips202BitString<'_>, output: &mut [u8], _authority: Sha3PublicDeclassification) -> Result<(), Error> {
                if output.len() != $width { return Err(Error::OutputLength); }
                self.storage.engine.finish(input, 0x06, 3)?;
                let buffer = self.storage.stage.0.get_mut(..$width).ok_or(Error::OutputLength)?;
                self.storage.engine.read(buffer)?;
                output.copy_from_slice(buffer);
                Ok(())
            }
        }
        impl Drop for $state<'_, '_> { fn drop(&mut self) { self.storage.clear(); } }
    };
}
fixed!(Sha3_224Workspace, Sha3_224, 144, 28);
fixed!(Sha3_256Workspace, Sha3_256, 136, 32);
fixed!(Sha3_384Workspace, Sha3_384, 104, 48);
fixed!(Sha3_512Workspace, Sha3_512, 72, 64);

#[cfg(test)]
mod tests;
