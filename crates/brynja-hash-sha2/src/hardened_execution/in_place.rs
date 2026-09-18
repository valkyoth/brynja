//! Scoped named SHA-2 with explicit hardened portable/static/hosted execution.
//!
//! Workspaces own both hash storage and execution scratch before accepting
//! secrets. Handles borrow them; finalization never moves the active engine.
//! Scope exit clears hash storage even after a forgotten handle or recoverable
//! unwind. CPU scratch is independently cleared by the existing compression
//! guard after every operation. Authority checks, quarantine and no-fallback
//! behavior are unchanged. Registers, compiler-created copies/spills, caller
//! buffers and abort remain outside the complete-API memory guarantee.
//!
//! ```
//! use brynja_hash_sha2::hardened_execution::{Execution, in_place::Sha256Workspace};
//! let mut workspace = Sha256Workspace::new(Execution::portable())?;
//! let mut output = [0u8; 32];
//! let secret = workspace.with(|mut state| {
//!     state.update(b"abc")?;
//!     state.finalize_secret(&mut output)
//! })??;
//! assert_eq!(secret.digest.expose().len(), 32);
//! drop(secret);
//! assert_eq!(output, [0; 32]);
//! # Ok::<(), brynja_hash_sha2::hardened_execution::Error>(())
//! ```

use super::{
    Error, Execution, PublicDeclassification, Report, Route, SecretOutput, begin, engine::Engine,
};
use crate::{BitString, hardened::HardenedSha2Owner};
use brynja_core::SecretRegionInitialization;

struct Cleanup<'scope, 'authority> {
    engine: &'scope mut Engine<'authority>,
    keep: bool,
}
impl Drop for Cleanup<'_, '_> {
    fn drop(&mut self) {
        if !self.keep {
            self.engine.invalidate();
        }
    }
}

fn initialize32(engine: &mut Engine<'_>, initial: [u32; 8]) {
    for (destination, word) in engine.owner.chaining_state.chunks_exact_mut(4).zip(initial) {
        destination.copy_from_slice(&word.to_be_bytes());
    }
}
fn initialize64(engine: &mut Engine<'_>, initial: [u64; 8]) {
    for (destination, word) in engine.owner.chaining_state.chunks_exact_mut(8).zip(initial) {
        destination.copy_from_slice(&word.to_be_bytes());
    }
}

macro_rules! scoped {
    ($workspace:ident, $state:ident, $initial:expr, $new:ident, $initialize:ident, $wide:expr, $size:literal) => {
        /// Caller-owned secret storage and an affine, lifetime-bound execution route.
        ///
        /// Construction accepts no secret input. Reuse rechecks the same authority;
        /// it never undoes quarantine or substitutes a portable route.
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha2::hardened_execution::{Execution, in_place::", stringify!($workspace), "};\nlet mut w = ", stringify!($workspace), "::new(Execution::portable()).unwrap();\nlet escaped = w.with(|state| state);\n```")]
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha2::hardened_execution::{Execution, in_place::", stringify!($workspace), "};\nlet mut w = ", stringify!($workspace), "::new(Execution::portable()).unwrap();\nw.with(|_state| w.with(|_other| ()));\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nuse brynja_hash_sha2::hardened_execution::{Execution, Kernel, in_place::", stringify!($workspace), "};\nuse brynja_crypto_cpu::static_execution::Authority;\nlet workspace = { let authority = Authority::new(Kernel::X86Sha256).unwrap(); ", stringify!($workspace), "::new(Execution::from_static(&authority).unwrap()).unwrap() };\ndrop(workspace);\n```")]
        pub struct $workspace<'authority> {
            engine: Engine<'authority>,
        }
        impl<'authority> $workspace<'authority> {
            /// Binds an explicit compatible execution route before secret input.
            pub fn new(execution: Execution<'authority>) -> Result<Self, Error> {
                Ok(Self { engine: Engine::new(HardenedSha2Owner::$new($initial), execution, $wide, false)? })
            }
            /// The selected public route, not proof of independent verification.
            #[must_use]
            pub const fn route(&self) -> Route { self.engine.report.route }
            /// Runs one computation in exclusively borrowed final storage.
            ///
            /// The outer result describes route admission; the inner value is
            /// the callback result. Scope exit clears storage, including after
            /// `mem::forget` of the handle. The next scope checks authority again.
            /// Admission failure never invokes the callback and cannot access or
            /// clear its captured buffers; destination clearing starts when a
            /// secret-finalization method receives that destination.
            pub fn with<R>(&mut self, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, Error> {
                self.engine.restart()?;
                $initialize(&mut self.engine, $initial);
                let cleanup = Cleanup { engine: &mut self.engine, keep: false };
                Ok(operation($state { engine: &mut *cleanup.engine }))
            }
        }

        /// Borrowed secret-bearing stream. Every update error clears and disables
        /// this handle. Finalization consumes it; no length/preflight query is
        /// exposed. Final reports retain the existing public work-count contract.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_sha2::hardened_execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[must_use = "finalize or cancel the scoped state"]
        pub struct $state<'scope, 'authority> { engine: &'scope mut Engine<'authority> }
        impl $state<'_, '_> {
            /// Absorbs complete bytes. All failures/unwind clear and disable this
            /// scoped computation, including length and work-count errors.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                let mut cleanup = Cleanup { engine: &mut *self.engine, keep: false };
                let result = cleanup.engine.update(input);
                if result.is_ok() { cleanup.keep = true; }
                result
            }
            /// Consumes and clears the state without output.
            pub fn cancel(self) {}
            /// Typed secret output; every error clears the complete destination.
            pub fn finalize_secret(self, destination: &mut [u8]) -> Result<SecretOutput<'_>, Error> {
                self.secret(None, begin(destination, $size)?)
            }
            /// Includes canonical final MSB-first bits before typed secret output.
            pub fn finalize_bits_secret<'out>(self, input: BitString<'_>, destination: &'out mut [u8]) -> Result<SecretOutput<'out>, Error> {
                self.secret(Some(input), begin(destination, $size)?)
            }
            fn secret<'out>(self, input: Option<BitString<'_>>, mut output: SecretRegionInitialization<'out>) -> Result<SecretOutput<'out>, Error> {
                self.engine.finish(input, $size, 0xff)?;
                output.write(self.engine.owner.staged($size).ok_or(Error::OutputLength)?)?;
                Ok(SecretOutput { digest: output.finish()?, report: self.engine.report })
            }
            /// Deliberately declassifies output. Failure preserves the destination.
            pub fn finalize_public(self, destination: &mut [u8], authority: PublicDeclassification) -> Result<Report, Error> {
                self.public(None, destination, authority)
            }
            /// Includes canonical final bits before explicit public output.
            pub fn finalize_bits_public(self, input: BitString<'_>, destination: &mut [u8], authority: PublicDeclassification) -> Result<Report, Error> {
                self.public(Some(input), destination, authority)
            }
            fn public(self, input: Option<BitString<'_>>, destination: &mut [u8], _authority: PublicDeclassification) -> Result<Report, Error> {
                if destination.len() != $size { return Err(Error::OutputLength); }
                self.engine.finish(input, $size, 0xff)?;
                destination.copy_from_slice(self.engine.owner.staged($size).ok_or(Error::OutputLength)?);
                Ok(self.engine.report)
            }
        }
        impl Drop for $state<'_, '_> { fn drop(&mut self) { self.engine.invalidate(); } }
    };
}

scoped!(
    Sha224Workspace,
    Sha224,
    crate::sha224::INITIAL_STATE,
    new32,
    initialize32,
    false,
    28
);
scoped!(
    Sha256Workspace,
    Sha256,
    crate::sha256::INITIAL_STATE,
    new32,
    initialize32,
    false,
    32
);
scoped!(
    Sha384Workspace,
    Sha384,
    crate::sha384::INITIAL_STATE,
    new64,
    initialize64,
    true,
    48
);
scoped!(
    Sha512Workspace,
    Sha512,
    crate::sha512::INITIAL_STATE,
    new64,
    initialize64,
    true,
    64
);
scoped!(
    Sha512_224Workspace,
    Sha512_224,
    crate::sha512_t::SHA512_224_INITIAL_STATE,
    new64,
    initialize64,
    true,
    28
);
scoped!(
    Sha512_256Workspace,
    Sha512_256,
    crate::sha512_t::SHA512_256_INITIAL_STATE,
    new64,
    initialize64,
    true,
    32
);

#[cfg(test)]
mod tests;
