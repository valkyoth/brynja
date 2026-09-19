use super::core_state::{Block, Core, Guard, Metadata};
use crate::{
    Fips202BitString, ParallelHashError, ParallelHashPublicDeclassification,
    ParallelHashSecretOutput, core_state::byte_string,
};
use brynja_hash_sha3::hardened_in_place as api;

macro_rules! fixed {
    ($workspace:ident, $state:ident, $storage:ident, $backend:ident) => {
        /// Empty caller-owned portable ParallelHash root and leaf-output storage.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        pub struct $workspace { sponge: api::$storage, metadata: Metadata }
        impl Default for $workspace { fn default() -> Self { Self::new() } }
        impl $workspace {
            /// Constructs empty storage without accepting input.
            #[must_use]
            pub fn new() -> Self { Self { sponge: api::$storage::new(), metadata: Metadata::new() } }
            /// Runs a scope with B equal to the positive block-buffer length.
            /// The whole block clears on exit; failed setup skips the callback.
            #[doc = concat!("```compile_fail\nlet mut w = brynja_hash_parallel::hardened_in_place::", stringify!($workspace), "::new();\nlet escaped = w.with(&mut [0;8], b\"\", |state| state);\n```")]
            #[doc = concat!("```compile_fail\nlet mut w = brynja_hash_parallel::hardened_in_place::", stringify!($workspace), "::new();\nw.with(&mut [0;8], b\"\", |_| w.with(&mut [0;8], b\"\", |_| ()));\n```")]
            pub fn with<R>(&mut self, block: &mut [u8], customization: &[u8], operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, ParallelHashError> {
                let guard = Block(block);
                self.with_bits(&mut *guard.0, byte_string(customization)?, operation)
            }
            /// Canonical-bit customization. Handles cannot escape the scope;
            /// typed outputs borrowing a separate destination may be returned.
            pub fn with_bits<R>(&mut self, block: &mut [u8], customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, ParallelHashError> {
                self.metadata.wipe();
                let metadata = Guard(&mut self.metadata);
                let block = Block(block);
                if block.0.is_empty() { return Err(ParallelHashError::InvalidBlockSize); }
                self.sponge.with_bits(byte_string(b"ParallelHash")?, customization, |state| {
                    let core = Core::new(state, &mut *metadata.0, &mut *block.0)?;
                    Ok(operation($state { core }))
                }).map_err(ParallelHashError::from)?
            }
            #[cfg(test)]
            pub(super) fn cleared(&self) -> bool { self.metadata.cleared() }
        }
        /// Exclusive streaming state. Errors are terminal. Consuming finalizers
        /// cannot be reused; no accumulated-length, count or preflight query exists.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[must_use = "finalize or cancel the scoped ParallelHash state"]
        pub struct $state<'scope> { core: Core<'scope, api::$backend<'scope>> }
        impl $state<'_> {
            /// Absorbs complete bytes. A partial-byte suffix belongs to finalization.
            pub fn update(&mut self, input: &[u8]) -> Result<(), ParallelHashError> { self.core.update(input) }
            /// Consumes the state and explicitly declassifies byte output.
            pub fn finalize_public(self, output: &mut [u8], authority: ParallelHashPublicDeclassification) -> Result<(), ParallelHashError> {
                let valid = if output.is_empty() { 0 } else { 8 }; self.finalize_public_bits(output, valid, authority)
            }
            /// Consumes byte input into canonical-bit public output. Errors preserve output.
            pub fn finalize_public_bits(self, output: &mut [u8], valid: u8, authority: ParallelHashPublicDeclassification) -> Result<(), ParallelHashError> {
                self.finalize_bits_public(byte_string(&[])?, output, valid, authority)
            }
            /// Appends canonical final input bits and consumes the state. Empty output
            /// requires valid=0; nonempty output requires 1..=8. Errors preserve it.
            pub fn finalize_bits_public(self, tail: Fips202BitString<'_>, output: &mut [u8], valid: u8, _authority: ParallelHashPublicDeclassification) -> Result<(), ParallelHashError> {
                self.core.public(tail, output, valid)
            }
            /// Consumes byte input into typed secret output; errors clear output.
            pub fn finalize_secret<'out>(self, output: &'out mut [u8]) -> Result<ParallelHashSecretOutput<'out>, ParallelHashError> {
                let valid = if output.is_empty() { 0 } else { 8 }; self.finalize_secret_bits(output, valid)
            }
            /// Consumes byte input into canonical-bit typed secret output.
            pub fn finalize_secret_bits<'out>(self, output: &'out mut [u8], valid: u8) -> Result<ParallelHashSecretOutput<'out>, ParallelHashError> {
                self.finalize_bits_secret(byte_string(&[])?, output, valid)
            }
            /// Appends canonical final input bits. Every failure clears the complete
            /// secret destination, including malformed output descriptors.
            pub fn finalize_bits_secret<'out>(self, tail: Fips202BitString<'_>, output: &'out mut [u8], valid: u8) -> Result<ParallelHashSecretOutput<'out>, ParallelHashError> {
                self.core.secret(tail, output, valid)
            }
            /// Consumes and clears the current computation without output.
            pub fn cancel(self) {}
        }
    };
}
fixed!(
    ParallelHash128Workspace,
    ParallelHash128,
    Cshake128Workspace,
    Cshake128
);
fixed!(
    ParallelHash256Workspace,
    ParallelHash256,
    Cshake256Workspace,
    Cshake256
);
