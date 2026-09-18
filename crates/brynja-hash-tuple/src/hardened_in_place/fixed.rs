use super::core_state::{Core, Guard, Metadata, byte_valid, bytes_input};
use crate::{
    Fips202BitString, TupleHashError, TupleHashPublicDeclassification, TupleHashSecretOutput,
};
use brynja_hash_sha3::hardened_in_place as cshake;

macro_rules! fixed {
    ($workspace:ident, $state:ident, $writer:ident, $storage:ident, $backend:ident) => {
        /// Caller-owned portable TupleHash storage, borrowed before secret input.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        pub struct $workspace { sponge: cshake::$storage, metadata: Metadata }
        impl Default for $workspace { fn default() -> Self { Self::new() } }
        impl $workspace {
            /// Constructs empty, allocation-free storage without accepting input.
            #[must_use]
            pub fn new() -> Self { Self { sponge: cshake::$storage::new(), metadata: Metadata::new() } }
            #[cfg(test)]
            pub(super) fn metadata_cleared(&self) -> bool { self.metadata.cleared() }
            /// Runs a byte-customized scope. Setup failure skips the callback.
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nlet escaped = w.with(b\"\", |state| state);\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(b\"\", |_| w.with(b\"\", |_| ()));\n```")]
            pub fn with<R>(&mut self, customization: &[u8], operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, TupleHashError> {
                self.with_bits(bytes_input(customization)?, operation)
            }
            /// Runs a canonical-bit customization scope. Neither handles nor item
            /// writers escape; separately borrowed secret outputs may be returned.
            pub fn with_bits<R>(&mut self, customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, TupleHashError> {
                self.metadata.wipe();
                let cleanup = Guard(&mut self.metadata);
                self.sponge.with_bits(bytes_input(b"TupleHash")?, customization, |state| {
                    operation($state { core: Core::new(state, &mut *cleanup.0) })
                }).map_err(TupleHashError::from)
            }
        }
        /// Scoped secret-bearing tuple state. Errors terminate the computation;
        /// finalization consumes the handle. No length or count queries exist.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[must_use = "finalize or cancel the tuple"]
        pub struct $state<'scope> { pub(super) core: Core<'scope, cshake::$backend<'scope>> }
        impl<'scope> $state<'scope> {
            #[cfg(test)]
            pub(super) fn terminal_and_cleared(&self) -> bool { self.core.terminal_and_cleared() }
            /// Appends a complete byte item. Empty items remain distinct members.
            pub fn push_item(&mut self, input: &[u8]) -> Result<(), TupleHashError> { self.core.item_bytes(input) }
            /// Appends one complete canonical arbitrary-bit item.
            pub fn push_item_bits(&mut self, input: Fips202BitString<'_>) -> Result<(), TupleHashError> { self.core.item(input) }
            /// Opens an exact-length item; it must be finished before any other
            /// operation. Drop, cancellation or a failed fragment clears the tuple.
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(b\"\", |mut state| state.begin_item(0));\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(b\"\", |mut state| { let item = state.begin_item(0).unwrap(); state.push_item(b\"x\"); item.finish(); });\n```")]
            pub fn begin_item(&mut self, bits: u128) -> Result<$writer<'_, 'scope>, TupleHashError> {
                self.core.begin(bits)?;
                Ok($writer { core: &mut self.core, complete: false })
            }
            /// Produces explicitly declassified byte output; failures preserve it.
            pub fn finalize_public(self, output: &mut [u8], _authority: TupleHashPublicDeclassification) -> Result<(), TupleHashError> {
                let valid = byte_valid(output.len());
                self.core.public(output, valid)
            }
            /// Produces canonical-bit public output. Empty output requires zero
            /// valid bits; a nonempty destination requires 1..=8.
            pub fn finalize_public_bits(self, output: &mut [u8], valid: u8, _authority: TupleHashPublicDeclassification) -> Result<(), TupleHashError> {
                self.core.public(output, valid)
            }
            /// Produces typed secret output; every failure clears the destination.
            pub fn finalize_secret<'out>(self, output: &'out mut [u8]) -> Result<TupleHashSecretOutput<'out>, TupleHashError> {
                let valid = byte_valid(output.len());
                self.core.secret(output, valid)
            }
            /// Produces canonical-bit secret output, clearing the whole destination
            /// even if the bit shape or tuple state is invalid.
            pub fn finalize_secret_bits<'out>(self, output: &'out mut [u8], valid: u8) -> Result<TupleHashSecretOutput<'out>, TupleHashError> {
                self.core.secret(output, valid)
            }
            /// Consumes and clears the tuple without producing output.
            pub fn cancel(self) {}
        }
        /// Exclusive exact-length item writer; an unfinished writer closes its
        /// parent even if forgotten. There is no remaining-length query.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($writer), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($writer), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($writer), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($writer), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($writer), "<'static, 'static>>();\n```")]
        #[must_use = "finish the complete item or cancel it"]
        pub struct $writer<'item, 'scope> { core: &'item mut Core<'scope, cshake::$backend<'scope>>, complete: bool }
        impl $writer<'_, '_> {
            /// Appends byte data; an overlong fragment clears and terminates.
            pub fn update(&mut self, input: &[u8]) -> Result<(), TupleHashError> { self.core.fragment_bytes(input) }
            /// Appends canonical bits; fragments need not be byte aligned.
            pub fn update_bits(&mut self, input: Fips202BitString<'_>) -> Result<(), TupleHashError> { self.core.fragment(input) }
            /// Completes only an exactly filled item. Failure clears the tuple.
            pub fn finish(mut self) -> Result<(), TupleHashError> { self.core.complete()?; self.complete = true; Ok(()) }
            /// Cancels this item and its parent tuple.
            pub fn cancel(self) {}
        }
        impl Drop for $writer<'_, '_> { fn drop(&mut self) { if !self.complete { self.core.cancel(); } } }
    };
}
fixed!(
    TupleHash128Workspace,
    TupleHash128,
    TupleHash128ItemWriter,
    Cshake128Workspace,
    Cshake128
);
fixed!(
    TupleHash256Workspace,
    TupleHash256,
    TupleHash256ItemWriter,
    Cshake256Workspace,
    Cshake256
);
