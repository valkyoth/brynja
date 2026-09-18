use super::{fixed, reader::Output};
use crate::{
    Fips202BitString, TupleHashError, TupleHashPublicDeclassification, TupleHashSecretOutput,
};
use brynja_hash_sha3::hardened_in_place as cshake;

macro_rules! xof {
    ($workspace:ident, $state:ident, $reader:ident, $fixed_workspace:ident, $fixed_state:ident, $writer:ident, $backend_reader:ident) => {
        /// Caller-owned portable TupleHashXOF storage, borrowed before input.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ">();\n```")]
        pub struct $workspace { inner: fixed::$fixed_workspace }
        impl Default for $workspace { fn default() -> Self { Self::new() } }
        impl $workspace {
            /// Constructs empty, allocation-free storage without accepting input.
            #[must_use]
            pub fn new() -> Self { Self { inner: fixed::$fixed_workspace::new() } }
            /// Byte customization scope; setup failure skips the callback.
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nlet escaped = w.with(b\"\", |state| state);\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nlet escaped = w.with(b\"\", |state| state.finalize_xof());\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(b\"\", |_| w.with(b\"\", |_| ()));\n```")]
            pub fn with<R>(&mut self, customization: &[u8], operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, TupleHashError> {
                self.inner.with(customization, |inner| operation($state { inner }))
            }
            /// Canonical-bit customization scope. Handles cannot escape; a typed
            /// secret output borrowing a separate destination may be returned.
            pub fn with_bits<R>(&mut self, customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, TupleHashError> {
                self.inner.with_bits(customization, |inner| operation($state { inner }))
            }
            #[cfg(test)]
            pub(super) fn metadata_cleared(&self) -> bool { self.inner.metadata_cleared() }
        }
        /// Exclusive absorbing handle; no inline secret owner moves into readers.
        /// Errors terminate. There are no length, item-count or preflight queries.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[must_use = "finalize or cancel the tuple"]
        pub struct $state<'scope> { inner: fixed::$fixed_state<'scope> }
        impl<'scope> $state<'scope> {
            /// Appends a byte item; an empty item remains a distinct tuple member.
            pub fn push_item(&mut self, input: &[u8]) -> Result<(), TupleHashError> { self.inner.push_item(input) }
            /// Appends one complete canonical arbitrary-bit item.
            pub fn push_item_bits(&mut self, input: Fips202BitString<'_>) -> Result<(), TupleHashError> { self.inner.push_item_bits(input) }
            /// Opens an exclusive exact-length writer. Dropping, cancelling or
            /// forgetting an unfinished writer prevents parent finalization.
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(b\"\", |mut state| state.begin_item(0));\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::hardened_in_place::", stringify!($workspace), ";\nlet mut w = ", stringify!($workspace), "::new();\nw.with(b\"\", |mut state| { let item = state.begin_item(0).unwrap(); state.finalize_xof(); item.finish(); });\n```")]
            pub fn begin_item(&mut self, bits: u128) -> Result<fixed::$writer<'_, 'scope>, TupleHashError> { self.inner.begin_item(bits) }
            /// Consumes absorption, appends right_encode(0), and borrows the same
            /// workspace for output. An open/incomplete item rejects this transition.
            pub fn finalize_xof(self) -> Result<$reader<'scope>, TupleHashError> {
                let (reader, cleanup) = self.inner.core.finish_xof()?;
                Ok($reader { inner: Output::new(reader, cleanup) })
            }
            /// Consumes and clears the tuple without producing output.
            pub fn cancel(self) {}
        }
        /// Exclusive incremental reader. Public writes require declassification;
        /// failed secret destinations and dropped typed outputs are cleared.
        /// Recoverable unwind and scope exit clear storage, even after forget.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[must_use = "read or cancel the scoped TupleHashXOF reader"]
        pub struct $reader<'scope> { inner: Output<'scope, cshake::$backend_reader<'scope>> }
        impl $reader<'_> {
            /// Emits the next bytes. Errors are terminal and preserve public output.
            pub fn squeeze_public(&mut self, output: &mut [u8], _authority: TupleHashPublicDeclassification) -> Result<(), TupleHashError> { self.inner.public(output) }
            /// Emits typed secret bytes; every failure clears the destination.
            pub fn squeeze_secret<'out>(&mut self, output: &'out mut [u8]) -> Result<TupleHashSecretOutput<'out>, TupleHashError> { self.inner.secret(output) }
            /// Emits final canonical public bits and consumes the reader. Empty
            /// output requires zero valid bits, otherwise 1..=8; errors preserve it.
            pub fn squeeze_final_bits_public(self, output: &mut [u8], valid: u8, _authority: TupleHashPublicDeclassification) -> Result<(), TupleHashError> { self.inner.final_public(output, valid) }
            /// Emits final canonical secret bits and consumes the reader. Invalid
            /// bit shapes also clear the entire destination.
            pub fn squeeze_final_bits_secret<'out>(self, output: &'out mut [u8], valid: u8) -> Result<TupleHashSecretOutput<'out>, TupleHashError> { self.inner.final_secret(output, valid) }
            /// Consumes and clears the reader without further output.
            pub fn cancel(self) {}
        }
    };
}
xof!(
    TupleHashXof128Workspace,
    TupleHashXof128,
    TupleHashXof128Reader,
    TupleHash128Workspace,
    TupleHash128,
    TupleHash128ItemWriter,
    Cshake128Reader
);
xof!(
    TupleHashXof256Workspace,
    TupleHashXof256,
    TupleHashXof256Reader,
    TupleHash256Workspace,
    TupleHash256,
    TupleHash256ItemWriter,
    Cshake256Reader
);

#[cfg(test)]
mod tests;
