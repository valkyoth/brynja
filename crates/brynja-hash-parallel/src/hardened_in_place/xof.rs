use super::{fixed, reader::Output};
use crate::{
    Fips202BitString, ParallelHashError, ParallelHashPublicDeclassification,
    ParallelHashSecretOutput, core_state::byte_string,
};
use brynja_hash_sha3::hardened_in_place as api;

macro_rules! xof {
    ($workspace:ident, $state:ident, $reader:ident, $fixed_workspace:ident, $fixed_state:ident, $backend_reader:ident) => {
        /// Empty portable ParallelHashXOF storage, borrowed before accepting input.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        pub struct $workspace { inner: fixed::$fixed_workspace }
        impl Default for $workspace { fn default() -> Self { Self::new() } }
        impl $workspace {
            /// Constructs empty storage. No secret input is accepted here.
            #[must_use]
            pub fn new() -> Self { Self { inner: fixed::$fixed_workspace::new() } }
            /// Runs a scope with byte customization and B equal to the nonempty
            /// block buffer length. Setup failure skips the callback.
            #[doc = concat!("```compile_fail\nlet mut w = brynja_hash_parallel::hardened_in_place::", stringify!($workspace), "::new();\nlet escaped = w.with(&mut [0;8], b\"\", |state| state);\n```")]
            #[doc = concat!("```compile_fail\nlet mut w = brynja_hash_parallel::hardened_in_place::", stringify!($workspace), "::new();\nlet escaped = w.with(&mut [0;8], b\"\", |state| state.finalize_xof());\n```")]
            #[doc = concat!("```compile_fail\nlet mut w = brynja_hash_parallel::hardened_in_place::", stringify!($workspace), "::new();\nw.with(&mut [0;8], b\"\", |_| w.with(&mut [0;8], b\"\", |_| ()));\n```")]
            pub fn with<R>(&mut self, block: &mut [u8], customization: &[u8], operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, ParallelHashError> {
                self.inner.with(block, customization, |inner| operation($state { inner }))
            }
            /// Canonical-bit customization. State/reader handles cannot escape;
            /// typed outputs borrowing a separate destination may be returned.
            pub fn with_bits<R>(&mut self, block: &mut [u8], customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope>) -> R) -> Result<R, ParallelHashError> {
                self.inner.with_bits(block, customization, |inner| operation($state { inner }))
            }
            #[cfg(test)]
            pub(super) fn cleared(&self) -> bool { self.inner.cleared() }
        }
        /// Exclusive absorbing handle. Update errors are terminal; finalization
        /// consumes it. No accumulated-length, leaf-count or preflight query exists.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($state), "<'static>>();\n```")]
        #[must_use = "finalize or cancel the scoped ParallelHashXOF state"]
        pub struct $state<'scope> { inner: fixed::$fixed_state<'scope> }
        impl<'scope> $state<'scope> {
            /// Absorbs complete bytes; partial final input belongs to finalization.
            pub fn update(&mut self, input: &[u8]) -> Result<(), ParallelHashError> { self.inner.update(input) }
            /// Appends right_encode(0) and transfers only the sponge borrow.
            /// Leaf output, counters and block are cleared before output begins.
            pub fn finalize_xof(self) -> Result<$reader<'scope>, ParallelHashError> {
                self.finalize_bits_xof(byte_string(&[])?)
            }
            /// Appends canonical final input bits and consumes absorption.
            pub fn finalize_bits_xof(self, tail: Fips202BitString<'_>) -> Result<$reader<'scope>, ParallelHashError> {
                Ok($reader { inner: Output::new(self.inner.core.finish_xof(tail)?) })
            }
            /// Consumes and clears absorption without output.
            pub fn cancel(self) {}
        }
        /// Borrowed incremental XOF reader. Errors terminate; public errors
        /// preserve output, secret errors clear it. Drop cancels. Scope exit
        /// covers forgotten readers and recoverable unwind, not panic=abort.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($reader), "<'static>>();\n```")]
        #[must_use = "read or cancel the scoped ParallelHashXOF reader"]
        pub struct $reader<'scope> { pub(super) inner: Output<api::$backend_reader<'scope>> }
        impl $reader<'_> {
            /// Emits the next bytes with explicit public declassification.
            pub fn squeeze_public(&mut self, output: &mut [u8], _authority: ParallelHashPublicDeclassification) -> Result<(), ParallelHashError> { self.inner.public(output) }
            /// Emits secret bytes, returning a separate clearing output borrow.
            pub fn squeeze_secret<'out>(&mut self, output: &'out mut [u8]) -> Result<ParallelHashSecretOutput<'out>, ParallelHashError> { self.inner.secret(output) }
            /// Emits final canonical bits and consumes the reader. Empty output
            /// requires valid=0; nonempty output requires 1..=8.
            pub fn squeeze_final_bits_public(self, output: &mut [u8], valid: u8, _authority: ParallelHashPublicDeclassification) -> Result<(), ParallelHashError> { self.inner.final_public(output, valid) }
            /// Consuming secret final-bit output. All errors, including invalid
            /// output descriptors, clear the entire destination.
            pub fn squeeze_final_bits_secret<'out>(self, output: &'out mut [u8], valid: u8) -> Result<ParallelHashSecretOutput<'out>, ParallelHashError> { self.inner.final_secret(output, valid) }
            /// Consumes and clears the reader without further output.
            pub fn cancel(self) {}
        }
    };
}
xof!(
    ParallelHashXof128Workspace,
    ParallelHashXof128,
    ParallelHashXof128Reader,
    ParallelHash128Workspace,
    ParallelHash128,
    Cshake128Reader
);
xof!(
    ParallelHashXof256Workspace,
    ParallelHashXof256,
    ParallelHashXof256Reader,
    ParallelHash256Workspace,
    ParallelHash256,
    Cshake256Reader
);

#[cfg(test)]
mod tests;
