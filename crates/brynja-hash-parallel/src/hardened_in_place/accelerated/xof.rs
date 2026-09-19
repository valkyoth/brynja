use super::super::reader::Output;
use super::{backend::Output as BackendOutput, fixed};
use crate::{
    Fips202BitString, ParallelHashError, ParallelHashPublicDeclassification,
    ParallelHashSecretOutput, core_state::byte_string,
};
use brynja_hash_sha3::hardened_execution::{KeccakSession, Report, in_place as api};

macro_rules! xof {
    ($workspace:ident, $state:ident, $reader:ident, $fixed_workspace:ident, $fixed_state:ident, $backend_reader:ident) => {
        /// Empty accelerated ParallelHashXOF storage, borrowed before accepting input.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        pub struct $workspace<'authority> { inner: fixed::$fixed_workspace<'authority> }
        impl<'authority> $workspace<'authority> {
            /// Binds supplied root and leaf sessions before accepting input.
            /// They may share an authority; neither ever silently falls back.
            pub fn new(root: KeccakSession<'authority>, leaf: KeccakSession<'authority>) -> Result<Self, ParallelHashError> {
                Ok(Self { inner: fixed::$fixed_workspace::new(root, leaf)? })
            }
            /// Non-authorizing root route/health observation.
            #[must_use]
            pub fn root_report(&self) -> Report { self.inner.root_report() }
            /// Non-authorizing leaf route/health observation.
            #[must_use]
            pub fn leaf_report(&self) -> Report { self.inner.leaf_report() }
            /// Byte customization; B equals the nonempty block length.
            /// Each public read is limited to the built-in 168-byte stage.
            /// Secret reads are not stage-width limited. Setup failure skips the callback.
            #[doc = concat!("```compile_fail\nfn escape(w: &mut brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'_>) { let escaped = w.with(&mut [0;8], b\"\", |state| state); }\n```")]
            #[doc = concat!("```compile_fail\nfn escape(w: &mut brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'_>) { let escaped = w.with(&mut [0;8], b\"\", |state| state.finalize_xof()); }\n```")]
            #[doc = concat!("```compile_fail\nfn overlap(w: &mut brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'_>) { w.with(&mut [0;8], b\"\", |_| w.with(&mut [0;8], b\"\", |_| ())); }\n```")]
            pub fn with<R>(&mut self, block: &mut [u8], customization: &[u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, ParallelHashError> {
                self.inner.with(block, customization, |inner| operation($state { inner }))
            }
            /// Canonical-bit customization with built-in public staging.
            pub fn with_bits<R>(&mut self, block: &mut [u8], customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, ParallelHashError> {
                self.inner.with_bits(block, customization, |inner| operation($state { inner }))
            }
            /// Caller staging for arbitrary-width transactional public reads.
            /// Block and complete scratch are cleared on every scope exit.
            pub fn with_scratch<R>(&mut self, block: &mut [u8], customization: &[u8], scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, ParallelHashError> {
                self.inner.with_scratch(block, customization, scratch, |inner| operation($state { inner }))
            }
            /// Canonical-bit customization and caller staging.
            pub fn with_bits_and_scratch<R>(&mut self, block: &mut [u8], customization: Fips202BitString<'_>, scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, ParallelHashError> {
                self.inner.with_bits_and_scratch(block, customization, scratch, |inner| operation($state { inner }))
            }
        }
        /// Exclusive absorbing handle. Update errors are terminal; finalization
        /// consumes it. No accumulated-length, leaf-count or preflight query exists.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[must_use = "finalize or cancel the scoped ParallelHashXOF state"]
        pub struct $state<'scope, 'authority> { inner: fixed::$fixed_state<'scope, 'authority> }
        impl<'scope, 'authority> $state<'scope, 'authority> {
            /// Absorbs complete bytes; partial final input belongs to finalization.
            pub fn update(&mut self, input: &[u8]) -> Result<(), ParallelHashError> { self.inner.update(input) }
            /// Appends right_encode(0) and transfers only the sponge borrow.
            /// Leaf output, counters and block are cleared before output begins.
            /// The reader uses only root authority; completed leaf work is not re-run.
            pub fn finalize_xof(self) -> Result<$reader<'scope, 'authority>, ParallelHashError> {
                self.finalize_bits_xof(byte_string(&[])?)
            }
            /// Appends canonical final input bits and consumes absorption.
            pub fn finalize_bits_xof(self, tail: Fips202BitString<'_>) -> Result<$reader<'scope, 'authority>, ParallelHashError> {
                Ok($reader { inner: Output::new(self.inner.core.finish_xof(tail)?) })
            }
            /// Consumes and clears absorption without output.
            pub fn cancel(self) {}
        }
        /// Borrowed incremental XOF reader. Errors terminate; public errors
        /// preserve output, secret errors clear it. Drop cancels. Scope exit
        /// covers forgotten readers and recoverable unwind, not panic=abort.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[must_use = "read or cancel the scoped ParallelHashXOF reader"]
        pub struct $reader<'scope, 'authority> { inner: Output<BackendOutput<api::$backend_reader<'scope, 'authority>, &'scope mut [u8]>> }
        impl $reader<'_, '_> {
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
