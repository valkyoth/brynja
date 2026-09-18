use super::super::reader::Output;
use super::{backend::Backend, cshake, fixed};
use crate::{
    Fips202BitString, TupleHashError, TupleHashPublicDeclassification, TupleHashSecretOutput,
};
use brynja_hash_sha3::hardened_execution::{KeccakSession, Report};

macro_rules! xof {
    ($workspace:ident, $state:ident, $reader:ident, $fixed_workspace:ident, $fixed_state:ident, $writer:ident, $backend_reader:ident) => {
        /// Caller-owned accelerated TupleHashXOF storage, borrowed before input.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        pub struct $workspace<'authority> { inner: fixed::$fixed_workspace<'authority> }
        impl<'authority> $workspace<'authority> {
            /// Binds an existing hardened session without accepting secret input.
            pub fn new(session: KeccakSession<'authority>) -> Result<Self, TupleHashError> {
                Ok(Self { inner: fixed::$fixed_workspace::new(session)? })
            }
            /// Non-authorizing backend/health metadata; never secret lengths.
            #[must_use]
            pub fn report(&self) -> Report { self.inner.report() }
            /// Byte customization scope; setup failure skips the callback.
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::execution::in_place::", stringify!($workspace), ";\nfn rejected(w: &mut ", stringify!($workspace), "<'_>) { let escaped = w.with(b\"\", |state| state); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::execution::in_place::", stringify!($workspace), ";\nfn rejected(w: &mut ", stringify!($workspace), "<'_>) { let escaped = w.with(b\"\", |state| state.finalize_xof()); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::execution::in_place::", stringify!($workspace), ";\nfn rejected(w: &mut ", stringify!($workspace), "<'_>) { w.with(b\"\", |_| w.with(b\"\", |_| ())); }\n```")]
            pub fn with<R>(&mut self, customization: &[u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, TupleHashError> {
                self.inner.with(customization, |inner| operation($state { inner }))
            }
            /// Canonical-bit customization scope. Handles cannot escape; a typed
            /// secret output borrowing a separate destination may be returned.
            pub fn with_bits<R>(&mut self, customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, TupleHashError> {
                self.inner.with_bits(customization, |inner| operation($state { inner }))
            }
            /// Scope with arbitrary-width public-fragment staging, cleared on exit.
            /// Each public fragment must fit; secret reads are not width-limited.
            pub fn with_scratch<R>(&mut self, customization: &[u8], scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, TupleHashError> {
                self.inner.with_scratch(customization, scratch, |inner| operation($state { inner }))
            }
            /// Canonical-bit customization with caller-provided public staging.
            pub fn with_bits_and_scratch<R>(&mut self, customization: Fips202BitString<'_>, scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, TupleHashError> {
                self.inner.with_bits_and_scratch(customization, scratch, |inner| operation($state { inner }))
            }
        }
        /// Exclusive absorbing handle; no inline secret owner moves into readers.
        /// Errors terminate. There are no length, item-count or preflight queries.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[must_use = "finalize or cancel the tuple"]
        pub struct $state<'scope, 'authority> { inner: fixed::$fixed_state<'scope, 'authority> }
        impl<'scope, 'authority> $state<'scope, 'authority> {
            /// Appends a byte item; an empty item remains a distinct tuple member.
            pub fn push_item(&mut self, input: &[u8]) -> Result<(), TupleHashError> { self.inner.push_item(input) }
            /// Appends one complete canonical arbitrary-bit item.
            pub fn push_item_bits(&mut self, input: Fips202BitString<'_>) -> Result<(), TupleHashError> { self.inner.push_item_bits(input) }
            /// Opens an exclusive exact-length writer. Dropping, cancelling or
            /// forgetting an unfinished writer prevents parent finalization.
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::execution::in_place::", stringify!($workspace), ";\nfn rejected(w: &mut ", stringify!($workspace), "<'_>) { w.with(b\"\", |mut state| state.begin_item(0)); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::execution::in_place::", stringify!($workspace), ";\nfn rejected(w: &mut ", stringify!($workspace), "<'_>) { w.with(b\"\", |mut state| { let item = state.begin_item(0).unwrap(); state.finalize_xof(); item.finish(); }); }\n```")]
            pub fn begin_item(&mut self, bits: u128) -> Result<fixed::$writer<'_, 'scope, 'authority>, TupleHashError> { self.inner.begin_item(bits) }
            /// Consumes absorption, appends right_encode(0), and borrows the same
            /// workspace for output. An open/incomplete item rejects this transition.
            pub fn finalize_xof(self) -> Result<$reader<'scope, 'authority>, TupleHashError> {
                let (reader, cleanup) = self.inner.core.finish_xof()?;
                Ok($reader { inner: Output::new(reader, cleanup) })
            }
            /// Consumes and clears the tuple without producing output.
            pub fn cancel(self) {}
        }
        /// Exclusive incremental reader. Public writes require declassification;
        /// failed secret destinations and dropped typed outputs are cleared.
        /// Recoverable unwind and scope exit clear storage, even after forget.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($reader), "<'static, 'static>>();\n```")]
        #[must_use = "read or cancel the scoped TupleHashXOF reader"]
        pub struct $reader<'scope, 'authority> { inner: Output<'scope, Backend<cshake::$backend_reader<'scope, 'authority>, &'scope mut [u8]>> }
        impl $reader<'_, '_> {
            /// Emits the next bytes using the scope's public staging (168 bytes by
            /// default). Too-short staging or any other error terminates the reader
            /// and preserves public output. No supplied backend failure falls back.
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
