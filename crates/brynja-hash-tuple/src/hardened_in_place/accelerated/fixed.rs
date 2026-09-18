use super::{backend::Backend, *};

macro_rules! fixed {
    ($workspace:ident, $state:ident, $writer:ident, $storage:ident, $backend:ident) => {
        /// Caller-owned accelerated TupleHash storage, borrowed before secret input.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        pub struct $workspace<'authority> {
            sponge: cshake::$storage<'authority>,
            metadata: Metadata,
            stage: [u8; 168],
        }
        impl<'authority> $workspace<'authority> {
            /// Binds the supplied hardened session before accepting input.
            pub fn new(session: KeccakSession<'authority>) -> Result<Self, TupleHashError> {
                Ok(Self { sponge: cshake::$storage::new(session)?, metadata: Metadata::new(), stage: [0; 168] })
            }
            /// Non-authorizing backend/health metadata, not secret lengths.
            #[must_use]
            pub fn report(&self) -> Report { self.sponge.report() }
            /// Byte customization scope. Setup failure skips the callback.
            /// Public output is limited to 168 bytes unless caller scratch is supplied.
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { let escaped = w.with(b\"\", |state| state); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::execution::in_place::", stringify!($workspace), ";\nfn overlap(w: &mut ", stringify!($workspace), "<'_>) { w.with(b\"\", |_| w.with(b\"\", |_| ())); }\n```")]
            pub fn with<R>(&mut self, customization: &[u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, TupleHashError> {
                self.with_bits(bytes_input(customization)?, operation)
            }
            /// Canonical-bit customization, borrowed before secret processing.
            pub fn with_bits<R>(&mut self, customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, TupleHashError> {
                Self::run_scope(&mut self.sponge, &mut self.metadata, &mut self.stage, customization, operation)
            }
            /// Arbitrary-width transactional public staging, cleared on every exit.
            pub fn with_scratch<R>(&mut self, customization: &[u8], scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, TupleHashError> {
                let scratch = Scratch(scratch);
                self.with_bits_and_scratch(bytes_input(customization)?, scratch.0, operation)
            }
            /// Canonical-bit scope with caller-provided staging. Secret output is
            /// not limited by scratch width. Admission errors skip the callback.
            pub fn with_bits_and_scratch<R>(&mut self, customization: Fips202BitString<'_>, scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, TupleHashError> {
                Self::run_scope(&mut self.sponge, &mut self.metadata, scratch, customization, operation)
            }
            fn run_scope<R>(sponge: &mut cshake::$storage<'authority>, metadata: &mut Metadata, scratch: &mut [u8], customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, TupleHashError> {
                metadata.wipe();
                let cleanup = Guard(metadata);
                let scratch = Scratch(scratch);
                sponge.with_bits(bytes_input(b"TupleHash")?, customization, |state| {
                    operation($state { core: Core::new(Backend { state, scratch: &mut *scratch.0 }, &mut *cleanup.0) })
                }).map_err(TupleHashError::from)
            }
        }
        /// Scoped secret-bearing tuple state. Errors terminate the computation;
        /// finalization consumes the handle. No length or count queries exist.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[must_use = "finalize or cancel the tuple"]
        pub struct $state<'scope, 'authority> { core: Core<'scope, Backend<cshake::$backend<'scope, 'authority>, &'scope mut [u8]>> }
        impl<'scope, 'authority> $state<'scope, 'authority> {
            /// Appends a complete byte item. Empty items remain distinct members.
            pub fn push_item(&mut self, input: &[u8]) -> Result<(), TupleHashError> { self.core.item_bytes(input) }
            /// Appends one complete canonical arbitrary-bit item.
            pub fn push_item_bits(&mut self, input: Fips202BitString<'_>) -> Result<(), TupleHashError> { self.core.item(input) }
            /// Opens an exact-length item; it must be finished before any other
            /// operation. Drop, cancellation or a failed fragment clears the tuple.
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::execution::in_place::", stringify!($workspace), ";\nfn escape(w: &mut ", stringify!($workspace), "<'_>) { w.with(b\"\", |mut state| state.begin_item(0)); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_tuple::execution::in_place::", stringify!($workspace), ";\nfn overlap(w: &mut ", stringify!($workspace), "<'_>) { w.with(b\"\", |mut state| { let item = state.begin_item(0).unwrap(); state.push_item(b\"x\"); item.finish(); }); }\n```")]
            pub fn begin_item(&mut self, bits: u128) -> Result<$writer<'_, 'scope, 'authority>, TupleHashError> {
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
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($writer), "<'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($writer), "<'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($writer), "<'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($writer), "<'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_tuple::execution::in_place::", stringify!($writer), "<'static, 'static, 'static>>();\n```")]
        #[must_use = "finish the complete item or cancel it"]
        pub struct $writer<'item, 'scope, 'authority> { core: &'item mut Core<'scope, Backend<cshake::$backend<'scope, 'authority>, &'scope mut [u8]>>, complete: bool }
        impl $writer<'_, '_, '_> {
            /// Appends byte data; an overlong fragment clears and terminates.
            pub fn update(&mut self, input: &[u8]) -> Result<(), TupleHashError> { self.core.fragment_bytes(input) }
            /// Appends canonical bits; fragments need not be byte aligned.
            pub fn update_bits(&mut self, input: Fips202BitString<'_>) -> Result<(), TupleHashError> { self.core.fragment(input) }
            /// Completes only an exactly filled item. Failure clears the tuple.
            pub fn finish(mut self) -> Result<(), TupleHashError> { self.core.complete()?; self.complete = true; Ok(()) }
            /// Cancels this item and its parent tuple.
            pub fn cancel(self) {}
        }
        impl Drop for $writer<'_, '_, '_> { fn drop(&mut self) { if !self.complete { self.core.cancel(); } } }
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
