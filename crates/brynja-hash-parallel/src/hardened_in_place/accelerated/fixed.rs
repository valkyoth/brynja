use super::{backend::Backend, *};

macro_rules! fixed {
    ($workspace:ident, $state:ident, $storage:ident, $backend:ident, $leaf:ident) => {
        /// Caller-owned root/leaf sponge storage and public-output staging.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        pub struct $workspace<'authority> {
            sponge: api::$storage<'authority>,
            leaf: api::$leaf<'authority>,
            metadata: Metadata,
            stage: [u8;168],
        }
        impl<'authority> $workspace<'authority> {
            /// Binds separate supplied root/leaf sessions; either rejection fails.
            /// Both may borrow the same authority. No input is accepted here.
            pub fn new(root: KeccakSession<'authority>, leaf: KeccakSession<'authority>) -> Result<Self, ParallelHashError> {
                Ok(Self { sponge: api::$storage::new(root)?, leaf: api::$leaf::new(leaf)?, metadata: Metadata::new(), stage: [0;168] })
            }
            /// Non-authorizing root route/health observation, not secret lengths.
            #[must_use]
            pub fn root_report(&self) -> Report { self.sponge.report() }
            /// Non-authorizing leaf route/health observation.
            #[must_use]
            pub fn leaf_report(&self) -> Report { self.leaf.report() }
            /// Byte customization. B is the nonempty block length. Built-in
            /// public staging supports up to 168 bytes; secret output is unbounded
            /// by staging. Setup failures skip the callback.
            #[doc = concat!("```compile_fail\nfn escape(w: &mut brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'_>) { let escaped = w.with(&mut [0;8], b\"\", |state| state); }\n```")]
            #[doc = concat!("```compile_fail\nfn overlap(w: &mut brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'_>) { w.with(&mut [0;8], b\"\", |_| w.with(&mut [0;8], b\"\", |_| ())); }\n```")]
            pub fn with<R>(&mut self, block: &mut [u8], customization: &[u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, ParallelHashError> {
                let block = Block(block);
                self.with_bits(&mut *block.0, byte_string(customization)?, operation)
            }
            /// Canonical-bit customization, with built-in public staging.
            pub fn with_bits<R>(&mut self, block: &mut [u8], customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, ParallelHashError> {
                Self::run_scope(&mut self.sponge, &mut self.leaf, &mut self.metadata, &mut self.stage, block, customization, operation)
            }
            /// Caller staging for arbitrary-width transactional public output.
            /// The complete block and scratch clear on every scope exit.
            pub fn with_scratch<R>(&mut self, block: &mut [u8], customization: &[u8], scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, ParallelHashError> {
                let block = Block(block); let scratch = Block(scratch);
                self.with_bits_and_scratch(&mut *block.0, byte_string(customization)?, &mut *scratch.0, operation)
            }
            /// Canonical-bit customization and borrowed public staging.
            pub fn with_bits_and_scratch<R>(&mut self, block: &mut [u8], customization: Fips202BitString<'_>, scratch: &mut [u8], operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, ParallelHashError> {
                Self::run_scope(&mut self.sponge, &mut self.leaf, &mut self.metadata, scratch, block, customization, operation)
            }
            fn run_scope<R>(sponge: &mut api::$storage<'authority>, leaf: &mut api::$leaf<'authority>, metadata: &mut Metadata, scratch: &mut [u8], block: &mut [u8], customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($state<'scope, 'authority>) -> R) -> Result<R, ParallelHashError> {
                metadata.wipe();
                let cleanup = Guard(metadata); let scratch = Block(scratch); let block = Block(block);
                if block.0.is_empty() { return Err(ParallelHashError::InvalidBlockSize); }
                sponge.with_bits(byte_string(b"ParallelHash")?, customization, |state| {
                    let core = Core::new(Backend { state, leaf, scratch: &mut *scratch.0 }, &mut *cleanup.0, &mut *block.0)?;
                    Ok(operation($state { core }))
                }).map_err(ParallelHashError::from)?
            }
        }
        /// Exclusive streaming state. Errors are terminal. Consuming finalizers
        /// cannot be reused; no accumulated-length, count or preflight query exists.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($state), "<'static, 'static>>();\n```")]
        #[must_use = "finalize or cancel the scoped ParallelHash state"]
        pub struct $state<'scope, 'authority> { pub(super) core: Core<'scope, Backend<api::$backend<'scope, 'authority>, &'scope mut api::$leaf<'authority>, &'scope mut [u8]>> }
        impl $state<'_, '_> {
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
    Cshake128,
    Shake128Workspace
);
fixed!(
    ParallelHash256Workspace,
    ParallelHash256,
    Cshake256Workspace,
    Cshake256,
    Shake256Workspace
);
