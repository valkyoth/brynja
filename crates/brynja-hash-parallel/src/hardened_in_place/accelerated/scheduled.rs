use super::super::{
    core_state::Block,
    reader::Output,
    scheduled_core::{Count, CountGuard, Root},
};
use super::{KeccakSession, Report, scheduled_backend::Scheduled, xof};
use crate::{
    Fips202BitString, ParallelHashError as Error, ParallelHashPublicDeclassification as Public,
    ParallelHashSecretOutput, core_state::byte_string,
};
use brynja_hash_sha3::hardened_execution::in_place as api;

macro_rules! scheduled {
    ($workspace:ident, $collector:ident, $plan:ident, $result:ident, $storage:ident, $backend:ident, $reader:ident, $batch:ident) => {
        /// Empty accelerated storage for an exact-plan ordered ParallelHash collector.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        pub struct $workspace<'authority> { sponge: api::$storage<'authority>, count: Count, stage: [u8;168] }
        impl<'authority> $workspace<'authority> {
            /// Constructs empty storage before input or customization is accepted.
            pub fn new(session: KeccakSession<'authority>) -> Result<Self, Error> {
                Ok(Self { sponge: api::$storage::new(session)?, count: Count::new(), stage: [0;168] })
            }
            /// Non-authorizing root route/health observation, not secret lengths.
            #[must_use]
            pub fn report(&self) -> Report { self.sponge.report() }
            /// Borrows root and counter for one exact plan. Leaf jobs may execute in
            /// any caller-chosen order but must be merged in increasing index order.
            /// Plan shape is caller-visible metadata; it is not concealed here.
            #[doc = concat!("```compile_fail\nfn probe(w: &mut brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'_>, plan: &brynja_hash_parallel::", stringify!($plan), "<'_>) { let escaped = w.with(plan, b\"\", |state| state); }\n```")]
            #[doc = concat!("```compile_fail\nfn probe(w: &mut brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'_>, plan: &brynja_hash_parallel::", stringify!($plan), "<'_>) { let escaped = w.with(plan, b\"\", |state| state.finalize_xof()); }\n```")]
            #[doc = concat!("```compile_fail\nfn probe(w: &mut brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'_>, plan: &brynja_hash_parallel::", stringify!($plan), "<'_>) { let escaped = w.with(plan, b\"\", |_| w.with(plan, b\"\", |_| ())); }\n```")]
            pub fn with<'plan, 'input, R>(&mut self, plan: &'plan crate::$plan<'input>, customization: &[u8], operation: impl for<'scope> FnOnce($collector<'scope, 'plan, 'input, 'authority>) -> R) -> Result<R, Error> {
                self.with_bits(plan, byte_string(customization)?, operation)
            }
            /// Canonical-bit customization. Setup failure skips the callback;
            /// destinations captured only by that callback cannot be cleared.
            pub fn with_bits<'plan, 'input, R>(&mut self, plan: &'plan crate::$plan<'input>, customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($collector<'scope, 'plan, 'input, 'authority>) -> R) -> Result<R, Error> {
                Self::run_scope(&mut self.sponge, &mut self.count, &mut self.stage, plan, customization, operation)
            }
            /// Caller staging for transactional public output wider than 168 bytes.
            /// The full scratch is cleared even when setup skips the callback.
            pub fn with_scratch<'plan, 'input, R>(&mut self, plan: &'plan crate::$plan<'input>, customization: &[u8], scratch: &mut [u8], operation: impl for<'scope> FnOnce($collector<'scope, 'plan, 'input, 'authority>) -> R) -> Result<R, Error> {
                let scratch = Block(scratch);
                self.with_bits_and_scratch(plan, byte_string(customization)?, &mut *scratch.0, operation)
            }
            /// Canonical-bit customization and caller public-output staging.
            pub fn with_bits_and_scratch<'plan, 'input, R>(&mut self, plan: &'plan crate::$plan<'input>, customization: Fips202BitString<'_>, scratch: &mut [u8], operation: impl for<'scope> FnOnce($collector<'scope, 'plan, 'input, 'authority>) -> R) -> Result<R, Error> {
                Self::run_scope(&mut self.sponge, &mut self.count, scratch, plan, customization, operation)
            }
            fn run_scope<'plan, 'input, R>(sponge: &mut api::$storage<'authority>, count: &mut Count, scratch: &mut [u8], plan: &'plan crate::$plan<'input>, customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($collector<'scope, 'plan, 'input, 'authority>) -> R) -> Result<R, Error> {
                count.wipe();
                let guard = CountGuard(count);
                let scratch = Block(scratch);
                sponge.with_bits(byte_string(b"ParallelHash")?, customization, |state| {
                    let inner = Root::new(Scheduled { state, scratch: &mut *scratch.0 }, &mut *guard.0, plan.block_size(), plan.leaf_count())?;
                    Ok(operation($collector { inner, plan }))
                }).map_err(Error::from)?
            }
        }
        /// Scope-bound ordered collector. Merge errors are terminal. Fixed and
        /// XOF finalization consume it; no accumulated-count/preflight query exists.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($collector), "<'static, 'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($collector), "<'static, 'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($collector), "<'static, 'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($collector), "<'static, 'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($collector), "<'static, 'static, 'static, 'static>>();\n```")]
        #[must_use = "complete or cancel the scoped scheduled collector"]
        pub struct $collector<'scope, 'plan, 'input, 'authority> {
            inner: Root<'scope, Scheduled<api::$backend<'scope, 'authority>, &'scope mut [u8]>>,
            plan: &'plan crate::$plan<'input>,
        }
        impl<'scope, 'plan, 'input, 'authority> $collector<'scope, 'plan, 'input, 'authority> {
            /// Consumes ordered multibuffer results bound to the exact plan.
            /// Every merge error is terminal; the complete result storage clears.
            #[cfg(feature = "hardened-batch-execution")]
            pub fn merge_batch(&mut self, leaves: crate::execution::batch::scoped::$batch<'plan, 'input, '_>) -> Result<(), Error> {
                leaves.merge(self.plan, |index, bytes| self.inner.merge(index, bytes))
            }
            /// Consumes and clears the typed leaf output on success or failure.
            /// Results must match the exact plan instance, shape and next index.
            pub fn merge(&mut self, result: crate::$result<'plan, '_>) -> Result<(), Error> {
                self.inner.merge(self.plan.checked_index(&result), result.expose())
            }
            /// Consumes complete collection into explicitly declassified byte output.
            pub fn finalize_public(self, output: &mut [u8], authority: Public) -> Result<(), Error> {
                let valid = if output.is_empty() { 0 } else { 8 };
                self.finalize_public_bits(output, valid, authority)
            }
            /// Canonical fixed public output; errors preserve the destination.
            pub fn finalize_public_bits(self, output: &mut [u8], valid: u8, _authority: Public) -> Result<(), Error> {
                self.inner.public(output, valid)
            }
            /// Typed byte output. Every error clears the supplied destination.
            pub fn finalize_secret<'out>(self, output: &'out mut [u8]) -> Result<ParallelHashSecretOutput<'out>, Error> {
                let valid = if output.is_empty() { 0 } else { 8 };
                self.finalize_secret_bits(output, valid)
            }
            /// Canonical fixed secret output; errors clear the entire destination.
            pub fn finalize_secret_bits<'out>(self, output: &'out mut [u8], valid: u8) -> Result<ParallelHashSecretOutput<'out>, Error> {
                self.inner.secret(output, valid)
            }
            /// Requires every planned leaf exactly once, appends right_encode(0),
            /// and clears the counter before transferring the root borrow.
            pub fn finalize_xof(self) -> Result<xof::$reader<'scope, 'authority>, Error> {
                Ok(xof::$reader { inner: Output::new(self.inner.xof()?) })
            }
            /// Consumes the collector and clears its borrowed root/counter.
            pub fn cancel(self) {}
        }
    };
}
scheduled!(
    ParallelHash128CollectorWorkspace,
    ParallelHash128Collector,
    ParallelHash128Plan,
    ParallelHash128LeafResult,
    Cshake128Workspace,
    Cshake128,
    ParallelHashXof128Reader,
    Leaves128
);
scheduled!(
    ParallelHash256CollectorWorkspace,
    ParallelHash256Collector,
    ParallelHash256Plan,
    ParallelHash256LeafResult,
    Cshake256Workspace,
    Cshake256,
    ParallelHashXof256Reader,
    Leaves256
);
