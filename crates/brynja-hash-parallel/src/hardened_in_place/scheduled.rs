use super::{
    reader::Output,
    scheduled_core::{Count, CountGuard, Root},
    xof,
};
use crate::{
    Fips202BitString, ParallelHashError as Error, ParallelHashPublicDeclassification as Public,
    ParallelHashSecretOutput, core_state::byte_string,
};
use brynja_hash_sha3::hardened_in_place as api;

macro_rules! scheduled {
    ($workspace:ident, $collector:ident, $plan:ident, $result:ident, $storage:ident, $backend:ident, $reader:ident) => {
        /// Empty portable storage for an exact-plan ordered ParallelHash collector.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ">();\n```")]
        pub struct $workspace { sponge: api::$storage, count: Count }
        impl Default for $workspace { fn default() -> Self { Self::new() } }
        impl $workspace {
            /// Constructs empty storage before input or customization is accepted.
            #[must_use]
            pub fn new() -> Self { Self { sponge: api::$storage::new(), count: Count::new() } }
            /// Borrows root and counter for one exact plan. Leaf jobs may execute in
            /// any caller-chosen order but must be merged in increasing index order.
            /// Plan shape is caller-visible metadata; it is not concealed here.
            #[doc = concat!("```compile_fail\nfn probe(w: &mut brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ", plan: &brynja_hash_parallel::", stringify!($plan), "<'_>) { let escaped = w.with(plan, b\"\", |state| state); }\n```")]
            #[doc = concat!("```compile_fail\nfn probe(w: &mut brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ", plan: &brynja_hash_parallel::", stringify!($plan), "<'_>) { let escaped = w.with(plan, b\"\", |state| state.finalize_xof()); }\n```")]
            #[doc = concat!("```compile_fail\nfn probe(w: &mut brynja_hash_parallel::hardened_in_place::", stringify!($workspace), ", plan: &brynja_hash_parallel::", stringify!($plan), "<'_>) { let escaped = w.with(plan, b\"\", |_| w.with(plan, b\"\", |_| ())); }\n```")]
            pub fn with<'plan, 'input, R>(&mut self, plan: &'plan crate::$plan<'input>, customization: &[u8], operation: impl for<'scope> FnOnce($collector<'scope, 'plan, 'input>) -> R) -> Result<R, Error> {
                self.with_bits(plan, byte_string(customization)?, operation)
            }
            /// Canonical-bit customization. Setup failure skips the callback;
            /// destinations captured only by that callback cannot be cleared.
            pub fn with_bits<'plan, 'input, R>(&mut self, plan: &'plan crate::$plan<'input>, customization: Fips202BitString<'_>, operation: impl for<'scope> FnOnce($collector<'scope, 'plan, 'input>) -> R) -> Result<R, Error> {
                self.count.wipe();
                let guard = CountGuard(&mut self.count);
                self.sponge.with_bits(byte_string(b"ParallelHash")?, customization, |state| {
                    let inner = Root::new(state, &mut *guard.0, plan.block_size(), plan.leaf_count())?;
                    Ok(operation($collector { inner, plan }))
                }).map_err(Error::from)?
            }
            #[cfg(test)]
            pub(super) fn cleared(&self) -> bool { self.count.cleared() }
        }
        /// Scope-bound ordered collector. Merge errors are terminal. Fixed and
        /// XOF finalization consume it; no accumulated-count/preflight query exists.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($collector), "<'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($collector), "<'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($collector), "<'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($collector), "<'static, 'static, 'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::hardened_in_place::", stringify!($collector), "<'static, 'static, 'static>>();\n```")]
        #[must_use = "complete or cancel the scoped scheduled collector"]
        pub struct $collector<'scope, 'plan, 'input> {
            inner: Root<'scope, api::$backend<'scope>>,
            plan: &'plan crate::$plan<'input>,
        }
        impl<'scope, 'plan, 'input> $collector<'scope, 'plan, 'input> {
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
            pub fn finalize_xof(self) -> Result<xof::$reader<'scope>, Error> {
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
    ParallelHashXof128Reader
);
scheduled!(
    ParallelHash256CollectorWorkspace,
    ParallelHash256Collector,
    ParallelHash256Plan,
    ParallelHash256LeafResult,
    Cshake256Workspace,
    Cshake256,
    ParallelHashXof256Reader
);

#[cfg(test)]
mod tests;
