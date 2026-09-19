use crate::{CancellationToken, ParallelHashExecutor, ParallelHashExecutorError as Error};
use brynja_hash_parallel::{Fips202BitString, hardened_in_place as api};

macro_rules! scope {
    ($bytes:ident, $bits:ident, $plan:ident, $workspace:ident, $collector:ident, $run:ident) => {
        impl ParallelHashExecutor {
            /// Runs bounded portable leaf workers and lends the completed ordered
            /// root to the caller on this thread. The callback can finalize fixed
            /// output or use an XOF reader, but cannot return the root or reader.
            /// All started workers are joined before the callback or an error.
            /// Admission, cancellation, launch or worker failure skips the callback;
            /// output captured only by that callback is not cleared automatically.
            /// The operation gate remains held through the callback. Recoverable
            /// callback unwinding clears workspace storage and poisons that gate.
            #[doc = concat!("```compile_fail\nuse brynja_hash_parallel_std::{ParallelHashExecutor, CancellationToken};\nuse brynja_hash_parallel::{", stringify!($plan), ", hardened_in_place::", stringify!($workspace), "};\nfn escape(e: &ParallelHashExecutor, w: &mut ", stringify!($workspace), ", p: &", stringify!($plan), "<'_>, c: &CancellationToken) { let state = e.", stringify!($bytes), "(w, p, b\"\", c, |root| root); }\n```")]
            #[doc = concat!("```compile_fail\nuse brynja_hash_parallel_std::{ParallelHashExecutor, CancellationToken};\nuse brynja_hash_parallel::{", stringify!($plan), ", hardened_in_place::", stringify!($workspace), "};\nfn escape(e: &ParallelHashExecutor, w: &mut ", stringify!($workspace), ", p: &", stringify!($plan), "<'_>, c: &CancellationToken) { let reader = e.", stringify!($bytes), "(w, p, b\"\", c, |root| root.finalize_xof()); }\n```")]
            pub fn $bytes<'plan, 'input, R>(
                &self,
                workspace: &mut api::$workspace,
                plan: &'plan brynja_hash_parallel::$plan<'input>,
                customization: &[u8],
                cancellation: &CancellationToken,
                operation: impl for<'scope> FnOnce(api::$collector<'scope, 'plan, 'input>) -> R,
            ) -> Result<R, Error> {
                let valid = if customization.is_empty() { 0 } else { 8 };
                let customization = Fips202BitString::new(customization, valid)
                    .map_err(|_| brynja_hash_parallel::ParallelHashError::InvalidBitString)?;
                self.$bits(workspace, plan, customization, cancellation, operation)
            }

            /// Canonical-bit customization variant of the scoped portable
            /// threaded collector. Plan/input shape remains caller-visible.
            /// Cancellation is checked before the callback; the callback controls
            /// its own subsequent work. No CPU acceleration is selected here.
            pub fn $bits<'plan, 'input, R>(
                &self,
                workspace: &mut api::$workspace,
                plan: &'plan brynja_hash_parallel::$plan<'input>,
                customization: Fips202BitString<'_>,
                cancellation: &CancellationToken,
                operation: impl for<'scope> FnOnce(api::$collector<'scope, 'plan, 'input>) -> R,
            ) -> Result<R, Error> {
                let _gate = self.enter_operation()?;
                crate::scoped_worker::admit(plan.leaf_count(), self.workers, self.max_leaves, cancellation)?;
                workspace.with_bits(plan, customization, |mut root| {
                    crate::scoped_worker::$run(plan, self.workers, self.max_leaves, cancellation, |leaf| root.merge(leaf))?;
                    crate::worker::ensure_live(cancellation)?;
                    Ok(operation(root))
                })?
            }
        }
    };
}
scope!(
    with128,
    with128_bits,
    ParallelHash128Plan,
    ParallelHash128CollectorWorkspace,
    ParallelHash128Collector,
    run128
);
scope!(
    with256,
    with256_bits,
    ParallelHash256Plan,
    ParallelHash256CollectorWorkspace,
    ParallelHash256Collector,
    run256
);
