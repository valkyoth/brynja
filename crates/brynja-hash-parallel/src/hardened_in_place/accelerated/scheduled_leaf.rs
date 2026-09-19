use super::{KeccakSession, Report, api};
use crate::ParallelHashError as Error;
use brynja_core::clear_owned_region;

macro_rules! leaf {
    ($workspace:ident, $storage:ident, $job:ident, $result:ident, $width:expr) => {
        /// Empty accelerated SHAKE storage for one exact-plan leaf at a time.
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::execution::in_place::", stringify!($workspace), "<'static>>();\n```")]
        pub struct $workspace<'authority> { sponge: api::$storage<'authority> }
        impl<'authority> $workspace<'authority> {
            /// Binds one supplied session before accepting input; never falls back.
            pub fn new(session: KeccakSession<'authority>) -> Result<Self, Error> {
                Ok(Self { sponge: api::$storage::new(session)? })
            }
            /// Non-authorizing leaf route/health observation.
            #[must_use]
            pub fn report(&self) -> Report { self.sponge.report() }
            /// Executes the consumed job into exactly the required secret-output
            /// width. All failures clear the supplied output, including revoked
            /// authority before scope entry. The result retains exact plan/index
            /// provenance, not a live leaf-authority lease; it may outlive this
            /// workspace, and later leaf revocation does not invalidate its bytes.
            pub fn execute<'plan, 'input, 'out>(&mut self, job: crate::$job<'plan, 'input>, output: &'out mut [u8; $width]) -> Result<crate::$result<'plan, 'out>, Error> {
                let _ = clear_owned_region(output);
                job.execute_with(output, |input, output| {
                    self.sponge.with(|state| state.finalize_bits_xof(input)?.squeeze_secret(output))?.map_err(Error::from)
                })
            }
        }
    };
}
leaf!(
    ParallelHash128LeafWorkspace,
    Shake128Workspace,
    ParallelHash128LeafJob,
    ParallelHash128LeafResult,
    32
);
leaf!(
    ParallelHash256LeafWorkspace,
    Shake256Workspace,
    ParallelHash256LeafJob,
    ParallelHash256LeafResult,
    64
);
