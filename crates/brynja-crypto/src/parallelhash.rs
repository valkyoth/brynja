//! Curated parallelhash facade. Leaf-only integration and conformance exports are excluded.
//!
//! Reexported types retain their inherent leaf methods; this is not a sandbox
//! against an application explicitly enabling a leaf's test-only features.

pub use brynja_hash_parallel::{
    HardenedParallelHash128, HardenedParallelHash256, HardenedParallelHashXof128,
    HardenedParallelHashXof128Reader, HardenedParallelHashXof256, HardenedParallelHashXof256Reader,
    ParallelHash128, ParallelHash128Collector, ParallelHash128LeafJob, ParallelHash128LeafResult,
    ParallelHash128Plan, ParallelHash128ScheduledXofReader, ParallelHash256,
    ParallelHash256Collector, ParallelHash256LeafJob, ParallelHash256LeafResult,
    ParallelHash256Plan, ParallelHash256ScheduledXofReader, ParallelHashError,
    ParallelHashPublicDeclassification, ParallelHashSecretOutput, ParallelHashXof128,
    ParallelHashXof128Reader, ParallelHashXof256, ParallelHashXof256Reader, parallel_hash_xof128,
    parallel_hash_xof256, parallel_hash128, parallel_hash256,
};

#[cfg(any(
    feature = "parallelhash-hardened-execution",
    feature = "parallelhash-runtime-execution",
    feature = "parallelhash-hardened-batch"
))]
pub use brynja_hash_parallel::execution;
pub use brynja_hash_parallel::{Fips202BitString, Fips202BitsError, Fips202Output};
