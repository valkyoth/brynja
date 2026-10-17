//! Curated tuplehash facade. Leaf-only integration and conformance exports are excluded.
//!
//! Reexported types retain their inherent leaf methods; this is not a sandbox
//! against an application explicitly enabling a leaf's test-only features.

pub use brynja_hash_tuple::{
    HardenedTupleHash128, HardenedTupleHash256, HardenedTupleHashXof128,
    HardenedTupleHashXof128Reader, HardenedTupleHashXof256, HardenedTupleHashXof256Reader,
    TupleHash128, TupleHash256, TupleHashError, TupleHashPublicDeclassification,
    TupleHashSecretOutput, TupleHashXof128, TupleHashXof128Reader, TupleHashXof256,
    TupleHashXof256Reader, tuple_hash_xof128, tuple_hash_xof128_bits, tuple_hash_xof256,
    tuple_hash_xof256_bits, tuple_hash128, tuple_hash128_bits, tuple_hash256, tuple_hash256_bits,
};

#[cfg(any(
    feature = "tuplehash-hardened-execution",
    feature = "tuplehash-runtime-execution"
))]
pub use brynja_hash_tuple::execution;
pub use brynja_hash_tuple::{Fips202BitString, Fips202BitsError, Fips202Output, TupleItemWriter};
