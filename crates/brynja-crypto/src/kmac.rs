//! Curated kmac facade. Leaf-only integration and conformance exports are excluded.
//!
//! Reexported types retain their inherent leaf methods; this is not a sandbox
//! against an application explicitly enabling a leaf's test-only features.

pub use brynja_mac_kmac::{
    Kmac128, Kmac256, KmacError, KmacKeyPolicy, KmacPublicDeclassification, KmacSecretOutput,
    KmacServiceStatus, KmacTag, KmacTagPolicy, KmacVerification, KmacXof128, KmacXof128Reader,
    KmacXof256, KmacXof256Reader, kmac128, kmac128_bits, kmac256, kmac256_bits, kmacxof128_public,
    kmacxof128_secret, kmacxof256_public, kmacxof256_secret,
};

#[cfg(any(
    feature = "kmac-hardened-execution",
    feature = "kmac-runtime-execution"
))]
pub use brynja_mac_kmac::execution;
pub use brynja_mac_kmac::{Fips202BitString, Fips202BitsError, Fips202Output};
