//! Compatibility exports for incremental GHASH over pre-framed blocks.
//! GHASH does not pad, encode lengths, or apply a tag mask. Never publish its
//! secret result as an authentication tag. The portable constructor stays
//! portable; the opt-in native routes are not timing-qualified.
#[cfg(feature = "ghash-runtime-execution")]
pub use brynja_universal_hash_ghash::ghash::{Backend, Mode};
#[cfg(feature = "hazmat-ghash")]
pub use brynja_universal_hash_ghash::ghash::{Error, Ghash, SecretHash};
