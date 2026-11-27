//! Compatibility exports for incremental GHASH over pre-framed blocks.
//! GHASH does not pad, encode lengths, or apply a tag mask. Never publish its
//! secret result as an authentication tag. The portable constructor stays
//! portable; the opt-in native routes are not timing-qualified.
#[cfg(not(feature = "hazmat-ghash"))]
pub(crate) use brynja_universal_hash_ghash::__mode::{Error, Ghash, SecretHash};
#[cfg(all(
    any(feature = "aes-gcm-execution", feature = "gmac-execution"),
    any(
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "windows")
        ),
        all(
            target_arch = "aarch64",
            target_endian = "little",
            any(target_os = "linux", target_os = "macos")
        )
    )
))]
pub(crate) use brynja_universal_hash_ghash::__mode::{PairMultiplier, from_pair};
#[cfg(feature = "ghash-runtime-execution")]
pub use brynja_universal_hash_ghash::ghash::{Backend, Mode};
#[cfg(feature = "hazmat-ghash")]
pub use brynja_universal_hash_ghash::ghash::{Error, Ghash, SecretHash};
