//! Development-only public-API probes. Passing tests do NOT qualify cleanup.
//!
//! Each C boundary includes this wrapper and the selected public implementation.
//! The wrapper never exposes the digest and drops its secret output before return.
//! Only fixed, synthetic, non-confidential test input may be supplied to observers.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "accelerated")]
pub mod accelerated;
#[cfg(feature = "higher")]
pub mod higher;
pub mod scoped;

/// Explicit diagnostic identity; neither profile qualifies register erasure.
pub const API_PROFILE: &str = if cfg!(feature = "accelerated") {
    "accelerated"
} else if cfg!(feature = "higher") {
    "higher"
} else if cfg!(feature = "scoped") {
    "scoped"
} else {
    "movable"
};

/// Public length, caller-owned input/output, and a non-secret status result.
pub type Probe = extern "C" fn(&[u8; 256], &mut [u8; 64], usize) -> u8;

macro_rules! probe {
    ($name:ident, $state:path, $width:literal) => {
        /// Return 0 on success, 1 on hashing failure, 2 on invalid fixture length.
        /// Only the selected output prefix is owned/cleared by the public API.
        #[inline(never)]
        pub extern "C" fn $name(input: &[u8; 256], output: &mut [u8; 64], length: usize) -> u8 {
            let Some(input) = input.get(..length) else {
                return 2;
            };
            let mut state = <$state>::new();
            if state.update(input).is_err() {
                return 1;
            }
            match state.finalize_secret(&mut output[..$width]) {
                Ok(secret) => {
                    drop(secret);
                    0
                }
                Err(_) => 1,
            }
        }
    };
}

probe!(sha256, brynja_hash_sha2::HardenedSha256, 32);
probe!(sha512, brynja_hash_sha2::HardenedSha512, 64);
probe!(sha3, brynja_hash_sha3::HardenedSha3_256, 32);
probe!(sha1, brynja_legacy_sha1::HardenedSha1, 20);
probe!(md5, brynja_legacy_md5::HardenedMd5, 16);

/// Algorithm name, actual public-API call, and owned output width.
#[cfg(not(any(feature = "scoped", feature = "higher")))]
pub const PROBES: [(&str, Probe, usize); 5] = [
    ("sha256", sha256, 32),
    ("sha512", sha512, 64),
    ("sha3", sha3, 32),
    ("sha1", sha1, 20),
    ("md5", md5, 16),
];

#[cfg(feature = "higher")]
pub use higher::PROBES;
#[cfg(all(feature = "scoped", not(feature = "higher")))]
pub use scoped::PROBES;
