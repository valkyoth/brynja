//! Strict-only protected modern cryptography. Not military/FIPS certification.
//!
//! Depending on this facade always enables the protected session implementations,
//! even with default features disabled. No ordinary, legacy, raw CPU authority,
//! generic callback, or unprotected workspace API is exported. This does not
//! prohibit applications from adding other dependencies; deployment review must
//! keep secret processing on these APIs and protect original caller storage.
//!
//! Every constructor acquires protected resources or returns an error. Supported
//! native targets are GNU/Linux x86-64 and little-endian AArch64 (Linux 4.4,
//! glibc 2.27 or later). Other targets and verification models compile for
//! portability checks but constructors reject: no successful weaker fallback.
//! Native qualification and independent review remain pending.
//!
//! Scalar sessions stay scalar. `acceleration` exposes the separate compiled
//! session constructors; batch execution also requires an explicit route. The
//! caller must establish the full CPU/OS deployment guarantee before selecting
//! a compiled kernel. This is not runtime migration detection or affinity.
//!
//! Locking/exclusion/clearing cover owned regions and joined worker stacks, not
//! original inputs, privileged snapshots, hibernation, arbitrary asynchronous
//! register capture, fatal abort or application-created copies. Instrumented
//! sanitizer builds are diagnostics only, not deployment-qualified protection.
//! Construct a bounded pool of sessions once and reuse them, rather than pinning
//! new mappings for every request. Resource limits are not a process-wide quota.
//!
//! ```no_run
//! use brynja_strict::sha2::{Algorithm, Error, Limits, Session};
//! let mut session = Session::new(Algorithm::Sha256, Limits {
//!     stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
//!     max_output_mapping_bytes: 65536, max_message_bits: 8192, max_chunks: 16,
//! })?;
//! for message in [b"first".as_slice(), b"second".as_slice()] {
//!     let digest = session.hash(message)?;
//!     assert_eq!(digest.expose().len(), 32);
//!     drop(digest); // clears the loan; reuse does not acquire another session
//! }
//! # Ok::<(), Error>(())
//! ```
//!
//! The weaker facade and low-level resources are intentionally not re-exported:
//! ```compile_fail
//! use brynja_strict::crypto;
//! ```
//! ```compile_fail
//! use brynja_strict::protected_memory;
//! ```
//! ```compile_fail
//! use brynja_strict::execution::Authority;
//! ```
//! ```compile_fail
//! use brynja_strict::sha2::Sha256;
//! ```
//! ```compile_fail
//! use brynja_strict::sha3::HardenedSha3_256;
//! ```
//! ```compile_fail
//! use brynja_strict::parallelhash::ParallelHashExecutor;
//! ```
//! ```compile_fail
//! use brynja_strict::legacy;
//! ```
#![no_std]

pub use brynja_crypto_cpu_std::strict_batch as batch;
pub use brynja_crypto_cpu_std::strict_kmac as kmac;
pub use brynja_crypto_cpu_std::strict_sha2 as sha2;
pub use brynja_crypto_cpu_std::strict_sha3 as sha3;
pub use brynja_crypto_cpu_std::strict_tuplehash as tuplehash;
pub use brynja_hash_parallel_std::strict_execution as parallelhash;

#[cfg(test)]
mod tests;
