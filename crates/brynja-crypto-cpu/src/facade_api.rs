//! CPU surface forwarded by the crypto facade. The raw GHASH kernel handle
//! is intentionally not forwarded, even when Cargo unifies CPU features.
#[cfg(feature = "aes-static-execution")]
pub use crate::aes;
#[cfg(feature = "hardened-execution")]
pub use crate::hardened_execution;
#[cfg(feature = "keccak-batch")]
pub use crate::keccak_batch;
#[cfg(feature = "keccak-hardened-batch")]
pub use crate::keccak_hardened_batch;
#[cfg(feature = "runtime-execution")]
pub use crate::runtime_execution;
#[cfg(feature = "sha256-batch")]
pub use crate::sha256_batch;
#[cfg(feature = "sha256-hardened-batch")]
pub use crate::sha256_hardened_batch;
#[cfg(feature = "sha512-batch")]
pub use crate::sha512_batch;
#[cfg(feature = "sha512-hardened-batch")]
pub use crate::sha512_hardened_batch;
#[cfg(feature = "static-execution")]
pub use crate::static_execution;
pub use crate::{
    ADMITTED_BACKEND_COUNT, BOUNDARY_MILESTONE, IMPLEMENTED, IMPLEMENTED_BACKEND_COUNT,
    IMPLEMENTED_KECCAK_BACKEND_COUNT, IMPLEMENTED_SHA256_BACKEND_COUNT,
    IMPLEMENTED_SHA512_BACKEND_COUNT, KeccakBackend, KeccakBackendError, KeccakBackendHealth,
    KeccakBackendReport, KeccakBackendSession, Sha256Backend, Sha256BackendError,
    Sha256BackendHealth, Sha256BackendReport, Sha256BackendSession, Sha512Backend,
    Sha512BackendError, Sha512BackendHealth, Sha512BackendReport, Sha512BackendSession,
};
