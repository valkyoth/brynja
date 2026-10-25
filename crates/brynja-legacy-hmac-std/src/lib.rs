//! Explicit hosted legacy-only HMAC owners; no modern facade or approved service.
//!
//! Features are default-off. `strict-execution` acquires Linux protected worker
//! and output storage before accepting inputs. Unsupported platforms reject;
//! there is no ordinary-memory fallback. Caller input buffers remain caller-owned.
//! This is an initial development implementation, not independent qualification.
//! The separate `macos-resident` profile has no core-dump exclusion guarantee.
//! Separate opt-in SHA-1 compiled sessions require matching deployment features;
//! unrelated hash CPU features never change either scalar route implemented here.
//! Separate opt-in MD5 batch owners require a complete AVX2/NEON lane group.

mod verification;
pub use verification::VerificationError;
#[cfg(any(feature = "strict-execution", feature = "macos-resident"))]
mod common;

#[cfg(feature = "strict-execution")]
pub mod strict_execution;

#[cfg(feature = "macos-resident")]
pub mod macos_resident;

#[doc = include_str!("../README.md")]
mod readme {}
