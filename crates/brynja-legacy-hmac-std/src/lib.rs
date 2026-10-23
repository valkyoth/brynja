//! Explicit hosted legacy-only HMAC owners; no modern facade or approved service.
//!
//! Features are default-off. `strict-execution` acquires Linux protected worker
//! and output storage before accepting inputs. Unsupported platforms reject;
//! there is no ordinary-memory fallback. Caller input buffers remain caller-owned.
//! This is an initial development implementation, not independent qualification.
//! macOS resident and accelerated owners are still pending; enabling an unrelated
//! hash CPU feature never changes the scalar route implemented here.

#[cfg(feature = "strict-execution")]
pub mod strict_execution;

#[doc = include_str!("../README.md")]
mod readme {}
