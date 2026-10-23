//! Explicit hosted legacy-only HMAC owners; no modern facade or approved service.
//!
//! Features are default-off. `strict-execution` acquires Linux protected worker
//! and output storage before accepting inputs. Unsupported platforms reject;
//! there is no ordinary-memory fallback. Caller input buffers remain caller-owned.
//! This is an initial development implementation, not independent qualification.
//! The separate `macos-resident` profile has no core-dump exclusion guarantee.
//! Hosted accelerated owners remain pending; unrelated hash CPU features never
//! change either scalar route implemented here.

#[cfg(feature = "strict-execution")]
pub mod strict_execution;

#[cfg(feature = "macos-resident")]
pub mod macos_resident;

#[doc = include_str!("../README.md")]
mod readme {}
