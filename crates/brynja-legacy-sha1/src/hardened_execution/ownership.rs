//! Hardened authority and state cannot cross threads, be duplicated or formatted.
//!
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Executor;
//! fn need<T: Send>() {} need::<Executor>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Executor;
//! fn need<T: Sync>() {} need::<Executor>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Executor;
//! fn need<T: Copy>() {} need::<Executor>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Executor;
//! fn need<T: Clone>() {} need::<Executor>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Executor;
//! fn need<T: core::fmt::Debug>() {} need::<Executor>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Authority;
//! fn need<T: Send>() {} need::<Authority>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Authority;
//! fn need<T: Sync>() {} need::<Authority>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Authority;
//! fn need<T: Copy>() {} need::<Authority>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Authority;
//! fn need<T: Clone>() {} need::<Authority>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Authority;
//! fn need<T: core::fmt::Debug>() {} need::<Authority>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Stream;
//! fn need<T: Send>() {} need::<Stream<'static>>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Stream;
//! fn need<T: Sync>() {} need::<Stream<'static>>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Stream;
//! fn need<T: Copy>() {} need::<Stream<'static>>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Stream;
//! fn need<T: Clone>() {} need::<Stream<'static>>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::Stream;
//! fn need<T: core::fmt::Debug>() {} need::<Stream<'static>>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::HardenedSha1State;
//! struct Unreviewed;
//! impl HardenedSha1State for Unreviewed {}
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::hardened_execution::{Executor, Error};
//! fn used(owner: &Executor) -> Result<(), Error> {
//!     let mut state = owner.start()?;
//!     let mut bytes = [0; 20];
//!     drop(state.finalize_secret(&mut bytes)?);
//!     state.update(b"reuse")
//! }
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::{execution, hardened_execution};
//! fn convert(authority: execution::Authority) {
//!     let _ = hardened_execution::Executor::with_authority(authority);
//! }
