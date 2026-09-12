//! Operational capabilities cannot cross threads, be cloned or forge reports.
//! ```compile_fail
//! fn send<T: Send>() {}
//! send::<brynja_legacy_sha1::execution::Executor>();
//! ```
//! ```compile_fail
//! fn sync<T: Sync>() {}
//! sync::<brynja_legacy_sha1::execution::Executor>();
//! ```
//! ```compile_fail
//! fn clone<T: Clone>() {}
//! clone::<brynja_legacy_sha1::execution::Authority>();
//! ```
//! ```compile_fail
//! fn debug<T: core::fmt::Debug>() {}
//! debug::<brynja_legacy_sha1::execution::Stream<'static>>();
//! ```
//! ```compile_fail
//! fn hardened<T: brynja_legacy_sha1::HardenedSha1State>() {}
//! hardened::<brynja_legacy_sha1::execution::Stream<'static>>();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::execution::{Executor, PublicData};
//! let state = { let owner = Executor::portable(); owner.start(PublicData::acknowledge()).unwrap() };
//! state.finalize();
//! ```
//! ```compile_fail
//! use brynja_legacy_sha1::execution::{Executor, PublicData};
//! let owner = Executor::portable();
//! let state = owner.start(PublicData::acknowledge()).unwrap();
//! state.finalize(); state.finalize();
//! ```
