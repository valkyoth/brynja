//! Unfinished hardened root/readers cannot transfer execution authority or copy secrets.
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Stream;
//! fn require<T: Send>() {}
//! require::<Stream<'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Stream;
//! fn require<T: Sync>() {}
//! require::<Stream<'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Stream;
//! fn require<T: Clone>() {}
//! require::<Stream<'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Stream;
//! fn require<T: Copy>() {}
//! require::<Stream<'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Stream;
//! fn require<T: core::fmt::Debug>() {}
//! require::<Stream<'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::StreamReader;
//! fn require<T: Send>() {}
//! require::<StreamReader<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::StreamReader;
//! fn require<T: Sync>() {}
//! require::<StreamReader<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::StreamReader;
//! fn require<T: Clone>() {}
//! require::<StreamReader<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::StreamReader;
//! fn require<T: Copy>() {}
//! require::<StreamReader<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::StreamReader;
//! fn require<T: core::fmt::Debug>() {}
//! require::<StreamReader<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Collector;
//! fn require<T: Send>() {}
//! require::<Collector<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Collector;
//! fn require<T: Sync>() {}
//! require::<Collector<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Collector;
//! fn require<T: Clone>() {}
//! require::<Collector<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Collector;
//! fn require<T: Copy>() {}
//! require::<Collector<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Collector;
//! fn require<T: core::fmt::Debug>() {}
//! require::<Collector<'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Reader;
//! fn require<T: Send>() {}
//! require::<Reader<'static, 'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Reader;
//! fn require<T: Sync>() {}
//! require::<Reader<'static, 'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Reader;
//! fn require<T: Clone>() {}
//! require::<Reader<'static, 'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Reader;
//! fn require<T: Copy>() {}
//! require::<Reader<'static, 'static, 'static, 'static>>();
//! ```
//!
//! ```compile_fail
//! use brynja_hash_parallel::execution::Reader;
//! fn require<T: core::fmt::Debug>() {}
//! require::<Reader<'static, 'static, 'static, 'static>>();
//! ```
