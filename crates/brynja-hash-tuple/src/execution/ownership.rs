//! Compiled negative ownership checks (capabilities cannot be transferred or copied).
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::TupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::TupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::TupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::TupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::TupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::TupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::TupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::TupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::TupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::TupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHash256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::TupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof128<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::HardenedTupleHashXof256<'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::Reader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::Reader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::Reader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::Reader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::Reader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::HardenedReader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::HardenedReader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::HardenedReader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::HardenedReader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::HardenedReader<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Send>() {}
//! require::<brynja_hash_tuple::execution::TupleItemWriter<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Sync>() {}
//! require::<brynja_hash_tuple::execution::TupleItemWriter<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Copy>() {}
//! require::<brynja_hash_tuple::execution::TupleItemWriter<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: Clone>() {}
//! require::<brynja_hash_tuple::execution::TupleItemWriter<'static, 'static>>();
//! ```
//!
//! ```compile_fail,E0277
//! fn require<T: core::fmt::Debug>() {}
//! require::<brynja_hash_tuple::execution::TupleItemWriter<'static, 'static>>();
//! ```
