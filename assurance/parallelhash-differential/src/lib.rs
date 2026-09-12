//! Compile and execute the crate README examples with their stated opt-in APIs.

#[cfg(feature = "execution")]
#[doc = include_str!("../../../crates/brynja-hash-parallel/README.md")]
pub struct LeafReadme;

#[cfg(feature = "execution")]
#[doc = include_str!("../../../crates/brynja-hash-parallel-std/README.md")]
pub struct ThreadedReadme;
