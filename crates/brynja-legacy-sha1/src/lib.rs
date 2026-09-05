//! Legacy, collision-broken SHA-1, implemented in first-party allocation-free Rust.
//!
//! # Security
//! Do not choose SHA-1 for new security designs, signatures, certificates, password
//! hashing or authentication. A raw digest is not a MAC. This crate supplies a
//! historical primitive, not permission to negotiate it in TLS, PKIX or OpenPGP.
//! Later constructions require their own explicit legacy admission.
//!
//! Ordinary APIs release public digests. Use [`HardenedSha1`] for confidential
//! input: its output requires explicit declassification or typed secret ownership.
//! Both states clear their owned storage on normal destruction. Compiler-created
//! copies, registers, spills, caches, caller copies, abort and `mem::forget` remain
//! outside that guarantee. No independent cryptographic review or FIPS validation.
//!
//! ```
//! use brynja_legacy_sha1::{Sha1, sha1};
//! let mut state = Sha1::new();
//! state.update(b"a")?;
//! state.update(b"bc")?;
//! assert_eq!(state.finalize(), sha1(b"abc")?);
//! # Ok::<(), brynja_legacy_sha1::Sha1Error>(())
//! ```

#![no_std]

mod compress;
mod engine;
mod hardened;
mod ordinary;
mod output;
mod owner;

pub use brynja_hash_core::{BitString, BitStringError};
pub use hardened::{HardenedSha1, HardenedSha1State};
pub use ordinary::{Sha1, sha1, sha1_bits};
pub use output::{PublicDeclassification, Sha1Error};

/// Width of a SHA-1 digest, in bytes (160 bits).
pub const DIGEST_BYTES: usize = 20;
/// SHA-1 compression block width, in bytes.
pub const BLOCK_BYTES: usize = 64;
/// Largest accepted bit length; SHA-1 requires a message shorter than 2^64 bits.
pub const MAX_MESSAGE_BITS: u64 = u64::MAX;
/// Largest accepted complete-byte message length.
pub const MAX_MESSAGE_BYTES: u64 = u64::MAX / 8;
