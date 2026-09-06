//! Legacy, collision- and chosen-prefix-broken MD5, implemented in first-party allocation-free Rust.
//!
//! # Security
//! Do not choose MD5 for new security designs, signatures, certificates, password
//! hashing or authentication. A raw digest is not a MAC. This crate supplies a
//! historical primitive, not permission to negotiate it in TLS, PKIX or OpenPGP.
//! Later constructions require their own explicit legacy admission.
//!
//! Ordinary APIs release public digests. Use [`HardenedMd5`] for confidential
//! input: its output requires explicit declassification or typed secret ownership.
//! Both states clear their owned storage on normal destruction. Compiler-created
//! copies, registers, spills, caches, caller copies, abort and `mem::forget` remain
//! outside that guarantee. No independent cryptographic review or FIPS validation.
//!
//! ```
//! use brynja_legacy_md5::{Md5, md5};
//! let mut state = Md5::new();
//! state.update(b"a")?;
//! state.update(b"bc")?;
//! assert_eq!(state.finalize(), md5(b"abc")?);
//! # Ok::<(), brynja_legacy_md5::Md5Error>(())
//! ```

#![no_std]

mod compress;
mod engine;
mod hardened;
mod ordinary;
mod output;
mod owner;

pub use brynja_hash_core::{BitString, BitStringError};
pub use hardened::{HardenedMd5, HardenedMd5State};
pub use ordinary::{Md5, md5, md5_bits};
pub use output::{Md5Error, PublicDeclassification};

/// Width of an MD5 digest, in bytes (128 bits).
pub const DIGEST_BYTES: usize = 16;
/// MD5 compression block width, in bytes.
pub const BLOCK_BYTES: usize = 64;
/// Largest accepted bit length; this API checks a 128-bit counter, not an RFC length bound.
pub const MAX_MESSAGE_BITS: u128 = u128::MAX;
/// Largest accepted complete-byte message length.
pub const MAX_MESSAGE_BYTES: u128 = u128::MAX / 8;
