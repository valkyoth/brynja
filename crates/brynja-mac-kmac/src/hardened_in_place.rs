//! Scoped portable KMAC/KMACXOF128/256 with caller-owned sponge and metadata storage.
//!
//! Construction accepts no secrets. `with` borrows the workspace before absorbing
//! a key; its outer result covers setup and its inner value is the callback result.
//! Setup failure skips the callback and cannot clear captured destinations it has
//! not received. Finalization accepts public tags or typed secret destinations.
//! Scope exit also clears forgotten handles and recoverable unwind. Caller input,
//! compiler copies, registers/spills and abort are outside the cleanup claim.
//! Existing by-value/execution APIs remain unchanged; these top-level scopes are
//! portable. The default-off `accelerated` module is also exposed as
//! `execution::in_place` and requires an explicit hardened Keccak session.
//! KMACXOF readers transfer only the exclusive borrow, require explicit public
//! declassification, and terminate on errors. Final-bit reads consume the reader.
//! There are no accumulated-message/output length or preflight queries.
//!
//! ```
//! use brynja_mac_kmac::{KmacError, hardened_in_place::Kmac128Workspace};
//! let mut workspace = Kmac128Workspace::new();
//! let mut bytes = [0; 32];
//! let secret = workspace.with(&[0x42; 16], b"example", |mut state| {
//!     state.update(b"message")?;
//!     state.finalize_secret(&mut bytes)
//! })??;
//! assert_eq!(secret.expose().len(), 32);
//! drop(secret);
//! assert_eq!(bytes, [0; 32]);
//! # Ok::<(), KmacError>(())
//! ```
//!
//! Incremental XOF reads retain the workspace borrow; secret output has its own
//! destination lifetime and can be returned from the scope:
//!
//! ```
//! use brynja_mac_kmac::{KmacError, KmacPublicDeclassification, hardened_in_place::KmacXof256Workspace};
//! let mut workspace = KmacXof256Workspace::new();
//! let mut public = [0; 16];
//! let mut output = [0; 33];
//! let secret = workspace.with(&[0x42; 32], b"example only", |mut state| {
//!     state.update(b"message")?;
//!     let mut reader = state.finalize_xof()?;
//!     reader.squeeze_public(&mut public, KmacPublicDeclassification::acknowledge())?;
//!     reader.squeeze_final_bits_secret(&mut output, 5)
//! })??;
//! assert_eq!(secret.expose().len(), 33);
//! drop(secret);
//! assert_eq!(output, [0; 33]);
//! # Ok::<(), KmacError>(())
//! ```

#[cfg(feature = "hardened-execution")]
pub mod accelerated;
mod backend;
mod core_state;
mod fixed;
mod reader;
mod xof;
pub use fixed::{Kmac128, Kmac128Workspace, Kmac256, Kmac256Workspace};
pub use xof::{
    KmacXof128, KmacXof128Reader, KmacXof128Workspace, KmacXof256, KmacXof256Reader,
    KmacXof256Workspace,
};

#[cfg(test)]
mod tests;
