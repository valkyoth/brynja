//! Scoped portable KMAC128/KMAC256, with caller-owned sponge and verification storage.
//!
//! Construction accepts no secrets. `with` borrows the workspace before absorbing
//! a key; its outer result covers setup and its inner value is the callback result.
//! Setup failure skips the callback and cannot clear captured destinations it has
//! not received. Finalization accepts public tags or typed secret destinations.
//! Scope exit also clears forgotten handles and recoverable unwind. Caller input,
//! compiler copies, registers/spills and abort are outside the cleanup claim.
//! Existing by-value/execution APIs remain unchanged; these scopes are portable.
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

mod backend;
mod core_state;
mod fixed;
pub use fixed::{Kmac128, Kmac128Workspace, Kmac256, Kmac256Workspace};

#[cfg(test)]
mod tests;
