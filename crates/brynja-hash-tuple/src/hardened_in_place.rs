//! Scoped portable fixed TupleHash128/256 with caller-owned storage.
//!
//! Workspaces are constructed empty, then exclusively borrowed before accepting
//! customization or items. Finalization consumes a borrowed handle, not a secret
//! owner. An item writer must consume exactly its declared bit length and finish;
//! abandoning or forgetting it cannot authorize parent finalization. Errors are
//! terminal. No accumulated-length, item-count or preflight query is exposed.
//! Scope exit clears owned storage even after forgotten handles or recoverable
//! unwind. Caller inputs, compiler copies, registers, spills and panic-abort are
//! outside this owned-memory claim. These APIs use portable execution only.
//!
//! The outer result covers setup; the callback's own result is the inner value.
//! Secret output borrows a separate destination and can outlive the scope:
//!
//! ```
//! use brynja_hash_tuple::{TupleHashError, hardened_in_place::TupleHash128Workspace};
//! let mut workspace = TupleHash128Workspace::new();
//! let mut output = [0; 32];
//! let secret = workspace.with(b"example", |mut tuple| {
//!     tuple.push_item(b"first item")?;
//!     let mut item = tuple.begin_item(40)?;
//!     item.update(b"he")?;
//!     item.update(b"llo")?;
//!     item.finish()?;
//!     tuple.finalize_secret(&mut output)
//! })??;
//! assert_eq!(secret.expose().len(), 32);
//! drop(secret);
//! assert_eq!(output, [0; 32]);
//! # Ok::<(), TupleHashError>(())
//! ```

mod backend;
mod core_state;
mod fixed;
pub use fixed::{
    TupleHash128, TupleHash128ItemWriter, TupleHash128Workspace, TupleHash256,
    TupleHash256ItemWriter, TupleHash256Workspace,
};

#[cfg(test)]
mod tests;
