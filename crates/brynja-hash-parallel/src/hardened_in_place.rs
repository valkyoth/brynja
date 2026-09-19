//! Scoped portable ParallelHash storage. Empty workspace construction precedes
//! secret input; state handles only borrow the root sponge, metadata and block.
//! The positive block-buffer length is the SP 800-185 parameter B. Scope exit
//! clears the full block and owned metadata even after forgotten handles or
//! recoverable unwind. Caller input, abort, registers, spills and compiler copies
//! are outside this owned-memory guarantee. Existing by-value APIs are unchanged.
//!
//! ```
//! use brynja_hash_parallel::{ParallelHashError, hardened_in_place::ParallelHash128Workspace};
//! let mut workspace = ParallelHash128Workspace::new();
//! let mut block = [0; 8];
//! let mut output = [0; 32];
//! let secret = workspace.with(&mut block, b"application", |mut state| {
//!     state.update(b"message")?;
//!     state.finalize_secret(&mut output)
//! })??;
//! assert_eq!(block, [0; 8]);
//! drop(secret);
//! assert_eq!(output, [0; 32]);
//! # Ok::<(), ParallelHashError>(())
//! ```

mod backend;
mod core_state;
mod fixed;
pub use fixed::{
    ParallelHash128, ParallelHash128Workspace, ParallelHash256, ParallelHash256Workspace,
};

#[cfg(test)]
mod tests;
