//! Scoped fixed-output ParallelHash with explicitly supplied hardened root and
//! leaf Keccak sessions. Both may borrow the same authority; each remains checked
//! independently. No supplied session ever falls back to portable work.
//!
//! Empty workspace construction precedes secret input. Each scope borrows the
//! root/leaf sponges, CPU scratch, metadata, caller block and public output stage.
//! Public output uses 168 bytes of built-in staging, or caller scratch passed to
//! `with_scratch`/`with_bits_and_scratch`. Secret output is not stage-width limited.
//! Setup failure skips the callback and cannot clear captured output destinations.
//! Block and supplied scratch clear on every scope exit. Forgotten handles and
//! recoverable unwind are covered, not abort, caller input, registers or spills.
//! Scoped accelerated XOF and scheduled/threaded APIs remain separate follow-up work.
//!
//! ```
//! use brynja_hash_parallel::{ParallelHashError, ParallelHashSecretOutput,
//!     execution::{KeccakSession, in_place::ParallelHash128Workspace}};
//! fn digest<'out>(root: KeccakSession<'_>, leaf: KeccakSession<'_>, input: &[u8],
//!     output: &'out mut [u8]) -> Result<ParallelHashSecretOutput<'out>, ParallelHashError> {
//!     let mut workspace = ParallelHash128Workspace::new(root, leaf)?;
//!     workspace.with(&mut [0;64], b"application", |mut state| {
//!         state.update(input)?;
//!         state.finalize_secret(output)
//!     })?
//! }
//! ```

use super::core_state::{Block, Core, Guard, Metadata};
use crate::{
    Fips202BitString, ParallelHashError, ParallelHashPublicDeclassification,
    ParallelHashSecretOutput, core_state::byte_string,
};
use brynja_hash_sha3::hardened_execution::{KeccakSession, Report, in_place as api};

mod backend;
mod fixed;
pub use fixed::{
    ParallelHash128, ParallelHash128Workspace, ParallelHash256, ParallelHash256Workspace,
};
