//! Scoped fixed KMAC using an explicitly supplied hardened Keccak session.
//!
//! Caller-owned storage is borrowed before accepting keys. The exact authority
//! is retained across reuse: a revoked session never falls back or revives.
//! Public tags use 168 bytes of built-in staging, or caller scratch supplied to
//! `with_scratch`/`with_bits_and_scratch`. Scratch is cleared on every exit;
//! setup failure skips the callback and cannot clear destinations it never sees.
//! Secret output and verification are not limited by the public staging width.
//! Scope cleanup covers forgotten handles and recoverable unwind, not abort,
//! compiler-created copies, registers/spills or caller input. No FIPS claim.
//!
//! ```
//! use brynja_mac_kmac::{KmacError, KmacSecretOutput, execution::{KeccakSession, in_place::Kmac256Workspace}};
//! fn authenticate<'out>(session: KeccakSession<'_>, key: &[u8], message: &[u8],
//!     output: &'out mut [u8]) -> Result<KmacSecretOutput<'out>, KmacError> {
//!     let mut workspace = Kmac256Workspace::new(session)?;
//!     workspace.with(key, b"application domain", |mut state| {
//!         state.update(message)?;
//!         state.finalize_secret(output)
//!     })?
//! }
//! ```

use super::core_state::{Core, Guard, Metadata, byte_valid, bytes};
use crate::{
    Fips202BitString, KmacError, KmacKeyPolicy, KmacSecretOutput, KmacServiceStatus, KmacTag,
    KmacVerification,
};
use brynja_hash_sha3::hardened_execution::{KeccakSession, Report, in_place as cshake};

mod backend;
mod fixed;
pub use fixed::{Kmac128, Kmac128Workspace, Kmac256, Kmac256Workspace};

struct Scratch<'a>(&'a mut [u8]);
impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(self.0);
    }
}

#[cfg(test)]
mod tests;
