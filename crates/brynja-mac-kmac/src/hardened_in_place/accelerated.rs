//! Scoped KMAC/KMACXOF using an explicitly supplied hardened Keccak session.
//!
//! Caller-owned storage is borrowed before accepting keys. The exact authority
//! is retained across reuse: a revoked session never falls back or revives.
//! Public tags/XOF reads use 168 bytes of built-in staging, or caller scratch supplied to
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
//!
//! XOF finalization transfers the exclusive borrow to a reader, not the secret
//! sponge. Public fragments require explicit declassification; errors terminate
//! the reader, and secret failures clear the destination even after termination.
//!
//! ```
//! use brynja_mac_kmac::{KmacError, KmacSecretOutput, KmacPublicDeclassification,
//!     execution::{KeccakSession, in_place::KmacXof256Workspace}};
//! fn derive<'out>(session: KeccakSession<'_>, key: &[u8], message: &[u8],
//!     prefix: &mut [u8; 16], output: &'out mut [u8; 33]) -> Result<KmacSecretOutput<'out>, KmacError> {
//!     let mut workspace = KmacXof256Workspace::new(session)?;
//!     workspace.with(key, b"application domain", |mut state| {
//!         state.update(message)?;
//!         let mut reader = state.finalize_xof()?;
//!         reader.squeeze_public(prefix, KmacPublicDeclassification::acknowledge())?;
//!         reader.squeeze_final_bits_secret(output, 5)
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
mod xof;
pub use fixed::{Kmac128, Kmac128Workspace, Kmac256, Kmac256Workspace};
pub use xof::{
    KmacXof128, KmacXof128Reader, KmacXof128Workspace, KmacXof256, KmacXof256Reader,
    KmacXof256Workspace,
};

struct Scratch<'a>(&'a mut [u8]);
impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(self.0);
    }
}

#[cfg(test)]
mod tests;
