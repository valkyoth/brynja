//! Scoped fixed TupleHash over an explicitly supplied hardened Keccak session.
//!
//! Storage is borrowed before customization/items. Reuse checks the same
//! authority; failure never falls back or revives quarantine. Public output uses
//! 168 bytes of built-in transactional staging, or caller scratch supplied to
//! `with_scratch`/`with_bits_and_scratch`. Scratch clears on every scope exit.
//! Secret output is not limited by staging width. Admission failure skips the
//! callback and cannot clear destinations it has not received.
//! Outer cleanup covers forgotten handles and recoverable unwind, not abort,
//! caller input, registers, spills or compiler copies. No FIPS claim is made.
//!
//! ```
//! use brynja_hash_tuple::{TupleHashError, TupleHashSecretOutput,
//!     execution::{KeccakSession, in_place::TupleHash128Workspace}};
//! fn digest<'out>(session: KeccakSession<'_>, item: &[u8], output: &'out mut [u8])
//!     -> Result<TupleHashSecretOutput<'out>, TupleHashError> {
//!     let mut workspace = TupleHash128Workspace::new(session)?;
//!     workspace.with(b"application", |mut tuple| {
//!         tuple.push_item(item)?;
//!         tuple.finalize_secret(output)
//!     })?
//! }
//! ```

use super::core_state::{Core, Guard, Metadata, byte_valid, bytes_input};
use crate::{
    Fips202BitString, TupleHashError, TupleHashPublicDeclassification, TupleHashSecretOutput,
};
use brynja_hash_sha3::hardened_execution::{KeccakSession, Report, in_place as cshake};

mod backend;
mod fixed;
pub use fixed::{
    TupleHash128, TupleHash128ItemWriter, TupleHash128Workspace, TupleHash256,
    TupleHash256ItemWriter, TupleHash256Workspace,
};

struct Scratch<'a>(&'a mut [u8]);
impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scoped_accelerated_tuple_scratch_clears_on_exit() {
        let mut bytes = [0xa5; 200];
        drop(Scratch(&mut bytes));
        assert_eq!(bytes, [0; 200]);
    }
}
