//! Incremental GHASH (NIST SP 800-38D §6.4) over an already-framed sequence
//! of 16-byte blocks. Updates may split blocks at any byte. There is **no**
//! implicit padding, length encoding, tag mask, or authentication decision.
//! Never publish the raw result as a tag: it can reveal the hash subkey.
//! All 128-bit field elements are accepted: a zero subkey produces zero for
//! every input. Do not substitute a zero buffer for failed key derivation.
//!
//! The caller supplies a byte budget, a borrowed subkey in NIST wire order,
//! and distinct workspace and output storage. No allocation or AES backend
//! is needed. Drop clears the borrowed workspace/output, not the caller's key,
//! copies, registers or spills; abort and forgotten owners bypass Drop.
//! Development interface: no machine-code timing qualification is claimed.
//!
//! ```
//! use brynja_crypto::ghash::{Error, Ghash};
//! # fn example() -> Result<(), Error> {
//! // Example subkey and pre-framed block, not a GCM implementation.
//! let h = [0x37; 16];
//! let (mut workspace, mut output) = ([0; 16], [0; 16]);
//! let mut hash = Ghash::new(&h, &mut workspace, 16);
//! hash.update(&[0x11; 5])?;
//! hash.update(&[0x22; 11])?;
//! let intermediate = hash.finish(&mut output)?;
//! // Use intermediate.expose() only inside the higher-level construction.
//! intermediate.clear();
//! assert_eq!(output, [0; 16]);
//! # Ok(()) }
//! # example().unwrap();
//! ```
//!
//! The output cannot alias the live workspace:
//! ```compile_fail,E0499
//! use brynja_crypto::ghash::Ghash;
//! let mut workspace = [0; 16];
//! let hash = Ghash::new(&[0; 16], &mut workspace, 0);
//! let intermediate = hash.finish(&mut workspace);
//! ```

#![forbid(unsafe_code)]

mod field;

use brynja_core::{
    OwnedSecretRegion, SecretMemoryError, SecretRegionInitialization, clear_owned_region,
};
use core::marker::PhantomData;

/// A public length or storage error; contains no secret bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The entire update would exceed the caller's remaining byte budget.
    LimitExceeded,
    /// The input did not end on a block boundary.
    PartialBlock,
    /// The output region could not be fully initialized.
    Storage(SecretMemoryError),
}

/// One local incremental computation; neither cloneable nor resettable.
#[must_use]
pub struct Ghash<'a> {
    h: &'a [u8; 16],
    state: &'a mut [u8; 16],
    used: usize,
    remaining: u64,
    local: PhantomData<*mut ()>,
}

impl<'a> Ghash<'a> {
    /// Starts from zero, clearing the workspace. The budget counts all bytes
    /// supplied, including any framing supplied by a higher-level protocol.
    pub fn new(h: &'a [u8; 16], workspace: &'a mut [u8; 16], max_bytes: u64) -> Self {
        let _ = clear_owned_region(workspace);
        Self {
            h,
            state: workspace,
            used: 0,
            remaining: max_bytes,
            local: PhantomData,
        }
    }

    /// Appends a chunk. An over-budget chunk leaves the entire context unchanged.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let len = u64::try_from(bytes.len()).map_err(|_| Error::LimitExceeded)?;
        let remaining = self
            .remaining
            .checked_sub(len)
            .ok_or(Error::LimitExceeded)?;
        let mut input = bytes.iter();
        while input.len() != 0 {
            // Between complete blocks the state holds the previous product
            // XOR the available prefix of the next block, in place.
            for (dst, src) in self.state.iter_mut().skip(self.used).zip(&mut input) {
                *dst ^= src;
                self.used = self.used.wrapping_add(1); // at most 16
            }
            if self.used == 16 {
                *self.state = field::multiply(
                    u128::from_be_bytes(*self.state),
                    u128::from_be_bytes(*self.h),
                )
                .to_be_bytes();
                self.used = 0;
            }
        }
        self.remaining = remaining;
        Ok(())
    }

    /// Consumes the context and returns the unmasked, secret GHASH result.
    /// Empty input yields zero. A partial final block leaves output unchanged.
    pub fn finish(self, output: &mut [u8; 16]) -> Result<SecretHash<'_>, Error> {
        if self.used != 0 {
            return Err(Error::PartialBlock);
        }
        let mut init = SecretRegionInitialization::begin(output).map_err(Error::Storage)?;
        init.write(self.state).map_err(Error::Storage)?;
        Ok(SecretHash {
            region: init.finish().map_err(Error::Storage)?,
            local: PhantomData,
        })
    }
}

impl Drop for Ghash<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.state);
    }
}

/// A secret intermediate for a construction such as GCM; never a public tag.
#[must_use]
pub struct SecretHash<'a> {
    region: OwnedSecretRegion<'a>,
    local: PhantomData<*mut ()>,
}

impl SecretHash<'_> {
    /// Explicitly borrows the unmasked bytes. The caller must protect any copies.
    pub fn expose(&self) -> &[u8] {
        self.region.expose()
    }

    /// Consumes the result and clears the caller's output immediately.
    pub fn clear(self) {
        let _ = self.region.clear();
    }
}
