//! Development portable AES-128 block primitive (FIPS 197).
//!
//! No mode, authentication, padding, nonce management, acceleration or implicit
//! algorithm selection. Do not encrypt messages by repeatedly applying this
//! primitive as ECB. Deployment/side-channel qualification is pending.
//! Source arithmetic has fixed work and no secret-indexed tables; this is not
//! a guarantee about every compiler's emitted code or every target's timing.
//!
//! Keys and outputs borrow clearing caller storage. Each operation expands an
//! ephemeral schedule which is cleared on return/error/unwind. Clearing does
//! not cover caller copies, compiler spills/registers, forgotten owners, abort,
//! paging or dumps. The input key/block remain the caller's responsibility.

#![forbid(unsafe_code)]

use brynja_core::{OwnedSecretRegion, SecretRegionInitialization, clear_owned_region};
use core::marker::PhantomData;

mod portable;

/// AES block size, in bytes (all AES variants use this block size).
pub const BLOCK_BYTES: usize = 16;
/// AES-128 key size, in bytes. Other key sizes are not admitted here.
pub const KEY_BYTES: usize = 16;

/// Explicit authority to release one encrypted block as public ciphertext.
/// This does not authenticate it or make raw block encryption a message mode.
#[must_use = "consume this acknowledgement in public encryption"]
pub struct PublicCiphertext {
    _private: (),
}
impl PublicCiphertext {
    /// Acknowledges the caller's decision to release this ciphertext publicly.
    pub const fn acknowledge() -> Self {
        Self { _private: () }
    }
}

/// Value-free secret-storage or internal-invariant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A secret-memory operation or fixed-size invariant failed.
    SecretMemory,
}

impl From<brynja_core::SecretMemoryError> for Error {
    fn from(_: brynja_core::SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

// Populated scratch is never returned by value or made Copy/Clone.
struct Scratch<const N: usize>([u8; N]);
impl<const N: usize> Scratch<N> {
    fn new() -> Self {
        Self([0; N])
    }
}
impl<const N: usize> Drop for Scratch<N> {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
        #[cfg(test)]
        tests::observe_clear(&self.0);
    }
}

/// Caller-backed AES-128 key. Not Copy, Clone, Debug, Send or Sync.
///
/// The expanded schedule is operation-local, not retained by this owner.
/// `clear` consumes the key immediately; ordinary Drop also clears its storage.
///
/// ```
/// use brynja_crypto::aes::{Aes128Key, Error};
/// let input_key = [0x42; 16]; // Example only: obtain real keys securely.
/// let mut key_storage = [0; 16];
/// let key = Aes128Key::new(&input_key, &mut key_storage)?;
/// let mut encrypted = [0; 16];
/// let ciphertext = key.encrypt_block(&[0; 16], &mut encrypted)?;
/// assert_eq!(ciphertext.expose().len(), 16);
/// drop(ciphertext);
/// assert_eq!(encrypted, [0; 16]);
/// key.clear();
/// assert_eq!(key_storage, [0; 16]);
/// # Ok::<(), Error>(())
/// ```
///
/// ```compile_fail
/// use brynja_crypto::aes::Aes128Key;
/// let mut storage = [0; 16];
/// let _ = Aes128Key::new(&[0; 24], &mut storage);
/// ```
/// ```compile_fail
/// use brynja_crypto::aes::Aes128Key;
/// let mut storage = [0; 16];
/// let key = Aes128Key::new(&[0; 16], &mut storage).unwrap();
/// let _ = key.clone();
/// ```
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_crypto::aes::Aes128Key<'static>>();
/// ```
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_crypto::aes::Aes128Key<'static>>();
/// ```
/// ```compile_fail
/// use brynja_crypto::aes::Aes128Key;
/// let mut storage = [0; 16];
/// let key = Aes128Key::new(&[0; 16], &mut storage).unwrap();
/// println!("{key:?}");
/// ```
#[must_use = "keep the key owner live until use is complete"]
pub struct Aes128Key<'a> {
    region: OwnedSecretRegion<'a>,
    local: PhantomData<*mut ()>,
}

impl<'a> Aes128Key<'a> {
    /// Copies exactly 16 key bytes into clearing storage. Does not clear input.
    pub fn new(input: &[u8; KEY_BYTES], storage: &'a mut [u8; KEY_BYTES]) -> Result<Self, Error> {
        let mut region = SecretRegionInitialization::begin(storage)?;
        region.write(input)?;
        Ok(Self {
            region: region.finish()?,
            local: PhantomData,
        })
    }

    /// Clears key storage immediately and consumes this owner.
    pub fn clear(self) {
        let _ = self.region.clear();
    }

    /// Encrypts one block into a clearing output owner. No mode or authentication.
    /// Errors/unwind clear the complete admitted destination; input is untouched.
    pub fn encrypt_block<'out>(
        &self,
        input: &[u8; BLOCK_BYTES],
        output: &'out mut [u8; BLOCK_BYTES],
    ) -> Result<SecretBlock<'out>, Error> {
        self.transform(input, output, false)
    }

    /// Encrypts one block with explicit public declassification.
    ///
    /// The complete public destination is unchanged on error or unwind. Secret
    /// state and schedule are guarded until the final, infallible block copy.
    /// Success leaves ciphertext in caller storage; it is not cleared on return.
    /// No public-decryption counterpart exists: plaintext retains secret ownership.
    ///
    /// ```compile_fail
    /// use brynja_crypto::aes::Aes128Key;
    /// let mut storage = [0; 16];
    /// let key = Aes128Key::new(&[0; 16], &mut storage).unwrap();
    /// key.encrypt_block_public(&[0; 16], &mut [0; 16]); // acknowledgement required
    /// ```
    /// ```compile_fail
    /// use brynja_crypto::aes::{Aes128Key, PublicCiphertext};
    /// let mut storage = [0; 16];
    /// let key = Aes128Key::new(&[0; 16], &mut storage).unwrap();
    /// key.decrypt_block_public(&[0; 16], &mut [0; 16], PublicCiphertext::acknowledge());
    /// ```
    pub fn encrypt_block_public(
        &self,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
        _authority: PublicCiphertext,
    ) -> Result<(), Error> {
        let mut schedule = Scratch::<176>::new();
        portable::expand(self.region.expose(), &mut schedule.0)?;
        let mut state = Scratch::<16>::new();
        state.0.copy_from_slice(input);
        portable::transform(&mut state.0, &schedule.0, false)?;
        output.copy_from_slice(&state.0);
        Ok(())
    }

    /// Decrypts one block into a clearing output owner. Does not authenticate it.
    /// Errors/unwind clear the complete admitted destination; input is untouched.
    pub fn decrypt_block<'out>(
        &self,
        input: &[u8; BLOCK_BYTES],
        output: &'out mut [u8; BLOCK_BYTES],
    ) -> Result<SecretBlock<'out>, Error> {
        self.transform(input, output, true)
    }

    fn transform<'out>(
        &self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, Error> {
        // Admit the destination before any secret computation. All guards stay
        // live across errors and unwind; schedule/state are destroyed on return.
        let mut destination = SecretRegionInitialization::begin(output)?;
        let mut schedule = Scratch::<176>::new();
        portable::expand(self.region.expose(), &mut schedule.0)?;
        let mut state = Scratch::<16>::new();
        state.0.copy_from_slice(input);
        portable::transform(&mut state.0, &schedule.0, inverse)?;
        destination.write(&state.0)?;
        Ok(SecretBlock {
            region: destination.finish()?,
            local: PhantomData,
        })
    }
}

/// Clearing block output. Both encryption and decryption retain secret ownership.
///
/// Explicit exposure borrows bytes; copied bytes require the caller's cleanup.
/// The output lifetime depends on its buffer, not the key or input block.
///
/// ```compile_fail
/// use brynja_crypto::aes::Aes128Key;
/// let mut storage = [0; 16];
/// let key = Aes128Key::new(&[0; 16], &mut storage).unwrap();
/// let mut block = [0; 16];
/// let result = key.encrypt_block(&block, &mut block).unwrap();
/// println!("{:?}", result.expose());
/// ```
/// ```compile_fail
/// use brynja_crypto::aes::Aes128Key;
/// let mut storage = [0; 16];
/// let key = Aes128Key::new(&[0; 16], &mut storage).unwrap();
/// let mut block = [0; 16];
/// let result = key.encrypt_block(&[0; 16], &mut block).unwrap();
/// block.fill(1);
/// println!("{:?}", result.expose());
/// ```
#[must_use = "retain the clearing output owner until use is complete"]
pub struct SecretBlock<'a> {
    region: OwnedSecretRegion<'a>,
    local: PhantomData<*mut ()>,
}
impl SecretBlock<'_> {
    /// Explicitly borrows the output bytes. Copies are outside this owner.
    pub fn expose(&self) -> &[u8] {
        self.region.expose()
    }
    /// Clears output immediately and consumes its readable ownership.
    pub fn clear(self) {
        let _ = self.region.clear();
    }
}

#[cfg(test)]
mod tests;
