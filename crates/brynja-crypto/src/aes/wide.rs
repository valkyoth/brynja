// Only named, fixed-width owners are public. Const parameters and the macro
// are private implementation details, not an extensible cipher interface.
use super::portable::wide;
use super::{
    AES192_EXPANDED_KEY_BYTES, AES192_KEY_BYTES, AES256_EXPANDED_KEY_BYTES, AES256_KEY_BYTES,
    BLOCK_BYTES, Error, OwnedSecretRegion, PhantomData, PublicCiphertext, Scratch, SecretBlock,
    SecretRegionInitialization,
};

fn secret<'out, const K: usize, const S: usize, const R: usize>(
    schedule: &[u8; S],
    input: &[u8; BLOCK_BYTES],
    mut destination: SecretRegionInitialization<'out>,
    inverse: bool,
) -> Result<SecretBlock<'out>, Error> {
    let mut state = Scratch::<BLOCK_BYTES>::new();
    state.0.copy_from_slice(input);
    wide::transform::<K, S, R>(&mut state.0, schedule, inverse)?;
    destination.write(&state.0)?;
    Ok(SecretBlock {
        region: destination.finish()?,
        local: PhantomData,
    })
}

fn public<const K: usize, const S: usize, const R: usize>(
    schedule: &[u8; S],
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) -> Result<(), Error> {
    let mut state = Scratch::<BLOCK_BYTES>::new();
    state.0.copy_from_slice(input);
    wide::transform::<K, S, R>(&mut state.0, schedule, false)?;
    output.copy_from_slice(&state.0);
    Ok(())
}

macro_rules! owners {
    ($key:ident, $cached:ident, $k:ident, $s:ident, $rounds:literal) => {
        /// Caller-backed fixed-width AES key; operation-local expanded schedule.
        ///
        /// Not Copy, Clone, Debug, Send or Sync. The input key is not cleared.
        /// Explicit clear and Drop clear caller storage; neither promises to
        /// erase compiler copies, registers, spills, dumps, aborts or forgotten
        /// owners. Raw blocks provide no authentication, mode or physical defense.
        ///
        /// # Work budget
        ///
        /// Every block operation rebuilds the entire expanded schedule. For
        /// repeated blocks under one key, consider the matching `Aes192ExpandedKey`
        /// or `Aes256ExpandedKey`: expansion is paid once, but key-equivalent
        /// material remains live longer. Neither form limits application request
        /// counts; callers must bound attacker-controlled work and concurrency.
        #[must_use = "keep the key owner live until use is complete"]
        pub struct $key<'a> {
            region: OwnedSecretRegion<'a>,
            local: PhantomData<*mut ()>,
        }
        impl<'a> $key<'a> {
            /// Copies an exactly sized key into clearing caller storage.
            pub fn new(input: &[u8; $k], storage: &'a mut [u8; $k]) -> Result<Self, Error> {
                let mut region = SecretRegionInitialization::begin(storage)?;
                region.write(input)?;
                Ok(Self {
                    region: region.finish()?,
                    local: PhantomData,
                })
            }
            /// Consumes the owner and clears its key storage immediately.
            pub fn clear(self) {
                let _ = self.region.clear();
            }
            /// Encrypts one block. Admitted output clears on error or unwind.
            pub fn encrypt_block<'out>(
                &self,
                input: &[u8; BLOCK_BYTES],
                output: &'out mut [u8; BLOCK_BYTES],
            ) -> Result<SecretBlock<'out>, Error> {
                self.transform(input, output, false)
            }
            /// Decrypts one block to a clearing owner. Does not authenticate it.
            pub fn decrypt_block<'out>(
                &self,
                input: &[u8; BLOCK_BYTES],
                output: &'out mut [u8; BLOCK_BYTES],
            ) -> Result<SecretBlock<'out>, Error> {
                self.transform(input, output, true)
            }
            fn transform<'out>(
                &self,
                input: &[u8; BLOCK_BYTES],
                output: &'out mut [u8; BLOCK_BYTES],
                inverse: bool,
            ) -> Result<SecretBlock<'out>, Error> {
                // Admit output before expansion so even expansion failures clear it.
                let destination = SecretRegionInitialization::begin(output)?;
                let mut schedule = Scratch::<$s>::new();
                wide::expand::<$k, $s, $rounds>(self.region.expose(), &mut schedule.0)?;
                secret::<$k, $s, $rounds>(&schedule.0, input, destination, inverse)
            }
            /// Explicit public encryption; output is unchanged on error/unwind.
            /// No public decryption or implicit declassification is provided.
            pub fn encrypt_block_public(
                &self,
                input: &[u8; BLOCK_BYTES],
                output: &mut [u8; BLOCK_BYTES],
                _authority: PublicCiphertext,
            ) -> Result<(), Error> {
                let mut schedule = Scratch::<$s>::new();
                wide::expand::<$k, $s, $rounds>(self.region.expose(), &mut schedule.0)?;
                public::<$k, $s, $rounds>(&schedule.0, input, output)
            }
        }

        /// Optional caller-owned cached AES schedule, expanded once at import.
        ///
        /// Schedule bytes are key-equivalent material, cleared on clear/Drop.
        /// Larger storage and longer residency trade off against repeated
        /// expansion; cached keys are not a protection against physical attacks.
        /// No allocation, export, Copy, Clone, Debug, Send or Sync is provided.
        #[must_use = "keep the expanded-key owner live until use is complete"]
        pub struct $cached<'a> {
            region: OwnedSecretRegion<'a>,
            local: PhantomData<*mut ()>,
        }
        impl<'a> $cached<'a> {
            /// Expands the exact key into clearing storage. Errors/unwind clear
            /// the admitted storage; the caller remains responsible for input.
            pub fn new(input: &[u8; $k], storage: &'a mut [u8; $s]) -> Result<Self, Error> {
                let mut destination = SecretRegionInitialization::begin(storage)?;
                let mut schedule = Scratch::<$s>::new();
                wide::expand::<$k, $s, $rounds>(input, &mut schedule.0)?;
                destination.write(&schedule.0)?;
                #[cfg(test)]
                crate::aes::tests::expansion_checkpoint()?;
                Ok(Self {
                    region: destination.finish()?,
                    local: PhantomData,
                })
            }
            /// Consumes the owner and clears the entire expanded schedule.
            pub fn clear(self) {
                let _ = self.region.clear();
            }
            /// Encrypts one block without re-expansion, into clearing output.
            pub fn encrypt_block<'out>(
                &self,
                input: &[u8; BLOCK_BYTES],
                output: &'out mut [u8; BLOCK_BYTES],
            ) -> Result<SecretBlock<'out>, Error> {
                self.transform(input, output, false)
            }
            /// Decrypts one block without re-expansion. No authentication.
            pub fn decrypt_block<'out>(
                &self,
                input: &[u8; BLOCK_BYTES],
                output: &'out mut [u8; BLOCK_BYTES],
            ) -> Result<SecretBlock<'out>, Error> {
                self.transform(input, output, true)
            }
            fn transform<'out>(
                &self,
                input: &[u8; BLOCK_BYTES],
                output: &'out mut [u8; BLOCK_BYTES],
                inverse: bool,
            ) -> Result<SecretBlock<'out>, Error> {
                let destination = SecretRegionInitialization::begin(output)?;
                let schedule: &[u8; $s] = self
                    .region
                    .expose()
                    .try_into()
                    .map_err(|_| Error::SecretMemory)?;
                secret::<$k, $s, $rounds>(schedule, input, destination, inverse)
            }
            /// Explicit public encryption; output is unchanged on error/unwind.
            pub fn encrypt_block_public(
                &self,
                input: &[u8; BLOCK_BYTES],
                output: &mut [u8; BLOCK_BYTES],
                _authority: PublicCiphertext,
            ) -> Result<(), Error> {
                let schedule: &[u8; $s] = self
                    .region
                    .expose()
                    .try_into()
                    .map_err(|_| Error::SecretMemory)?;
                public::<$k, $s, $rounds>(schedule, input, output)
            }
        }
    };
}

owners!(
    Aes192Key,
    Aes192ExpandedKey,
    AES192_KEY_BYTES,
    AES192_EXPANDED_KEY_BYTES,
    12
);
owners!(
    Aes256Key,
    Aes256ExpandedKey,
    AES256_KEY_BYTES,
    AES256_EXPANDED_KEY_BYTES,
    14
);
