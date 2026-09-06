use crate::{BitString, Md5Error, PublicDeclassification, engine, output, owner::Md5Owner};
use brynja_core::OwnedSecretRegion;

mod sealed {
    pub trait Sealed {}
}

/// Sealed ownership capability, never downstream-implementable admission to a MAC.
/// ```compile_fail
/// struct Forged;
/// impl brynja_legacy_md5::HardenedMd5State for Forged {}
/// ```
pub trait HardenedMd5State: sealed::Sealed {}

/// Secret-bearing legacy MD5 with mandatory clearing of its private regions.
///
/// Hardening memory does not repair MD5 collisions or make raw MD5 a MAC.
/// No Clone, Debug, reset, snapshot, ordinary-to-hardened conversion or CPU route.
/// Borrowed input remains caller-owned. Secret destinations clear on errors and
/// their returned owner's Drop; explicit public destinations are caller-owned.
/// ```compile_fail
/// let state = brynja_legacy_md5::HardenedMd5::new();
/// let _ = state.clone();
/// ```
/// ```compile_fail
/// let state = brynja_legacy_md5::HardenedMd5::new();
/// println!("{:?}", state);
/// ```
pub struct HardenedMd5 {
    owner: Md5Owner,
}
impl sealed::Sealed for HardenedMd5 {}
impl HardenedMd5State for HardenedMd5 {}

impl HardenedMd5 {
    /// Creates an empty secret-bearing MD5 state.
    pub const fn new() -> Self {
        Self {
            owner: Md5Owner::new(),
        }
    }
    /// Checks byte capacity without exposing the current message length.
    pub fn check_additional_bytes(&self, bytes: usize) -> Result<(), Md5Error> {
        engine::admit_bytes(self.owner.bits(), bytes).map(|_| ())
    }
    /// Checks bit capacity without mutation; the result may reveal capacity.
    pub fn check_additional_bits(&self, bits: u128) -> Result<(), Md5Error> {
        engine::admit_bits(self.owner.bits(), bits).map(|_| ())
    }
    /// Absorbs bytes; exhaustion leaves the state unchanged for retry or Drop.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Md5Error> {
        engine::update(&mut self.owner, input)
    }
    /// Finalizes into public storage of exactly 16 bytes; errors preserve it.
    pub fn finalize_public(
        self,
        destination: &mut [u8],
        authority: PublicDeclassification,
    ) -> Result<(), Md5Error> {
        let empty = BitString::new(&[], 0).map_err(|_| Md5Error::MessageTooLong)?;
        self.finalize_bits_public(empty, destination, authority)
    }
    /// Finalizes with a canonical bit tail and explicit public release authority.
    pub fn finalize_bits_public(
        mut self,
        tail: BitString<'_>,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Md5Error> {
        if destination.len() != 16 {
            return Err(Md5Error::OutputLength);
        }
        engine::finish(&mut self.owner, tail)?;
        destination.copy_from_slice(&self.owner.output_staging);
        Ok(())
    }
    /// Finalizes into a typed secret owner; errors clear the entire destination.
    pub fn finalize_secret(
        self,
        destination: &mut [u8],
    ) -> Result<OwnedSecretRegion<'_>, Md5Error> {
        match BitString::new(&[], 0) {
            Ok(empty) => self.finalize_bits_secret(empty, destination),
            Err(_) => Err(output::failed(destination, Md5Error::MessageTooLong)),
        }
    }
    /// Consumes a final bit tail; errors clear even an incorrectly sized output.
    pub fn finalize_bits_secret<'out>(
        mut self,
        tail: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<OwnedSecretRegion<'out>, Md5Error> {
        if destination.len() != 16 {
            return Err(output::failed(destination, Md5Error::OutputLength));
        }
        if let Err(error) = engine::finish(&mut self.owner, tail) {
            return Err(output::failed(destination, error));
        }
        output::secret(&self.owner.output_staging, destination)
    }
    /// One-shot confidential byte hashing into typed secret output.
    pub fn digest_secret<'out>(
        input: &[u8],
        destination: &'out mut [u8],
    ) -> Result<OwnedSecretRegion<'out>, Md5Error> {
        let mut state = Self::new();
        if let Err(error) = state.update(input) {
            return Err(output::failed(destination, error));
        }
        state.finalize_secret(destination)
    }
    /// One-shot confidential arbitrary-bit hashing into typed secret output.
    pub fn digest_bits_secret<'out>(
        input: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<OwnedSecretRegion<'out>, Md5Error> {
        Self::new().finalize_bits_secret(input, destination)
    }
}

impl Default for HardenedMd5 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustion_finalization_preserves_public_and_clears_secret_output() {
        let tail = BitString::new(&[0], 8);
        assert!(tail.is_ok());
        if let Ok(tail) = tail {
            let mut state = HardenedMd5::new();
            state.owner.message_length = (u128::MAX - 7).to_be_bytes();
            let mut output = [0xa5; 16];
            assert_eq!(
                state.finalize_bits_public(
                    tail,
                    &mut output,
                    PublicDeclassification::acknowledge()
                ),
                Err(Md5Error::MessageTooLong)
            );
            assert_eq!(output, [0xa5; 16]);
            let mut state = HardenedMd5::new();
            state.owner.message_length = (u128::MAX - 7).to_be_bytes();
            assert!(matches!(
                state.finalize_bits_secret(tail, &mut output),
                Err(Md5Error::MessageTooLong)
            ));
            assert_eq!(output, [0; 16]);
        }
    }
}
