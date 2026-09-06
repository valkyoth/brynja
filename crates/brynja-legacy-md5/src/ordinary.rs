use crate::{BitString, Md5Error, engine, owner::Md5Owner};

/// Ordinary MD5 for public legacy data; collision resistance is broken.
///
/// Not cloneable, resettable or serializable. Finalization consumes the state.
/// Use `HardenedMd5` for confidential input and explicit output classification.
/// ```compile_fail
/// let state = brynja_legacy_md5::Md5::new();
/// let _ = state.finalize();
/// let _ = state.finalize();
/// ```
pub struct Md5 {
    owner: Md5Owner,
}

impl Md5 {
    /// Initializes the RFC 1321 MD5 IV.
    pub const fn new() -> Self {
        Self {
            owner: Md5Owner::new(),
        }
    }
    /// Number of complete input bits absorbed so far.
    pub fn message_bits(&self) -> u128 {
        self.owner.bits()
    }
    /// Checks complete-byte capacity without mutation.
    pub fn check_additional_bytes(&self, bytes: usize) -> Result<(), Md5Error> {
        engine::admit_bytes(self.owner.bits(), bytes).map(|_| ())
    }
    /// Checks bit capacity without mutation; partial bits are terminal only.
    pub fn check_additional_bits(&self, bits: u128) -> Result<(), Md5Error> {
        engine::admit_bits(self.owner.bits(), bits).map(|_| ())
    }
    /// Appends complete bytes. Length rejection leaves the state unchanged.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Md5Error> {
        engine::update(&mut self.owner, input)
    }
    /// Consumes the state and returns its public 128-bit digest.
    pub fn finalize(mut self) -> [u8; 16] {
        engine::finish_bytes(&mut self.owner);
        self.owner.output_staging
    }
    /// Appends a canonical MSB-first bit string and consumes the state.
    pub fn finalize_bits(mut self, tail: BitString<'_>) -> Result<[u8; 16], Md5Error> {
        engine::finish(&mut self.owner, tail)?;
        Ok(self.owner.output_staging)
    }
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes a public legacy MD5 digest over complete bytes.
pub fn md5(input: &[u8]) -> Result<[u8; 16], Md5Error> {
    let mut state = Md5::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes a public legacy MD5 digest over a canonical bit string.
pub fn md5_bits(input: BitString<'_>) -> Result<[u8; 16], Md5Error> {
    Md5::new().finalize_bits(input)
}
