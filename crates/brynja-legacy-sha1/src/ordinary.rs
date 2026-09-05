use crate::{BitString, Sha1Error, engine, owner::Sha1Owner};

/// Ordinary SHA-1 for public legacy data; collision resistance is broken.
///
/// Not cloneable, resettable or serializable. Finalization consumes the state.
/// Use `HardenedSha1` for confidential input and explicit output classification.
/// ```compile_fail
/// let state = brynja_legacy_sha1::Sha1::new();
/// let _ = state.finalize();
/// let _ = state.finalize();
/// ```
pub struct Sha1 {
    owner: Sha1Owner,
}

impl Sha1 {
    /// Initializes the FIPS 180-4 SHA-1 IV.
    pub const fn new() -> Self {
        Self {
            owner: Sha1Owner::new(),
        }
    }
    /// Number of complete input bits absorbed so far.
    pub fn message_bits(&self) -> u64 {
        self.owner.bits()
    }
    /// Checks complete-byte capacity without mutation.
    pub fn check_additional_bytes(&self, bytes: usize) -> Result<(), Sha1Error> {
        engine::admit_bytes(self.owner.bits(), bytes).map(|_| ())
    }
    /// Checks bit capacity without mutation; partial bits are terminal only.
    pub fn check_additional_bits(&self, bits: u64) -> Result<(), Sha1Error> {
        engine::admit_bits(self.owner.bits(), bits).map(|_| ())
    }
    /// Appends complete bytes. Length rejection leaves the state unchanged.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha1Error> {
        engine::update(&mut self.owner, input)
    }
    /// Consumes the state and returns its public 160-bit digest.
    pub fn finalize(mut self) -> [u8; 20] {
        engine::finish_bytes(&mut self.owner);
        self.owner.output_staging
    }
    /// Appends a canonical MSB-first bit string and consumes the state.
    pub fn finalize_bits(mut self, tail: BitString<'_>) -> Result<[u8; 20], Sha1Error> {
        engine::finish(&mut self.owner, tail)?;
        Ok(self.owner.output_staging)
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes a public legacy SHA-1 digest over complete bytes.
pub fn sha1(input: &[u8]) -> Result<[u8; 20], Sha1Error> {
    let mut state = Sha1::new();
    state.update(input)?;
    Ok(state.finalize())
}

/// Computes a public legacy SHA-1 digest over a canonical bit string.
pub fn sha1_bits(input: BitString<'_>) -> Result<[u8; 20], Sha1Error> {
    Sha1::new().finalize_bits(input)
}
