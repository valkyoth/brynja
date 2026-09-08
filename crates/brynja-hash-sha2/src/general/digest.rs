use super::{Sha512TBits, Sha512TError};

/// Canonical, parameter-bound **public** general SHA-512/t digest bytes.
///
/// Importing bytes does not compute or verify a hash. This value never owns
/// confidential input: copies, formatting and ordinary (not constant-time)
/// equality are allowed. Callers must explicitly declassify secret material
/// before import. A future secret digest has a different, non-copyable owner.
/// Equality and Hash bind t even when two rounded byte encodings match.
/// No implicit conversion to a named /224 or /256 digest is provided.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha512TDigest {
    parameter: Sha512TBits,
    storage: [u8; 64],
}

impl Sha512TDigest {
    // Only ordinary results or explicitly declassified bytes enter here.
    pub(super) fn computed(parameter: Sha512TBits, bytes: &[u8]) -> Result<Self, Sha512TError> {
        let source = bytes
            .get(..parameter.output_bytes())
            .ok_or(Sha512TError::OutputLength)?;
        let mut storage = [0; 64];
        for (slot, byte) in storage.iter_mut().zip(source) {
            *slot = *byte;
        }
        if let Some(last) = storage.get_mut(parameter.output_bytes().saturating_sub(1)) {
            *last &= parameter.last_byte_mask();
        }
        Ok(Self { parameter, storage })
    }
    /// Imports an exact-width public digest, rejecting noncanonical low bits.
    ///
    /// Does not truncate, mask malformed input, or modify caller storage.
    /// Uses 64 bytes of fixed private storage with all unused bytes zero.
    ///
    /// ```
    /// use brynja_hash_sha2::{Sha512TBits, Sha512TDigest};
    /// let parameter = Sha512TBits::new(9)?;
    /// let digest = Sha512TDigest::from_bytes(parameter, &[0xab, 0x80])?;
    /// assert_eq!(digest.parameter(), parameter);
    /// assert_eq!(digest.as_bytes(), &[0xab, 0x80]);
    /// assert!(Sha512TDigest::from_bytes(parameter, &[0xab, 0x81]).is_err());
    /// # Ok::<(), brynja_hash_sha2::Sha512TError>(())
    /// ```
    pub fn from_bytes(parameter: Sha512TBits, bytes: &[u8]) -> Result<Self, Sha512TError> {
        if bytes.len() != parameter.output_bytes() {
            return Err(Sha512TError::OutputLength);
        }
        if bytes
            .last()
            .is_some_and(|last| last & !parameter.last_byte_mask() != 0)
        {
            return Err(Sha512TError::NonCanonicalOutput);
        }
        let mut storage = [0_u8; 64];
        for (slot, byte) in storage.iter_mut().zip(bytes) {
            *slot = *byte;
        }
        Ok(Self { parameter, storage })
    }

    /// Returns the exact digest identity, including its bit count.
    #[must_use]
    pub const fn parameter(&self) -> Sha512TBits {
        self.parameter
    }

    /// Borrows exactly ceil(t/8) bytes; unused low bits in the last are zero.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.storage
            .get(..self.parameter.output_bytes())
            .unwrap_or_default()
    }
}

impl AsRef<[u8]> for Sha512TDigest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_unused_private_byte_is_zero() {
        for t in 1..512 {
            let Ok(parameter) = Sha512TBits::new(t) else {
                continue;
            };
            let mut bytes = [0xff; 64];
            let length = parameter.output_bytes();
            if let Some(last) = bytes.get_mut(length.saturating_sub(1)) {
                *last &= parameter.last_byte_mask();
            }
            let digest =
                Sha512TDigest::from_bytes(parameter, bytes.get(..length).unwrap_or_default());
            assert!(digest.is_ok());
            if let Ok(digest) = digest {
                assert!(
                    digest
                        .storage
                        .get(length..)
                        .unwrap_or_default()
                        .iter()
                        .all(|byte| *byte == 0)
                );
            }
        }
    }
}
