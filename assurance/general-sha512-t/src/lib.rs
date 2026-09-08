//! Downstream no_std consumer of general ordinary and hardened SHA-512/t.
#![no_std]

pub mod acceptance;
mod boundaries;
mod corpus;
pub mod resources;

/// Visit exactly the frozen corpus rows. The visitor must validate its own
/// outputs; successful parsing by itself is not cryptographic acceptance.
pub fn visit_corpus<F>(input: &str, visitor: F) -> Result<usize, acceptance::Error>
where
    F: FnMut(u16, usize, &[u8], &[u8]) -> Result<(), acceptance::Error>,
{
    corpus::visit(input, visitor)
}

use brynja_hash_sha2::{Sha512TBits, Sha512TDigest, Sha512TError};

/// Import a public result from another implementation with exact identity.
pub fn import_public(t: u16, bytes: &[u8]) -> Result<Sha512TDigest, Sha512TError> {
    Sha512TDigest::from_bytes(Sha512TBits::new(t)?, bytes)
}

/// Read public IV material for diagnostics; this is not message hashing.
pub fn initial_words(t: u16) -> Result<[u64; 8], Sha512TError> {
    Ok(Sha512TBits::new(t)?.initial_words())
}

/// Hash confidential bytes, explicitly release their digest as public, and
/// check that the caller-owned secret destination is cleared on transfer.
pub fn declassified_hash(
    parameter: Sha512TBits,
    input: &[u8],
    storage: &mut [u8],
) -> Result<Sha512TDigest, Sha512TError> {
    let secret = brynja_hash_sha2::hardened_sha512_t_secret(parameter, input, storage)?;
    let public = secret.declassify(brynja_hash_sha2::PublicDeclassification::acknowledge())?;
    if storage.iter().any(|byte| *byte != 0) {
        return Err(Sha512TError::SecretMemory);
    }
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downstream_parameter_and_digest_are_usable() -> Result<(), Sha512TError> {
        for t in [1, 9, 224, 256, 511] {
            let p = Sha512TBits::new(t)?;
            let mut storage = [0xa5; 64];
            let output = storage
                .get_mut(..p.output_bytes())
                .ok_or(Sha512TError::OutputLength)?;
            assert_eq!(
                declassified_hash(p, b"abc", output)?,
                brynja_hash_sha2::sha512_t(p, b"abc")?
            );
        }
        let digest = import_public(9, &[0xa5, 0x80])?;
        assert_eq!(digest.parameter().bits(), 9);
        assert_eq!(digest.as_bytes(), &[0xa5, 0x80]);
        assert_eq!(
            import_public(9, &[0xa5, 1]),
            Err(Sha512TError::NonCanonicalOutput)
        );
        assert_eq!(
            import_public(384, &[0; 48]),
            Err(Sha512TError::InvalidParameter)
        );
        assert_ne!(initial_words(9)?, initial_words(10)?);
        Ok(())
    }
}
