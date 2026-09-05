//! Dependency-external no_std SHA-1 consumer, with no modern crypto dependency.
#![no_std]

use brynja_legacy_sha1::{BitString, HardenedSha1, PublicDeclassification, Sha1, Sha1Error, sha1};

/// Real consumer streaming and one-shot digest agreement, plus secret ownership.
pub fn acceptance() -> Result<(), Sha1Error> {
    let expected = sha1(b"abc")?;
    let mut ordinary = Sha1::new();
    ordinary.update(b"a")?;
    ordinary.update(b"bc")?;
    assert_eq!(ordinary.finalize(), expected);
    let mut hardened = HardenedSha1::new();
    hardened.update(b"abc")?;
    let mut public = [0; 20];
    hardened.finalize_public(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(public, expected);
    let mut output = [0xa5; 20];
    {
        let input = BitString::new(b"abc", 8).map_err(|_| Sha1Error::MessageTooLong)?;
        let secret = HardenedSha1::digest_bits_secret(input, &mut output)?;
        assert_eq!(secret.expose(), expected);
    }
    assert_eq!(output, [0; 20]);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn complete_downstream_api() {
        assert_eq!(super::acceptance(), Ok(()));
    }
}
