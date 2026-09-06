//! Dependency-external no_std MD5 consumer, with no modern crypto dependency.
#![no_std]

use brynja_legacy_md5::{BitString, HardenedMd5, Md5, Md5Error, PublicDeclassification, md5};

/// Real consumer streaming and one-shot digest agreement, plus secret ownership.
pub fn acceptance() -> Result<(), Md5Error> {
    let expected = md5(b"abc")?;
    let mut ordinary = Md5::new();
    ordinary.update(b"a")?;
    ordinary.update(b"bc")?;
    assert_eq!(ordinary.finalize(), expected);
    let mut hardened = HardenedMd5::new();
    hardened.update(b"abc")?;
    let mut public = [0; 16];
    hardened.finalize_public(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(public, expected);
    let mut output = [0xa5; 16];
    {
        let input = BitString::new(b"abc", 8).map_err(|_| Md5Error::MessageTooLong)?;
        let secret = HardenedMd5::digest_bits_secret(input, &mut output)?;
        assert_eq!(secret.expose(), expected);
    }
    assert_eq!(output, [0; 16]);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn complete_downstream_api() {
        assert_eq!(super::acceptance(), Ok(()));
    }
}
