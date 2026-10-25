//! Invalid public tag-width admission only; not cryptographic correctness.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(kani)]
mod proofs {
    use brynja_legacy_hmac::{Error, Hmac, LegacyUse, Md5, Sha1};

    #[kani::proof]
    #[kani::unwind(2)]
    fn md5_invalid_tag_width_rejects() {
        let width: usize = kani::any();
        kani::assume(!(10..=16).contains(&width));
        let key: [u8; 1] = kani::any();
        assert!(matches!(
            Hmac::<Md5>::with_tag_length(LegacyUse::acknowledge(), &key, width),
            Err(Error::TagLength)
        ));
    }

    #[kani::proof]
    #[kani::unwind(2)]
    fn sha1_invalid_tag_width_rejects() {
        let width: usize = kani::any();
        kani::assume(!(10..=20).contains(&width));
        let key: [u8; 1] = kani::any();
        assert!(matches!(
            Hmac::<Sha1>::with_tag_length(LegacyUse::acknowledge(), &key, width),
            Err(Error::TagLength)
        ));
    }
}

#[cfg(test)]
mod tests {
    use brynja_legacy_hmac::{Error, Hmac, LegacyUse, Md5, Sha1};

    #[test]
    fn invalid_widths_use_real_public_constructors() {
        for width in [0, 1, 9, 17, 20, 21, usize::MAX] {
            if !(10..=16).contains(&width) {
                assert!(matches!(
                    Hmac::<Md5>::with_tag_length(LegacyUse::acknowledge(), b"k", width),
                    Err(Error::TagLength)
                ));
            }
            if !(10..=20).contains(&width) {
                assert!(matches!(
                    Hmac::<Sha1>::with_tag_length(LegacyUse::acknowledge(), b"k", width),
                    Err(Error::TagLength)
                ));
            }
        }
    }
}
