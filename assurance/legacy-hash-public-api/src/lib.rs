//! Frozen forced-portable consumer contract. These broken hashes are NOT authentication.
#![no_std]

#[macro_use]
mod profiles;
mod vectors;

mod sha1 {
    use brynja_legacy_sha1::{
        BitString, HardenedSha1, PublicDeclassification, Sha1, sha1, sha1_bits,
    };
    profile!(Sha1, HardenedSha1, sha1, sha1_bits, 20, u64);
}
mod md5 {
    use brynja_legacy_md5::{BitString, HardenedMd5, Md5, PublicDeclassification, md5, md5_bits};
    profile!(Md5, HardenedMd5, md5, md5_bits, 16, u128);
}

/// Real files, authoritative byte vectors, independent bits and all public profiles.
pub fn acceptance() {
    for (data, sha1_digest, md5_digest) in vectors::FILES {
        sha1::bytes(data, sha1_digest);
        md5::bytes(data, md5_digest);
    }
    for (data, width, sha1_digest, md5_digest) in vectors::BITS {
        sha1::bits(data, *width, sha1_digest);
        md5::bits(data, *width, md5_digest);
    }
    sha1::failures();
    md5::failures();
}

/// Bounded interpreter campaign: classification failures and one bit-tail per family.
pub fn dynamic_lifecycle() {
    sha1::failures();
    md5::failures();
    let (data, width, sha1_digest, md5_digest) = vectors::BITS[1];
    sha1::bits(data, width, sha1_digest);
    md5::bits(data, width, md5_digest);
}

#[cfg(test)]
mod tests {
    extern crate std;

    #[test]
    fn real_files_and_public_profiles() {
        super::acceptance();
    }
    #[test]
    fn dynamic_lifecycle_smoke() {
        super::dynamic_lifecycle();
    }

    #[test]
    fn dynamic_unwind_clears_borrowed_secret_output() {
        let mut output = [0xa5; 20];
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let secret = brynja_legacy_sha1::HardenedSha1::digest_secret(b"a", &mut output);
            assert!(secret.is_ok());
            panic!("exercise recoverable consumer unwind");
        }));
        assert!(caught.is_err());
        assert_eq!(output, [0; 20]);
        let mut output = [0xa5; 16];
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let secret = brynja_legacy_md5::HardenedMd5::digest_secret(b"a", &mut output);
            assert!(secret.is_ok());
            panic!("exercise recoverable consumer unwind");
        }));
        assert!(caught.is_err());
        assert_eq!(output, [0; 16]);
    }
}
