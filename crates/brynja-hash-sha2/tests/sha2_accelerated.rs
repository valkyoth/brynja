//! Compile-time-selected no_std SHA-2 family backend differential tests.

#![cfg(feature = "cpu")]

use brynja_hash_sha2::{
    BitString, Sha224, Sha256, Sha256BackendSession, Sha384, Sha512, Sha512_224, Sha512_256,
    Sha512BackendSession, sha224, sha256, sha384, sha512, sha512_224, sha512_256,
};

fn corpus() -> [u8; 385] {
    let mut content = [0_u8; 385];
    for (index, byte) in content.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap_or(0);
    }
    content
}

#[test]
fn sha256_family_backend_matches_both_algorithm_identities() {
    let Some(backend) = Sha256BackendSession::for_compiled_target() else {
        return;
    };
    let content = corpus();
    for length in [0_usize, 1, 55, 56, 63, 64, 65, 127, 128, 255, 385] {
        let Some(input) = content.get(..length) else {
            continue;
        };
        let expected224 = sha224(input);
        let expected256 = sha256(input);
        assert!(expected224.is_ok());
        assert!(expected256.is_ok());
        let (Ok(expected224), Ok(expected256)) = (expected224, expected256) else {
            continue;
        };
        for width in [1_usize, 3, 17, 63, 64, 67, 129] {
            let mut state224 = Sha224::new();
            let mut state256 = Sha256::new();
            for chunk in input.chunks(width) {
                assert_eq!(state224.update_with_backend(chunk, &backend), Ok(()));
                assert_eq!(state256.update_with_backend(chunk, &backend), Ok(()));
            }
            assert_eq!(state224.finalize_with_backend(&backend), Ok(expected224));
            assert_eq!(state256.finalize_with_backend(&backend), Ok(expected256));
        }
    }
    for valid in 1_u8..8 {
        let tail = [content[130] & !(u8::MAX >> valid)];
        let bits = BitString::new(&tail, valid);
        assert!(bits.is_ok());
        let Ok(bits) = bits else {
            continue;
        };
        let mut scalar224 = Sha224::new();
        let mut scalar256 = Sha256::new();
        let mut accelerated224 = Sha224::new();
        let mut accelerated256 = Sha256::new();
        assert_eq!(scalar224.update(&content[..130]), Ok(()));
        assert_eq!(scalar256.update(&content[..130]), Ok(()));
        assert_eq!(
            accelerated224.update_with_backend(&content[..130], &backend),
            Ok(())
        );
        assert_eq!(
            accelerated256.update_with_backend(&content[..130], &backend),
            Ok(())
        );
        assert_eq!(
            accelerated224.finalize_bits_with_backend(bits, &backend),
            scalar224
                .finalize_bits(bits)
                .map_err(|_| { brynja_hash_sha2::Sha224AcceleratedError::MessageTooLong })
        );
        assert_eq!(
            accelerated256.finalize_bits_with_backend(bits, &backend),
            scalar256
                .finalize_bits(bits)
                .map_err(|_| { brynja_hash_sha2::Sha256AcceleratedError::MessageTooLong })
        );
    }
}

#[test]
fn sha512_family_backend_matches_all_four_algorithm_identities() {
    let Some(backend) = Sha512BackendSession::for_compiled_target() else {
        return;
    };
    assert_eq!(
        backend.health(),
        brynja_hash_sha2::Sha512BackendHealth::Healthy
    );
    let content = corpus();
    for length in [0_usize, 1, 111, 112, 127, 128, 129, 255, 256, 385] {
        let Some(input) = content.get(..length) else {
            continue;
        };
        let expected384 = sha384(input);
        let expected512 = sha512(input);
        let expected512_224 = sha512_224(input);
        let expected512_256 = sha512_256(input);
        assert!(expected384.is_ok());
        assert!(expected512.is_ok());
        assert!(expected512_224.is_ok());
        assert!(expected512_256.is_ok());
        let (Ok(expected384), Ok(expected512), Ok(expected512_224), Ok(expected512_256)) =
            (expected384, expected512, expected512_224, expected512_256)
        else {
            continue;
        };
        for width in [1_usize, 3, 31, 111, 127, 128, 131] {
            let mut state384 = Sha384::new();
            let mut state512 = Sha512::new();
            let mut state512_224 = Sha512_224::new();
            let mut state512_256 = Sha512_256::new();
            for chunk in input.chunks(width) {
                assert_eq!(state384.update_with_backend(chunk, &backend), Ok(()));
                assert_eq!(state512.update_with_backend(chunk, &backend), Ok(()));
                assert_eq!(state512_224.update_with_backend(chunk, &backend), Ok(()));
                assert_eq!(state512_256.update_with_backend(chunk, &backend), Ok(()));
            }
            assert_eq!(state384.finalize_with_backend(&backend), Ok(expected384));
            assert_eq!(state512.finalize_with_backend(&backend), Ok(expected512));
            assert_eq!(
                state512_224.finalize_with_backend(&backend),
                Ok(expected512_224)
            );
            assert_eq!(
                state512_256.finalize_with_backend(&backend),
                Ok(expected512_256)
            );
        }
    }
    for valid in 1_u8..8 {
        let tail = [content[258] & !(u8::MAX >> valid)];
        let bits = BitString::new(&tail, valid);
        assert!(bits.is_ok());
        let Ok(bits) = bits else {
            continue;
        };
        let mut scalar384 = Sha384::new();
        let mut scalar512 = Sha512::new();
        let mut scalar512_224 = Sha512_224::new();
        let mut scalar512_256 = Sha512_256::new();
        let mut accelerated384 = Sha384::new();
        let mut accelerated512 = Sha512::new();
        let mut accelerated512_224 = Sha512_224::new();
        let mut accelerated512_256 = Sha512_256::new();
        for chunk in content[..258].chunks(67) {
            assert_eq!(scalar384.update(chunk), Ok(()));
            assert_eq!(scalar512.update(chunk), Ok(()));
            assert_eq!(scalar512_224.update(chunk), Ok(()));
            assert_eq!(scalar512_256.update(chunk), Ok(()));
            assert_eq!(accelerated384.update_with_backend(chunk, &backend), Ok(()));
            assert_eq!(accelerated512.update_with_backend(chunk, &backend), Ok(()));
            assert_eq!(
                accelerated512_224.update_with_backend(chunk, &backend),
                Ok(())
            );
            assert_eq!(
                accelerated512_256.update_with_backend(chunk, &backend),
                Ok(())
            );
        }
        assert_eq!(
            accelerated384.finalize_bits_with_backend(bits, &backend),
            scalar384
                .finalize_bits(bits)
                .map_err(|_| { brynja_hash_sha2::Sha512AcceleratedError::MessageTooLong })
        );
        assert_eq!(
            accelerated512.finalize_bits_with_backend(bits, &backend),
            scalar512
                .finalize_bits(bits)
                .map_err(|_| { brynja_hash_sha2::Sha512AcceleratedError::MessageTooLong })
        );
        assert_eq!(
            accelerated512_224.finalize_bits_with_backend(bits, &backend),
            scalar512_224
                .finalize_bits(bits)
                .map_err(|_| { brynja_hash_sha2::Sha512AcceleratedError::MessageTooLong })
        );
        assert_eq!(
            accelerated512_256.finalize_bits_with_backend(bits, &backend),
            scalar512_256
                .finalize_bits(bits)
                .map_err(|_| { brynja_hash_sha2::Sha512AcceleratedError::MessageTooLong })
        );
    }
}
