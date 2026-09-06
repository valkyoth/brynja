use super::*;
use crate::{AcceleratedSha1, BitString, Sha1, owner::Sha1Owner, sha1, sha1_bits};

fn session() -> Option<Sha1BackendSession> {
    compiled_backend()?;
    let result = Sha1BackendSession::for_compiled_target();
    assert!(result.is_ok());
    let session = result.ok()?;
    assert_eq!(session.health(), Sha1BackendHealth::Healthy);
    Some(session)
}

#[test]
fn exact_identity_features_and_unadmitted_status() {
    assert_eq!(Sha1Backend::X86Sha.required_features(), &["sse2", "sha"]);
    assert_eq!(
        Sha1Backend::Aarch64Sha1.required_features(),
        &["neon", "sha2"]
    );
    assert!(!Sha1Backend::X86Sha.is_admitted());
    assert!(!Sha1Backend::Aarch64Sha1.is_admitted());
    if compiled_backend().is_none() {
        assert_eq!(
            Sha1BackendSession::for_compiled_target().err(),
            Some(Sha1BackendError::MissingFeatures)
        );
    }
}

#[test]
fn arbitrary_state_block_differential() {
    let Some(session) = session() else {
        return;
    };
    let mut rng = 0x9e3779b9_u32;
    for _ in 0..4096 {
        let mut owner = Sha1Owner::new();
        for byte in owner
            .chaining_state
            .iter_mut()
            .chain(owner.block.iter_mut())
        {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            *byte = rng.to_le_bytes()[0];
        }
        let mut state = [0; 5];
        for (word, bytes) in state.iter_mut().zip(owner.chaining_state.chunks_exact(4)) {
            if let [a, b, c, d] = bytes {
                *word = u32::from_be_bytes([*a, *b, *c, *d]);
            }
        }
        assert_eq!(session.compress(&mut state, &owner.block), Ok(()));
        crate::compress::compress(&mut owner);
        for (word, bytes) in state.into_iter().zip(owner.chaining_state.chunks_exact(4)) {
            assert_eq!(word.to_be_bytes(), bytes);
        }
    }
}

#[test]
fn byte_bit_and_irregular_streams_match_portable() {
    let Some(session) = session() else {
        return;
    };
    let input = [0xa5; 257];
    for length in 0..=257 {
        let bytes = input.get(..length).unwrap_or_default();
        assert_eq!(
            AcceleratedSha1::hash(&session, bytes),
            sha1(bytes).map_err(|_| Sha1BackendError::MessageTooLong)
        );
        for residue in 0..8 {
            let mut tail = [0; 258];
            tail.get_mut(..length)
                .unwrap_or_default()
                .copy_from_slice(bytes);
            if let Some(last) = tail.get_mut(length) {
                *last = 0xff << (8 - residue).min(7);
                if residue == 0 {
                    *last = 0;
                }
            }
            let used = length + usize::from(residue != 0);
            let bits = BitString::new(
                tail.get(..used).unwrap_or_default(),
                if used == 0 {
                    0
                } else if residue == 0 {
                    8
                } else {
                    u8::try_from(residue).unwrap_or(0)
                },
            );
            assert!(bits.is_ok());
            let Ok(bits) = bits else {
                return;
            };
            assert_eq!(
                AcceleratedSha1::hash_bits(&session, bits),
                sha1_bits(bits).map_err(|_| Sha1BackendError::MessageTooLong)
            );
            let prefix = length / 2;
            let stream = AcceleratedSha1::new(&session);
            assert!(stream.is_ok());
            let Ok(mut streamed) = stream else {
                return;
            };
            assert_eq!(
                streamed.update(tail.get(..prefix).unwrap_or_default()),
                Ok(())
            );
            let remainder = BitString::new(
                tail.get(prefix..used).unwrap_or_default(),
                if used == prefix {
                    0
                } else if residue == 0 {
                    8
                } else {
                    u8::try_from(residue).unwrap_or(0)
                },
            );
            assert!(remainder.is_ok());
            if let Ok(remainder) = remainder {
                assert_eq!(
                    streamed.finalize_bits(remainder),
                    sha1_bits(bits).map_err(|_| Sha1BackendError::MessageTooLong)
                );
            }
        }
        let selected = AcceleratedSha1::new(&session).ok();
        let mut scalar = Sha1::new();
        let Some(mut selected) = selected else {
            return;
        };
        for chunk in bytes.chunks(7) {
            assert_eq!(selected.update(chunk), Ok(()));
            assert_eq!(scalar.update(chunk), Ok(()));
        }
        assert_eq!(selected.message_bits(), scalar.message_bits());
        assert_eq!(selected.finalize(), Ok(scalar.finalize()));
    }
}

#[test]
fn corrupted_kat_and_lost_features_are_permanent() {
    let Some(backend) = compiled_backend() else {
        return;
    };
    let bad = Sha1BackendSession::construct(backend, compiled_features, [0; 5]);
    assert!(bad.is_ok());
    let Ok(bad) = bad else {
        return;
    };
    assert_eq!(bad.health(), Sha1BackendHealth::Quarantined);
    let mut state = IV;
    assert_eq!(
        bad.compress(&mut state, &[0; 64]),
        Err(Sha1BackendError::Quarantined)
    );
    assert_eq!(state, IV);
    let Some(mut session) = session() else {
        return;
    };
    session.revalidate = |_| false;
    assert_eq!(
        session.compress(&mut state, &[0; 64]),
        Err(Sha1BackendError::MissingFeatures)
    );
    session.revalidate = compiled_features;
    assert_eq!(
        session.compress(&mut state, &[0; 64]),
        Err(Sha1BackendError::Quarantined)
    );
    assert_eq!(state, IV);
}

#[test]
fn architecture_and_missing_features_reject_before_startup() {
    let wrong = if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
        Sha1Backend::Aarch64Sha1
    } else {
        Sha1Backend::X86Sha
    };
    assert_eq!(
        Sha1BackendSession::construct(wrong, |_| false, ABC).err(),
        Some(Sha1BackendError::WrongArchitecture)
    );
    if let Some(backend) = compiled_backend() {
        assert_eq!(
            Sha1BackendSession::construct(backend, |_| false, ABC).err(),
            Some(Sha1BackendError::MissingFeatures)
        );
    }
}
