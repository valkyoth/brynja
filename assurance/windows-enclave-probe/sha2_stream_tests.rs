use super::*;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};

fn reference(algorithm: Algorithm, input: &[u8], last: u8) -> Vec<u8> {
    use brynja_hash_sha2::*;
    let bits = BitString::new(input, last).unwrap();
    match algorithm {
        Algorithm::Sha224 => sha224_bits(bits).unwrap().as_bytes().to_vec(),
        Algorithm::Sha256 => sha256_bits(bits).unwrap().as_bytes().to_vec(),
        Algorithm::Sha384 => sha384_bits(bits).unwrap().as_bytes().to_vec(),
        Algorithm::Sha512 => sha512_bits(bits).unwrap().as_bytes().to_vec(),
        Algorithm::Sha512_224 => sha512_224_bits(bits).unwrap().as_bytes().to_vec(),
        Algorithm::Sha512_256 => sha512_256_bits(bits).unwrap().as_bytes().to_vec(),
        Algorithm::Sha512T(t) => sha512_t_bits(t, bits).unwrap().as_bytes().to_vec(),
    }
}
fn algorithms() -> Vec<Algorithm> {
    (1..=6)
        .chain(0x1001..=0x11ff)
        .filter_map(|v| Algorithm::decode(v).ok())
        .collect()
}
fn retained(algorithm: Algorithm) -> Owner {
    let mut owner = Owner::new();
    owner.begin(1, algorithm.encode()).unwrap();
    owner.finish(2, b"abc", 8).unwrap();
    owner
}
fn quarantined(owner: &Owner) {
    assert_eq!(owner.phase, Phase::Quarantined);
    assert!(owner.state.is_none());
    assert!(owner.algorithm.is_none());
    assert_eq!(owner.output, [0; 64]);
}

#[test]
fn all_identities_streaming_and_arbitrary_bit_differential() {
    assert_eq!(algorithms().len(), 516);
    for algorithm in algorithms() {
        for length in [
            0_usize, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 1023, 1024, 2049,
        ] {
            for last in if length == 0 { 0..=0 } else { 1..=8 } {
                let mut message: Vec<u8> =
                    (0..length).map(|i| (i as u8).wrapping_mul(17)).collect();
                if let Some(byte) = message.last_mut() {
                    *byte &= 0xff << (8 - last);
                }
                let expected = reference(algorithm, &message, last);
                let mut owner = Owner::new();
                owner.begin(1, algorithm.encode()).unwrap();
                let split = length.saturating_sub(1);
                let mut sequence = 1;
                for chunk in message[..split].chunks(113) {
                    sequence += 1;
                    owner.update(sequence, &[]).unwrap();
                    sequence += 1;
                    owner.update(sequence, chunk).unwrap();
                }
                sequence += 1;
                owner.finish(sequence, &message[split..], last).unwrap();
                assert_eq!(owner.output[..algorithm.width()], expected);
                sequence += 1;
                let mut public = Vec::new();
                owner
                    .export_public(sequence, algorithm.encode(), |bytes| {
                        public.extend_from_slice(bytes);
                        true
                    })
                    .unwrap();
                assert_eq!(public, expected);
                assert_eq!(owner.output, [0; 64]);
                assert!(owner.state.is_none());
                assert_eq!(owner.phase, Phase::Empty);
            }
        }
    }
}

#[test]
fn retained_rehash_preserves_exact_general_digest_bit_length() {
    for algorithm in algorithms() {
        let mut owner = retained(algorithm);
        let first = reference(algorithm, b"abc", 8);
        let last = match algorithm {
            Algorithm::Sha512T(t) if t.bits() % 8 != 0 => (t.bits() % 8) as u8,
            _ => 8,
        };
        let target = Algorithm::Sha512;
        let expected = reference(target, &first, last);
        owner.rehash(3, target.encode()).unwrap();
        assert_eq!(&owner.output[..64], expected);
        assert_eq!(owner.algorithm, Some(target));
        owner.cancel(4).unwrap();
        assert_eq!(owner.output, [0; 64]);
    }
}

#[test]
fn replay_gaps_exhaustion_and_invalid_identity_destroy_state() {
    for sequence in [0, 1, 2, 4, u64::MAX] {
        let mut owner = retained(Algorithm::Sha256);
        assert_eq!(owner.rehash(sequence, 2), Err(Error::Sequence));
        quarantined(&owner);
    }
    let mut owner = retained(Algorithm::Sha256);
    owner.sequence = u64::MAX;
    assert_eq!(owner.rehash(0, 2), Err(Error::Sequence));
    quarantined(&owner);
    for identity in [0, 7, 511, 0x1000, 0x1180, 0x1200, u64::MAX] {
        let mut owner = Owner::new();
        assert_eq!(owner.begin(1, identity), Err(Error::Identity));
        quarantined(&owner);
        let mut owner = retained(Algorithm::Sha256);
        assert_eq!(owner.rehash(3, identity), Err(Error::Identity));
        quarantined(&owner);
    }
}

#[test]
fn failures_cancel_and_unwind_clear_retained_output() {
    for algorithm in algorithms() {
        let mut owner = retained(algorithm);
        assert_eq!(
            owner.export_public(3, algorithm.encode(), |_| false),
            Err(Error::Copy)
        );
        quarantined(&owner);
        let mut owner = retained(algorithm);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ =
                    owner.export_public(3, algorithm.encode(), |_| panic!("injected copy unwind"));
            }))
            .is_err()
        );
        quarantined(&owner);
        let mut owner = retained(algorithm);
        assert_eq!(
            owner.export_public(3, 0, |_| panic!("must not export")),
            Err(Error::Identity)
        );
        quarantined(&owner);
        let mut owner = retained(algorithm);
        owner.cancel(3).unwrap();
        assert_eq!(owner.output, [0; 64]);
        owner.begin(4, algorithm.encode()).unwrap();
        owner.update(5, b"secret").unwrap();
        owner.cancel(6).unwrap();
        assert_eq!(owner.output, [0; 64]);
        assert!(owner.state.is_none());
    }
}

#[test]
fn invalid_tail_oversize_terminal_use_and_wrong_phase_fail_closed() {
    for retained in [false, true] {
        let mut owner = Owner::new();
        owner.begin(1, 2).unwrap();
        if retained {
            owner.finish(2, b"abc", 8).unwrap();
        }
        let sequence = if retained { 3 } else { 2 };
        assert_eq!(owner.begin(sequence, 4), Err(Error::State));
        quarantined(&owner);
    }
    for (input, last) in [(&[1][..], 1), (&[][..], 1), (&[0][..], 0), (&[0][..], 9)] {
        let mut owner = Owner::new();
        owner.begin(1, 2).unwrap();
        owner.update(2, b"secret").unwrap();
        assert_eq!(owner.finish(3, input, last), Err(Error::Bits));
        quarantined(&owner);
    }
    for finishing in [false, true] {
        let mut owner = Owner::new();
        owner.begin(1, 4).unwrap();
        let result = if finishing {
            owner.finish(2, &[42; 1025], 8)
        } else {
            owner.update(2, &[42; 1025])
        };
        assert_eq!(result, Err(Error::Length));
        quarantined(&owner);
    }
    let mut owner = retained(Algorithm::Sha256);
    assert_eq!(owner.update(3, b"late"), Err(Error::State));
    quarantined(&owner);
    assert_eq!(owner.begin(4, 2), Err(Error::State));
    let mut owner = Owner::new();
    owner.begin(1, 2).unwrap();
    assert_eq!(
        owner.export_public(2, 2, |_| panic!("must not export")),
        Err(Error::State)
    );
    quarantined(&owner);
}

#[test]
fn public_identities_roundtrip_and_never_alias_general_parameters() {
    for algorithm in algorithms() {
        assert_eq!(Algorithm::decode(algorithm.encode()), Ok(algorithm));
        assert!((1..=64).contains(&algorithm.width()));
    }
    assert_ne!(Algorithm::decode(5), Algorithm::decode(0x10e0));
    assert_ne!(Algorithm::decode(6), Algorithm::decode(0x1100));
}

// Independent Python oracle cases are added to a generated copy by the build.
