use super::*;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};

pub(super) fn make_authority() -> Authority {
    Authority::new(Kernel::X86Sha256).unwrap()
}
fn expected(algorithm: Algorithm, input: &[u8], last: u8) -> Vec<u8> {
    let bits = BitString::new(input, last).unwrap();
    match algorithm {
        Algorithm::Sha224 => brynja_hash_sha2::sha224_bits(bits)
            .unwrap()
            .as_bytes()
            .to_vec(),
        Algorithm::Sha256 => brynja_hash_sha2::sha256_bits(bits)
            .unwrap()
            .as_bytes()
            .to_vec(),
        _ => unreachable!(),
    }
}
fn check_dead(owner: &Owner<'_>) {
    assert_eq!(owner.phase, Phase::Quarantined);
    assert!(owner.state.is_none());
    assert!(owner.algorithm.is_none());
    assert_eq!(owner.output, [0; 32]);
    assert!(owner.authority.session().is_err());
}
fn retained(authority: &Authority) -> Owner<'_> {
    let mut owner = Owner::new(authority).unwrap();
    owner.begin(1, 2).unwrap();
    owner.finish(2, b"abc", 8).unwrap();
    owner
}

#[test]
fn fragmented_bit_inputs_use_the_hardware_route() {
    for algorithm in [Algorithm::Sha224, Algorithm::Sha256] {
        for length in [
            0_usize, 1, 7, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1023, 1024, 2049,
        ] {
            for last in if length == 0 { 0..=0 } else { 1..=8 } {
                let authority = make_authority();
                let mut owner = Owner::new(&authority).unwrap();
                let mut message: Vec<_> = (0..length).map(|i| (i as u8).wrapping_mul(17)).collect();
                if let Some(byte) = message.last_mut() {
                    *byte &= 0xff << (8 - last);
                }
                let expected = expected(algorithm, &message, last);
                owner.begin(1, algorithm.encode()).unwrap();
                let state = owner.state.as_ref().unwrap();
                let route = match state {
                    State::A(s) => s.report().route,
                    State::B(s) => s.report().route,
                };
                assert_eq!(
                    route,
                    brynja_hash_sha2::execution::Route::Static(Kernel::X86Sha256)
                );
                let split = length.saturating_sub(1);
                let mut sequence = 1;
                for chunk in message[..split].chunks(37) {
                    sequence += 1;
                    owner.update(sequence, &[]).unwrap();
                    sequence += 1;
                    owner.update(sequence, chunk).unwrap();
                }
                sequence += 1;
                owner.finish(sequence, &message[split..], last).unwrap();
                assert_eq!(owner.output[..algorithm.width()], expected);
                sequence += 1;
                owner
                    .export_public(sequence, algorithm.encode(), |bytes| {
                        assert_eq!(bytes, expected);
                        true
                    })
                    .unwrap();
                assert_eq!(owner.output, [0; 32]);
                assert_eq!(owner.phase, Phase::Empty);
            }
        }
    }
}

#[test]
fn retained_composition_and_clean_cancellation_reuse() {
    for first in [Algorithm::Sha224, Algorithm::Sha256] {
        for next in [Algorithm::Sha224, Algorithm::Sha256] {
            let authority = make_authority();
            let mut owner = Owner::new(&authority).unwrap();
            owner.begin(1, first.encode()).unwrap();
            owner.finish(2, b"abc", 8).unwrap();
            let reference = expected(next, &expected(first, b"abc", 8), 8);
            owner.rehash(3, next.encode()).unwrap();
            assert_eq!(owner.output[..next.width()], reference);
            owner.cancel(4).unwrap();
            owner.begin(5, first.encode()).unwrap();
            owner.update(6, b"new secret input").unwrap();
            owner.cancel(7).unwrap();
            assert_eq!(owner.output, [0; 32]);
            assert!(authority.session().is_ok());
        }
    }
}

#[test]
fn wide_and_unknown_identities_never_fallback() {
    for identity in [0, 3, 4, 5, 6, 7, 0x1001, 0x1180, 0x11ff, u64::MAX] {
        let authority = make_authority();
        let mut owner = Owner::new(&authority).unwrap();
        assert_eq!(owner.begin(1, identity), Err(Error::Identity));
        check_dead(&owner);
        let authority = make_authority();
        let mut owner = retained(&authority);
        assert_eq!(owner.rehash(3, identity), Err(Error::Identity));
        check_dead(&owner);
    }
}

#[test]
fn copy_failure_unwind_and_wrong_identity_clear_and_revoke() {
    for failure in 0..4 {
        let authority = make_authority();
        let mut owner = retained(&authority);
        let result = catch_unwind(AssertUnwindSafe(|| {
            owner.export_public(3, if failure == 2 { 1 } else { 2 }, |_| match failure {
                0 => false,
                1 => panic!("fixed test unwind"),
                3 => {
                    authority.quarantine();
                    true
                }
                _ => true,
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        check_dead(&owner);
    }
}

#[test]
fn revocation_rejects_even_empty_updates_and_retained_export() {
    for step in 0..5 {
        let authority = make_authority();
        let mut owner = Owner::new(&authority).unwrap();
        owner.begin(1, 2).unwrap();
        if step >= 2 {
            owner.finish(2, b"abc", 8).unwrap();
        }
        authority.quarantine();
        let result = match step {
            0 => owner.update(2, &[]),
            1 => owner.finish(2, &[], 0),
            2 => owner.rehash(3, 2),
            3 => owner.export_public(3, 2, |_| panic!("revoked output callback")),
            _ => owner.cancel(3),
        };
        assert_eq!(result, Err(Error::Backend));
        check_dead(&owner);
    }
}

#[test]
fn replay_wrong_phase_overflow_and_bad_tail_destroy_state() {
    for sequence in [0, 1, 2, 4, u64::MAX] {
        let authority = make_authority();
        let mut owner = retained(&authority);
        assert_eq!(owner.rehash(sequence, 2), Err(Error::Sequence));
        check_dead(&owner);
    }
    let authority = make_authority();
    let mut owner = retained(&authority);
    owner.sequence = u64::MAX;
    assert_eq!(owner.rehash(0, 2), Err(Error::Sequence));
    check_dead(&owner);
    for step in 0..5 {
        let authority = make_authority();
        let mut owner = Owner::new(&authority).unwrap();
        owner.begin(1, 2).unwrap();
        let result = match step {
            0 => owner.begin(2, 2),
            1 => owner.update(2, &[0; 1025]),
            2 => owner.finish(2, &[0; 1025], 8),
            3 => owner.finish(2, &[1], 1),
            _ => owner.finish(2, &[], 8),
        };
        assert!(result.is_err());
        check_dead(&owner);
    }
}

#[test]
fn revoked_or_wrong_kernel_cannot_construct() {
    let authority = make_authority();
    authority.quarantine();
    assert!(matches!(Owner::new(&authority), Err(Error::Backend)));
    #[cfg(target_feature = "avx2")]
    {
        let wrong = Authority::new(Kernel::X86Keccak).unwrap();
        assert!(matches!(Owner::new(&wrong), Err(Error::Backend)));
    }
}
