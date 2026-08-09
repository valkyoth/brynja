//! Owned-memory zeroization and affine secret-region tests.

use brynja_core::{
    OwnedSecretRegion, SecretMemoryError, SecretRegionInitialization, clear_owned_region,
};

fn initialize<'a>(region: &'a mut [u8], input: &[u8]) -> OwnedSecretRegion<'a> {
    let mut initialization = match SecretRegionInitialization::begin(region) {
        Ok(value) => value,
        Err(_) => return unreachable_for_test(),
    };
    assert_eq!(initialization.write(input), Ok(()));
    match initialization.finish() {
        Ok(owner) => owner,
        Err(_) => unreachable_for_test(),
    }
}

fn incomplete_finish(region: &mut [u8], input: &[u8]) -> SecretMemoryError {
    let mut initialization = match SecretRegionInitialization::begin(region) {
        Ok(value) => value,
        Err(_) => return unreachable_for_test(),
    };
    assert_eq!(initialization.write(input), Ok(()));
    match initialization.finish() {
        Err(error) => error,
        Ok(owner) => {
            drop(owner);
            unreachable_for_test()
        }
    }
}

fn unreachable_for_test<T>() -> T {
    assert!(core::hint::black_box(false), "unreachable test state");
    loop {
        core::hint::spin_loop();
    }
}

#[test]
fn direct_clear_covers_every_byte_and_small_length() {
    for length in 1..=64 {
        let mut region = [0xa5_u8; 64];
        let selected = match region.get_mut(..length) {
            Some(value) => value,
            None => return assert!(core::hint::black_box(false)),
        };
        let _completion = match clear_owned_region(selected) {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        };
        assert!(selected.iter().all(|byte| *byte == 0));
        assert!(region.iter().skip(length).all(|byte| *byte == 0xa5));
    }
}

#[test]
fn empty_region_is_rejected_without_a_completion_claim() {
    let mut empty = [];
    assert!(matches!(
        clear_owned_region(&mut empty),
        Err(SecretMemoryError::EmptyRegion)
    ));
    assert!(matches!(
        SecretRegionInitialization::begin(&mut empty),
        Err(SecretMemoryError::EmptyRegion)
    ));
}

#[test]
fn every_initialization_split_admits_only_complete_readable_state() {
    let secret = [1_u8, 2, 3, 4];
    for split in 0..=secret.len() {
        let mut region = [0xa5_u8; 4];
        {
            let mut initialization = match SecretRegionInitialization::begin(&mut region) {
                Ok(value) => value,
                Err(_) => return assert!(core::hint::black_box(false)),
            };
            let first = match secret.get(..split) {
                Some(value) => value,
                None => return assert!(core::hint::black_box(false)),
            };
            let second = match secret.get(split..) {
                Some(value) => value,
                None => return assert!(core::hint::black_box(false)),
            };
            assert_eq!(initialization.write(first), Ok(()));
            assert_eq!(initialization.write(second), Ok(()));
            let owner = match initialization.finish() {
                Ok(value) => value,
                Err(_) => return assert!(core::hint::black_box(false)),
            };
            assert_eq!(owner.expose(), secret);
        }
        assert_eq!(region, [0_u8; 4]);
    }
}

#[test]
fn every_incomplete_finish_clears_the_complete_region() {
    let secret = [1_u8, 2, 3, 4];
    for prefix in 0..secret.len() {
        let mut region = [0xa5_u8; 4];
        let input = match secret.get(..prefix) {
            Some(value) => value,
            None => return assert!(core::hint::black_box(false)),
        };
        let error = incomplete_finish(&mut region, input);
        assert_eq!(error, SecretMemoryError::IncompleteInitialization);
        assert_eq!(region, [0_u8; 4]);
    }
}

#[test]
fn failed_write_is_transactional_and_owner_drop_clears() {
    let mut region = [0xa5_u8; 4];
    {
        let mut initialization = match SecretRegionInitialization::begin(&mut region) {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        };
        assert_eq!(initialization.write(&[1, 2]), Ok(()));
        assert_eq!(
            initialization.write(&[9, 9, 9]),
            Err(SecretMemoryError::InsufficientCapacity)
        );
        assert_eq!(initialization.write(&[3, 4]), Ok(()));
        let owner = match initialization.finish() {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        };
        assert_eq!(owner.expose(), &[1, 2, 3, 4]);
    }
    assert_eq!(region, [0_u8; 4]);
}

#[test]
fn begin_and_partial_drop_clear_preexisting_and_partial_bytes() {
    let mut preexisting = [0xa5_u8; 4];
    drop(match SecretRegionInitialization::begin(&mut preexisting) {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    });
    assert_eq!(preexisting, [0_u8; 4]);

    let mut partial = [0xa5_u8; 4];
    {
        let mut initialization = match SecretRegionInitialization::begin(&mut partial) {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        };
        assert_eq!(initialization.write(&[7, 8]), Ok(()));
    }
    assert_eq!(partial, [0_u8; 4]);
}

#[test]
fn explicit_clear_consumes_owner_and_clears_exact_region() {
    let mut region = [0xa5_u8; 4];
    let owner = initialize(&mut region, &[1, 2, 3, 4]);
    let _completion = owner.clear();
    assert_eq!(region, [0_u8; 4]);
}
