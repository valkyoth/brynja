//! Adapter behavior, failure, transfer, and shared modern/legacy tests.

use brynja_core::SecretRegionInitialization;
use brynja_sanitization::{SanitizationError, SanitizedSecret, SourceFailure};
use sanitization::SecretBytes;

fn secret<const N: usize>(byte: u8) -> SanitizedSecret<N> {
    match SanitizedSecret::try_from_fn(|_| byte) {
        Ok(value) => value,
        Err(_) => unreachable_for_test(),
    }
}

fn unreachable_for_test<T>() -> T {
    assert!(core::hint::black_box(false), "unreachable test state");
    loop {
        core::hint::spin_loop();
    }
}

fn use_from_any_protocol(secret: &SanitizedSecret<4>) -> u8 {
    secret.inspect(|bytes| bytes.iter().fold(0_u8, |sum, byte| sum ^ byte))
}

#[test]
fn zero_capacity_is_rejected_without_running_source() {
    let mut calls = 0_usize;
    let result = SanitizedSecret::<0>::try_from_fn(|_| {
        calls = calls.saturating_add(1);
        7
    });
    assert!(matches!(result, Err(SanitizationError::EmptySecret)));
    assert_eq!(calls, 0);
}

#[test]
fn construction_and_redacted_debug_match_fixed_storage() {
    let secret =
        match SanitizedSecret::<4>::try_from_fn(|index| u8::try_from(index).unwrap_or_default()) {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        };
    assert_eq!(secret.inspect(|bytes| *bytes), [0, 1, 2, 3]);
    assert_eq!(
        format!("{secret:?}"),
        "SanitizedSecret { len: 4, contents: \"<redacted>\" }"
    );
}

#[test]
fn every_source_failure_is_closed_and_leaves_no_owner() {
    for fail_at in 0..4 {
        let result = SanitizedSecret::<4>::try_from_fallible(|index| {
            if index == fail_at {
                Err(SourceFailure)
            } else {
                Ok(0xa5)
            }
        });
        assert!(matches!(result, Err(SanitizationError::SourceFailure)));
    }
}

#[test]
fn replacement_is_transactional_at_every_failure_boundary() {
    for fail_at in 0..4 {
        let mut secret = secret::<4>(7);
        let result = secret.try_replace_from_fallible(|index| {
            if index == fail_at {
                Err(SourceFailure)
            } else {
                Ok(9)
            }
        });
        assert_eq!(result, Err(SanitizationError::SourceFailure));
        assert_eq!(secret.inspect(|bytes| *bytes), [7; 4]);
    }
}

#[test]
fn transfer_requires_exact_capacity_and_each_owner_clears() {
    for length in 0..=6 {
        let secret = secret::<4>(0x42);
        let mut region = [0xa5_u8; 6];
        let selected = match region.get_mut(..length) {
            Some(value) => value,
            None => return assert!(core::hint::black_box(false)),
        };
        {
            match secret.copy_into_brynja(selected) {
                Ok(owner) => {
                    assert_eq!(length, 4);
                    assert_eq!(owner.expose(), &[0x42; 4]);
                    drop(owner);
                }
                Err(error) if length == 0 => {
                    assert_eq!(error, SanitizationError::RegionInitialization);
                }
                Err(error) => assert_eq!(error, SanitizationError::RegionLengthMismatch),
            }
        }
        assert!(selected.iter().all(|byte| *byte == 0));
        secret.clear();
    }
}

#[test]
fn reverse_copy_is_explicit_and_length_checked() {
    let mut region = [0_u8; 4];
    let mut initialization = match SecretRegionInitialization::begin(&mut region) {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    assert_eq!(initialization.write(&[1, 2, 3, 4]), Ok(()));
    let owner = match initialization.finish() {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    let copied = match SanitizedSecret::<4>::try_copy_from_brynja(&owner) {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    assert_eq!(copied.inspect(|bytes| *bytes), [1, 2, 3, 4]);
    assert!(matches!(
        SanitizedSecret::<3>::try_copy_from_brynja(&owner),
        Err(SanitizationError::RegionLengthMismatch)
    ));
    copied.clear();
    drop(owner);
    assert_eq!(region, [0; 4]);
}

#[test]
fn modern_and_legacy_callers_share_one_identical_contract() {
    let modern = secret::<4>(3);
    let legacy = secret::<4>(3);
    assert_eq!(
        use_from_any_protocol(&modern),
        use_from_any_protocol(&legacy)
    );
}

#[test]
fn explicit_clear_and_drop_are_safe_after_inspection() {
    let explicit = secret::<32>(0xa5);
    assert!(explicit.inspect(|bytes| bytes.iter().all(|byte| *byte == 0xa5)));
    explicit.clear();
    let dropped = secret::<32>(0x5a);
    assert!(dropped.inspect(|bytes| bytes.iter().all(|byte| *byte == 0x5a)));
    drop(dropped);
}

#[test]
fn adapter_matches_exact_upstream_fixed_storage_for_generated_inputs() {
    for seed in 0_u8..=31 {
        let adapter = match SanitizedSecret::<32>::try_from_fn(|index| {
            seed.wrapping_add(u8::try_from(index).unwrap_or_default())
        }) {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        };
        let upstream = SecretBytes::<32>::from_fn(|index| {
            seed.wrapping_add(u8::try_from(index).unwrap_or_default())
        });
        assert!(adapter.inspect(|left| upstream.expose_secret(|right| left == right)));
    }
}

#[test]
fn unwind_during_replacement_preserves_original_owner() {
    let mut secret = secret::<4>(0x33);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = secret.try_replace_from_fallible(|index| {
            assert!(index != 2, "injected unwind");
            Ok(0x44)
        });
    }));
    assert!(result.is_err());
    assert_eq!(secret.inspect(|bytes| *bytes), [0x33; 4]);
}
