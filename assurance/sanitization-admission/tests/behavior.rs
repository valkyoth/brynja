use brynja_sanitization_admission_fixture::{CandidateError, CandidateSecret};
use std::{format, panic};

fn visible(secret: &CandidateSecret<4>) -> [u8; 4] {
    secret.inspect(|bytes| *bytes)
}

fn candidate() -> CandidateSecret<4> {
    match CandidateSecret::<4>::try_from_fn(|index| index as u8 + 1) {
        Ok(secret) => secret,
        Err(_) => std::process::abort(),
    }
}

#[test]
fn empty_storage_is_rejected() {
    assert_eq!(
        CandidateSecret::<0>::try_from_fn(|_| 1).err(),
        Some(CandidateError::EmptySecret)
    );
}

#[test]
fn explicit_clear_covers_the_complete_fixed_storage() {
    let mut secret = candidate();
    secret.clear();
    assert_eq!(visible(&secret), [0; 4]);
}

#[test]
fn failed_construction_returns_only_a_closed_error() {
    let result = CandidateSecret::<4>::try_from_fallible(|index| {
        if index == 2 {
            Err([0xA5; 16])
        } else {
            Ok(index as u8)
        }
    });
    assert_eq!(result.err(), Some(CandidateError::SourceFailure));
}

#[test]
fn failed_replacement_preserves_the_old_value() {
    let mut secret = candidate();
    let before = visible(&secret);
    let replaced = secret.try_replace_from_fallible(|index| {
        if index == 3 {
            Err(())
        } else {
            Ok(0xA0 + index as u8)
        }
    });
    assert_eq!(replaced, Err(CandidateError::SourceFailure));
    assert_eq!(visible(&secret), before);
}

#[test]
fn unwinding_replacement_preserves_the_old_value() {
    let mut secret = candidate();
    let before = visible(&secret);
    let unwind = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = secret.try_replace_from_fallible::<()>(|index| {
            if index == 2 {
                panic::panic_any(());
            }
            Ok(0xB0 + index as u8)
        });
    }));
    assert!(unwind.is_err());
    assert_eq!(visible(&secret), before);
}

#[test]
fn diagnostics_are_redacted() {
    let secret = match CandidateSecret::<4>::try_from_fn(|index| 0xC0 + index as u8) {
        Ok(secret) => secret,
        Err(_) => std::process::abort(),
    };
    let diagnostic = format!("{secret:?}");
    assert!(diagnostic.contains("<redacted>"));
    assert!(!diagnostic.contains("192"));
}
