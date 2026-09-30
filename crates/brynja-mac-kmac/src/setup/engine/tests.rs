use super::*;
use brynja_hash_sha3::HardenedCshake128Setup;
extern crate std;
use std::boxed::Box;
fn must<T, E: Send + 'static>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|e| std::panic::resume_unwind(Box::new(e)))
}
fn bits(bytes: &[u8], valid: u8) -> Fips202BitString<'_> {
    must(Fips202BitString::new(bytes, valid))
}
fn cleared(s: &Setup<HardenedCshake128Setup>) {
    assert!(s.phase == Phase::Dead);
    assert_eq!(s.pending, [0]);
    assert_eq!(s.used, 0);
    assert_eq!(s.remaining, 0);
    assert_eq!(s.key_bits, 0);
    assert_eq!(s.emitted, 0);
    assert_eq!(s.expected, 0);
}
#[test]
fn rejected_incomplete_excess_and_wrong_phase_are_terminal() {
    assert!(Setup::<HardenedCshake128Setup>::new(127, 0).is_err());
    assert!(Setup::<HardenedCshake128Setup>::new(128, u128::MAX).is_err());
    for case in 0..6 {
        let mut s = must(Setup::<HardenedCshake128Setup>::new(128, 1));
        let result = match case {
            0 => s.finish_custom(),
            1 => s.key(bits(&[1], 1)),
            2 => s.custom(bits(&[3], 2)),
            _ => {
                must(s.custom(bits(&[1], 1)));
                must(s.finish_custom());
                match case {
                    3 => s.finish().map(|_| ()),
                    4 => s.key(bits(&[1; 17], 8)),
                    _ => s.custom(bits(&[], 0)),
                }
            }
        };
        assert!(result.is_err());
        cleared(&s);
        assert!(s.finish_custom().is_err());
        cleared(&s);
    }
}
#[test]
fn exact_completion_and_unwind_clear_source() {
    for corrupt in [false, true] {
        let mut s = must(Setup::<HardenedCshake128Setup>::new(129, 0));
        must(s.finish_custom());
        must(s.key(bits(&[0xa5; 16], 8)));
        must(s.key(bits(&[1], 1)));
        if corrupt {
            s.expected = s.expected.saturating_add(1);
        }
        assert_eq!(s.finish().is_ok(), !corrupt);
        cleared(&s);
        assert!(s.finish().is_err());
    }
    let mut s = must(Setup::<HardenedCshake128Setup>::new(129, 0));
    must(s.finish_custom());
    must(s.key(bits(&[1], 1)));
    assert_ne!(s.pending, [0]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _op = Operation {
                setup: &mut s,
                complete: false,
            };
            std::panic::resume_unwind(Box::new(()));
        }))
        .is_err()
    );
    cleared(&s);
}
