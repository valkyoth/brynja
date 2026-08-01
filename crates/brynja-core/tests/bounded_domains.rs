//! Boundary and failure tests for the v0.6 bounded domains.

use core::mem::size_of;

use brynja_core::{BoundedU64, BoundedUsize, Count, Epoch, Length, NumericError, SequenceNumber};

const CONST_COUNT: Count<8> = match Count::new(3) {
    Ok(value) => value,
    Err(_) => Count::ZERO,
};
const CONST_LENGTH: Length<16> = match Length::new(12) {
    Ok(value) => value,
    Err(_) => Length::ZERO,
};
const CONST_SEQUENCE: SequenceNumber<4> = match SequenceNumber::new(2) {
    Ok(value) => value,
    Err(_) => SequenceNumber::ZERO,
};
const CONST_EPOCH: Epoch<4> = match Epoch::new(2) {
    Ok(value) => value,
    Err(_) => Epoch::ZERO,
};

#[test]
fn bounded_integer_boundaries_are_exact() {
    assert_eq!(format!("{:?}", NumericError::Overflow), "Overflow");

    for raw in 0_u64..=260 {
        let value = BoundedU64::<255>::new(raw);
        assert_eq!(value.is_ok(), raw <= 255);
        if let Ok(value) = value {
            assert_eq!(value.get(), raw);
            assert_eq!(value.remaining(), 255_u64.saturating_sub(raw));
        }
    }

    assert!(matches!(
        BoundedU64::<10>::new(11),
        Err(NumericError::AboveMaximum)
    ));
    assert!(matches!(
        BoundedUsize::<10>::new(11),
        Err(NumericError::AboveMaximum)
    ));
    assert_eq!(BoundedU64::<0>::MINIMUM.get(), 0);
    assert_eq!(BoundedUsize::<0>::MINIMUM.get(), 0);
}

#[test]
fn bounded_arithmetic_never_wraps_or_saturates() {
    let value = BoundedU64::<10>::new(6);
    assert!(value.is_ok());
    if let Ok(value) = value {
        let sum = value.checked_add(4);
        assert!(sum.is_ok());
        if let Ok(sum) = sum {
            assert_eq!(sum.get(), 10);
        }
        assert!(matches!(
            value.checked_add(5),
            Err(NumericError::AboveMaximum)
        ));
        assert!(matches!(
            value.checked_mul(2),
            Err(NumericError::AboveMaximum)
        ));
        assert!(matches!(value.checked_sub(7), Err(NumericError::Underflow)));
        assert_eq!(value.get(), 6);
    }

    let maximum = BoundedU64::<{ u64::MAX }>::new(u64::MAX);
    assert!(maximum.is_ok());
    if let Ok(maximum) = maximum {
        assert!(matches!(
            maximum.checked_add(1),
            Err(NumericError::Overflow)
        ));
        assert!(matches!(
            maximum.checked_mul(2),
            Err(NumericError::Overflow)
        ));
    }
}

#[test]
fn small_domain_arithmetic_is_exhaustive() {
    for raw in 0_usize..=16 {
        let bounded = BoundedUsize::<16>::new(raw);
        assert!(bounded.is_ok());
        if let Ok(bounded) = bounded {
            for amount in 0_usize..=20 {
                let expected_add = raw.checked_add(amount).filter(|value| *value <= 16);
                let actual_add = bounded.checked_add(amount);
                assert_eq!(actual_add.is_ok(), expected_add.is_some());
                if let (Ok(actual), Some(expected)) = (actual_add, expected_add) {
                    assert_eq!(actual.get(), expected);
                }

                let expected_mul = raw.checked_mul(amount).filter(|value| *value <= 16);
                let actual_mul = bounded.checked_mul(amount);
                assert_eq!(actual_mul.is_ok(), expected_mul.is_some());
                if let (Ok(actual), Some(expected)) = (actual_mul, expected_mul) {
                    assert_eq!(actual.get(), expected);
                }

                let expected_sub = raw.checked_sub(amount);
                let actual_sub = bounded.checked_sub(amount);
                assert_eq!(actual_sub.is_ok(), expected_sub.is_some());
                if let (Ok(actual), Some(expected)) = (actual_sub, expected_sub) {
                    assert_eq!(actual.get(), expected);
                }
            }
        }
    }
}

#[test]
fn platform_width_conversion_is_fail_closed() {
    let small = BoundedUsize::<32>::from_u64(32);
    assert!(small.is_ok());
    if let Ok(small) = small {
        assert_eq!(small.get(), 32);
    }

    let largest = BoundedUsize::<8>::from_u64(u64::MAX);
    if usize::BITS < u64::BITS {
        assert!(matches!(largest, Err(NumericError::PlatformWidth)));
    } else {
        assert!(matches!(largest, Err(NumericError::AboveMaximum)));
    }
}

#[test]
fn counts_and_lengths_remain_distinct_and_bounded() {
    assert_eq!(CONST_COUNT.get(), 3);
    assert_eq!(CONST_LENGTH.get(), 12);

    let count = Count::<8>::new(7);
    assert!(count.is_ok());
    if let Ok(count) = count {
        let next = count.checked_add(1);
        assert!(next.is_ok());
        if let Ok(next) = next {
            assert_eq!(next.get(), 8);
        }
        assert!(matches!(
            count.checked_add(2),
            Err(NumericError::AboveMaximum)
        ));
        assert_eq!(count.get(), 7);
        let reduced = count.checked_sub(7);
        assert!(reduced.is_ok());
        if let Ok(reduced) = reduced {
            assert_eq!(reduced.get(), 0);
        }
    }

    let length = Length::<16>::new(8);
    assert!(length.is_ok());
    if let Ok(length) = length {
        let doubled = length.checked_mul(2);
        assert!(doubled.is_ok());
        if let Ok(doubled) = doubled {
            assert_eq!(doubled.get(), 16);
        }
        assert!(matches!(
            length.checked_mul(3),
            Err(NumericError::AboveMaximum)
        ));
        assert_eq!(length.get(), 8);
        let extended = length.checked_add(8);
        assert!(extended.is_ok());
        if let Ok(extended) = extended {
            assert_eq!(extended.get(), 16);
        }
        let reduced = length.checked_sub(8);
        assert!(reduced.is_ok());
        if let Ok(reduced) = reduced {
            assert_eq!(reduced.get(), 0);
        }
    }

    assert!(Count::<8>::from_u64(8).is_ok());
    assert!(Length::<8>::from_u64(8).is_ok());
    assert!(matches!(
        Count::<8>::from_u64(9),
        Err(NumericError::AboveMaximum)
    ));
    assert!(matches!(
        Length::<8>::from_u64(9),
        Err(NumericError::AboveMaximum)
    ));
}

#[test]
fn sequences_and_epochs_exhaust_without_reuse() {
    assert_eq!(CONST_SEQUENCE.get(), 2);
    assert_eq!(CONST_EPOCH.get(), 2);

    let sequence = SequenceNumber::<3>::ZERO;
    let final_sequence = sequence.advance_by(3);
    assert!(final_sequence.is_ok());
    if let Ok(final_sequence) = final_sequence {
        assert_eq!(final_sequence.get(), 3);
        assert_eq!(final_sequence.remaining(), 0);
        assert!(matches!(
            final_sequence.next(),
            Err(NumericError::Exhausted)
        ));
    }
    assert_eq!(sequence.get(), 0);

    let epoch = Epoch::<2>::ZERO;
    let final_epoch = epoch.advance_by(2);
    assert!(final_epoch.is_ok());
    if let Ok(final_epoch) = final_epoch {
        assert_eq!(final_epoch.get(), 2);
        assert!(matches!(final_epoch.next(), Err(NumericError::Exhausted)));
    }
    assert_eq!(epoch.get(), 0);

    assert!(matches!(
        SequenceNumber::<3>::new(4),
        Err(NumericError::AboveMaximum)
    ));
    assert!(matches!(
        Epoch::<2>::new(3),
        Err(NumericError::AboveMaximum)
    ));
}

#[test]
fn small_sequence_and_epoch_advances_are_exhaustive() {
    for raw in 0_u64..=7 {
        let sequence = SequenceNumber::<7>::new(raw);
        assert!(sequence.is_ok());
        if let Ok(sequence) = sequence {
            for amount in 0_u64..=9 {
                let expected = raw.checked_add(amount).filter(|value| *value <= 7);
                let actual = sequence.advance_by(amount);
                assert_eq!(actual.is_ok(), expected.is_some());
                if let (Ok(actual), Some(expected)) = (actual, expected) {
                    assert_eq!(actual.get(), expected);
                }
            }
        }
    }

    for raw in 0_u16..=7 {
        let epoch = Epoch::<7>::new(raw);
        assert!(epoch.is_ok());
        if let Ok(epoch) = epoch {
            for amount in 0_u16..=9 {
                let expected = raw.checked_add(amount).filter(|value| *value <= 7);
                let actual = epoch.advance_by(amount);
                assert_eq!(actual.is_ok(), expected.is_some());
                if let (Ok(actual), Some(expected)) = (actual, expected) {
                    assert_eq!(actual.get(), expected);
                }
            }
        }
    }
}

#[test]
fn primitive_maximum_sequence_and_epoch_exhaust_exactly() {
    let sequence = SequenceNumber::<{ u64::MAX }>::new(u64::MAX);
    assert!(sequence.is_ok());
    if let Ok(sequence) = sequence {
        assert_eq!(sequence.remaining(), 0);
        assert!(matches!(sequence.next(), Err(NumericError::Exhausted)));
    }

    let epoch = Epoch::<{ u16::MAX }>::new(u16::MAX);
    assert!(epoch.is_ok());
    if let Ok(epoch) = epoch {
        assert_eq!(epoch.remaining(), 0);
        assert!(matches!(epoch.next(), Err(NumericError::Exhausted)));
    }
}

#[test]
fn bounded_domains_have_no_hidden_storage() {
    assert_eq!(size_of::<BoundedU64<10>>(), size_of::<u64>());
    assert_eq!(size_of::<BoundedUsize<10>>(), size_of::<usize>());
    assert_eq!(size_of::<Count<10>>(), size_of::<usize>());
    assert_eq!(size_of::<Length<10>>(), size_of::<usize>());
    assert_eq!(size_of::<SequenceNumber<10>>(), size_of::<u64>());
    assert_eq!(size_of::<Epoch<10>>(), size_of::<u16>());
}
