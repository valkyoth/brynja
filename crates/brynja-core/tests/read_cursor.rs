//! Exhaustive borrowed read cursor behavior.

use brynja_core::{Length, ReadCursor, ReadError};
use core::mem::size_of;

const BODY_LENGTH: Length<4> = match Length::new(2) {
    Ok(length) => length,
    Err(_) => Length::ZERO,
};

fn parse_six(input: &[u8]) -> Result<(), ReadError> {
    let mut cursor = ReadCursor::new(input);
    let _header = cursor.take_array::<1>()?;
    let _body = cursor.take_length(BODY_LENGTH)?;
    let _trailer = cursor.take_array::<3>()?;
    cursor.finish()
}

#[test]
fn exact_consumption_and_borrow_identity() {
    let input = [10_u8, 20, 30, 40, 50];
    let mut cursor = ReadCursor::new(&input);

    assert_eq!(cursor.position(), 0);
    assert_eq!(cursor.remaining_len(), input.len());
    assert_eq!(cursor.remaining().as_ptr(), input.as_ptr());

    let first = cursor.take(2);
    assert_eq!(first, Ok(&[10, 20][..]));
    let Ok(first) = first else {
        return;
    };
    assert_eq!(first.as_ptr(), input.as_ptr());
    assert_eq!(cursor.position(), 2);

    let rest = cursor.take_array::<3>();
    assert_eq!(rest, Ok(&[30, 40, 50]));
    let Ok(rest) = rest else {
        return;
    };
    assert_eq!(rest.as_ptr(), input.as_ptr().wrapping_add(2));
    assert!(cursor.is_finished());
    assert_eq!(cursor.remaining(), &[]);
    assert_eq!(cursor.finish(), Ok(()));
}

#[test]
fn truncation_at_every_byte_is_rejected() {
    let complete = [1_u8, 2, 3, 4, 5, 6];
    for length in 0..complete.len() {
        let Some(prefix) = complete.get(..length) else {
            return;
        };
        assert_eq!(parse_six(prefix), Err(ReadError::Truncated));
    }
    assert_eq!(parse_six(&complete), Ok(()));
    for suffix in 1..=complete.len() {
        let mut extended = [0_u8; 12];
        for (output, input) in extended.iter_mut().zip(complete) {
            *output = input;
        }
        let end = complete.len().saturating_add(suffix);
        let Some(candidate) = extended.get(..end) else {
            return;
        };
        assert_eq!(parse_six(candidate), Err(ReadError::TrailingData),);
    }
}

#[test]
fn every_failed_range_preserves_position() {
    let input = [0_u8; 8];
    for consumed in 0..=input.len() {
        for requested in 0..=input.len().saturating_add(1) {
            let mut cursor = ReadCursor::new(&input);
            assert!(cursor.take(consumed).is_ok());
            let before = cursor.position();
            let remaining_before = cursor.remaining();
            let result = cursor.take(requested);
            if requested <= input.len() - consumed {
                assert_eq!(result.map(|bytes| bytes.len()), Ok(requested));
                assert_eq!(cursor.position(), before.saturating_add(requested));
            } else {
                assert_eq!(result, Err(ReadError::Truncated));
                assert_eq!(cursor.position(), before);
                assert_eq!(cursor.remaining(), remaining_before);
            }
        }
    }
}

#[test]
fn arithmetic_overflow_is_distinct_and_transactional() {
    let input = [7_u8];
    let mut cursor = ReadCursor::new(&input);
    assert!(cursor.take(1).is_ok());
    let before = cursor.position();
    assert_eq!(cursor.take(usize::MAX), Err(ReadError::LengthOverflow));
    assert_eq!(cursor.position(), before);
    assert!(cursor.is_finished());
}

#[test]
fn typed_and_fixed_failures_preserve_the_remaining_suffix() {
    let input = [1_u8, 2, 3];
    let mut fixed = ReadCursor::new(&input);
    assert!(fixed.take(1).is_ok());
    let fixed_before = fixed.remaining();
    assert_eq!(fixed.take_array::<3>(), Err(ReadError::Truncated));
    assert_eq!(fixed.position(), 1);
    assert_eq!(fixed.remaining(), fixed_before);

    let length = Length::<8>::new(4);
    assert!(length.is_ok());
    let Ok(length) = length else {
        return;
    };
    let mut typed = ReadCursor::new(&input);
    let typed_before = typed.remaining();
    assert_eq!(typed.take_length(length), Err(ReadError::Truncated));
    assert_eq!(typed.position(), 0);
    assert_eq!(typed.remaining(), typed_before);
}

#[test]
fn zero_length_reads_are_exact_at_every_boundary() {
    let input = [1_u8, 2, 3];
    for position in 0..=input.len() {
        let mut cursor = ReadCursor::new(&input);
        assert!(cursor.take(position).is_ok());
        let empty = cursor.take_array::<0>();
        assert!(empty.is_ok());
        let Ok(empty) = empty else {
            return;
        };
        assert!(empty.is_empty());
        assert_eq!(cursor.position(), position);
    }
}

#[test]
fn empty_input_has_exact_zero_length_behavior() {
    let input = [];
    let mut cursor = ReadCursor::new(&input);
    assert_eq!(cursor.remaining(), &[]);
    assert_eq!(cursor.take(0), Ok(&[][..]));
    assert_eq!(cursor.take(1), Err(ReadError::Truncated));
    assert_eq!(cursor.position(), 0);
    assert_eq!(cursor.finish(), Ok(()));
}

#[test]
fn typed_lengths_consume_only_their_value() {
    let input = [1_u8, 2, 3, 4];
    let mut cursor = ReadCursor::new(&input);
    let length = Length::<8>::new(3);
    assert!(length.is_ok());
    let Ok(length) = length else {
        return;
    };
    assert_eq!(cursor.take_length(length), Ok(&[1, 2, 3][..]));
    assert_eq!(cursor.remaining(), &[4]);
    assert_eq!(cursor.finish(), Err(ReadError::TrailingData));
}

#[test]
fn cursor_storage_is_borrow_and_position_only() {
    assert_eq!(
        size_of::<ReadCursor<'_>>(),
        size_of::<&[u8]>().saturating_add(size_of::<usize>())
    );
    assert_eq!(size_of::<ReadError>(), 1);
}

#[test]
fn errors_are_closed_and_value_free() {
    assert_eq!(format!("{:?}", ReadError::Truncated), "Truncated");
    assert_eq!(format!("{:?}", ReadError::LengthOverflow), "LengthOverflow");
    assert_eq!(format!("{:?}", ReadError::TrailingData), "TrailingData");
}
