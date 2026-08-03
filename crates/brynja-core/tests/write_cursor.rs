//! Exhaustive transactional write cursor behavior.

use brynja_core::{WriteCursor, WriteError};
use core::mem::size_of;

#[test]
fn exact_write_order_and_output_identity() {
    let mut output = [0xa5_u8; 6];
    let output_address = output.as_ptr();
    let mut cursor = WriteCursor::new(&mut output);

    assert_eq!(cursor.position(), 0);
    assert_eq!(cursor.remaining_len(), 6);
    assert_eq!(cursor.written(), &[]);
    assert_eq!(cursor.write(&[1, 2]), Ok(()));
    assert_eq!(cursor.written(), &[1, 2]);
    assert_eq!(cursor.write_repeated(3, 2), Ok(()));
    assert_eq!(cursor.write_parts(&[&[4], &[], &[5]]), Ok(()));
    assert!(cursor.is_finished());

    let result = cursor.finish();
    assert!(result.is_ok());
    let Ok(finished) = result else {
        return;
    };
    assert_eq!(finished, &[1, 2, 3, 3, 4, 5]);
    assert_eq!(finished.as_ptr(), output_address);
}

#[test]
fn every_failed_single_write_preserves_position_and_output() {
    const CAPACITY: usize = 8;
    for consumed in 0..=CAPACITY {
        for requested in 0..=CAPACITY.saturating_add(1) {
            let mut output = [0x5a_u8; CAPACITY];
            let mut cursor = WriteCursor::new(&mut output);
            assert_eq!(cursor.write_repeated(0x11, consumed), Ok(()));
            let before_position = cursor.position();
            let before = cursor.written().to_owned();
            let input = [0x22_u8; CAPACITY + 1];
            let Some(input) = input.get(..requested) else {
                return;
            };
            let result = cursor.write(input);
            if requested <= CAPACITY - consumed {
                assert_eq!(result, Ok(()));
                assert_eq!(cursor.position(), before_position + requested);
            } else {
                assert_eq!(result, Err(WriteError::InsufficientCapacity));
                assert_eq!(cursor.position(), before_position);
                assert_eq!(cursor.written(), before);
                drop(cursor);
                assert_eq!(output.get(..consumed), Some(before.as_slice()));
                assert!(output.iter().skip(consumed).all(|byte| *byte == 0x5a));
            }
        }
    }
}

#[test]
fn multipart_capacity_failure_changes_no_byte() {
    let initial = [0xd3_u8; 7];
    for capacity in 0..7 {
        let mut output = initial;
        let mut cursor = WriteCursor::new(&mut output);
        assert_eq!(cursor.write_repeated(0x44, capacity), Ok(()));
        let before_position = cursor.position();
        let mut before = initial;
        let Some(prefix) = before.get_mut(..capacity) else {
            return;
        };
        prefix.fill(0x44);
        let parts: [&[u8]; 4] = [&[1, 2], &[], &[3], &[4, 5]];
        let result = cursor.write_parts(&parts);
        if capacity <= 2 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(WriteError::InsufficientCapacity));
            assert_eq!(cursor.position(), before_position);
            drop(cursor);
            assert_eq!(output, before);
        }
    }
}

#[test]
fn repeated_write_overflow_and_capacity_fail_transactionally() {
    let mut output = [0x9c_u8; 3];
    let mut cursor = WriteCursor::new(&mut output);
    assert_eq!(cursor.write(&[1]), Ok(()));
    let before_position = cursor.position();
    let before = cursor.written().to_owned();

    assert_eq!(
        cursor.write_repeated(0, usize::MAX),
        Err(WriteError::LengthOverflow)
    );
    assert_eq!(cursor.position(), before_position);
    assert_eq!(cursor.written(), before);
    assert_eq!(
        cursor.write_repeated(0, 3),
        Err(WriteError::InsufficientCapacity)
    );
    assert_eq!(cursor.position(), before_position);
    assert_eq!(cursor.written(), before);
    drop(cursor);
    assert_eq!(output, [1, 0x9c, 0x9c]);
}

#[test]
fn zero_length_transactions_are_exact_at_every_boundary() {
    let mut output = [0x33_u8; 4];
    for position in 0..=output.len() {
        let mut candidate = output;
        let mut cursor = WriteCursor::new(&mut candidate);
        assert_eq!(cursor.write_repeated(0x77, position), Ok(()));
        let before = cursor.position();
        assert_eq!(cursor.write(&[]), Ok(()));
        assert_eq!(cursor.write_parts(&[]), Ok(()));
        assert_eq!(cursor.write_parts(&[&[], &[]]), Ok(()));
        assert_eq!(cursor.write_repeated(0xff, 0), Ok(()));
        assert_eq!(cursor.position(), before);
    }
    output.fill(0x33);
}

#[test]
fn empty_output_accepts_only_empty_transactions() {
    let mut output = [];
    let mut cursor = WriteCursor::new(&mut output);
    assert_eq!(cursor.write(&[]), Ok(()));
    assert_eq!(cursor.write_parts(&[&[]]), Ok(()));
    assert_eq!(cursor.write_repeated(1, 0), Ok(()));
    assert_eq!(cursor.write(&[1]), Err(WriteError::InsufficientCapacity));
    assert_eq!(cursor.position(), 0);
    assert_eq!(cursor.finish().map(|finished| finished.len()), Ok(0));
}

#[test]
fn completion_requires_exact_capacity_use_without_mutation() {
    let mut output = [0x81_u8; 4];
    let result = {
        let mut cursor = WriteCursor::new(&mut output);
        assert_eq!(cursor.write(&[1, 2]), Ok(()));
        cursor.finish()
    };
    assert_eq!(result, Err(WriteError::TrailingCapacity));
    assert_eq!(output, [1, 2, 0x81, 0x81]);
}

#[test]
fn cursor_storage_is_borrow_and_position_only() {
    assert_eq!(
        size_of::<WriteCursor<'_>>(),
        size_of::<&mut [u8]>().saturating_add(size_of::<usize>())
    );
    assert_eq!(size_of::<WriteError>(), 1);
}

#[test]
fn errors_are_closed_and_value_free() {
    assert_eq!(
        format!("{:?}", WriteError::InsufficientCapacity),
        "InsufficientCapacity"
    );
    assert_eq!(
        format!("{:?}", WriteError::LengthOverflow),
        "LengthOverflow"
    );
    assert_eq!(
        format!("{:?}", WriteError::TrailingCapacity),
        "TrailingCapacity"
    );
}
