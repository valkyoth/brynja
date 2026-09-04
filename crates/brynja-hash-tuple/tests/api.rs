//! Public TupleHash state, boundary, and cleanup acceptance.

use brynja_hash_tuple::{
    Fips202BitString, Fips202Output, HardenedTupleHash128, HardenedTupleHashXof128, TupleHash128,
    TupleHashError, TupleHashPublicDeclassification, TupleHashXof128, tuple_hash_xof128_bits,
    tuple_hash128,
};

#[test]
fn tuple_boundaries_order_and_empty_items_are_distinct() {
    let cases: &[&[&[u8]]] = &[
        &[b"ab", b"c"],
        &[b"a", b"bc"],
        &[b"abc"],
        &[b"c", b"ab"],
        &[b"", b"abc"],
    ];
    let mut outputs = [[0_u8; 32]; 5];
    for (items, output) in cases.iter().zip(outputs.iter_mut()) {
        assert_eq!(tuple_hash128(items, b"", output), Ok(()));
    }
    for (index, output) in outputs.iter().enumerate() {
        for distinct in outputs.iter().skip(index.saturating_add(1)) {
            assert_ne!(output, distinct);
        }
    }
}

#[test]
fn exact_length_streaming_matches_whole_items() {
    let mut whole = TupleHash128::new(b"partition").ok();
    let mut streamed = TupleHash128::new(b"partition").ok();
    assert!(whole.is_some());
    assert!(streamed.is_some());
    let Some(mut whole) = whole.take() else {
        return;
    };
    let Some(mut streamed) = streamed.take() else {
        return;
    };
    assert_eq!(whole.push_item(b"abcdef"), Ok(()));
    {
        let writer = streamed.begin_item(48);
        assert!(writer.is_ok());
        let Ok(mut writer) = writer else { return };
        assert_eq!(writer.update(b"ab"), Ok(()));
        assert_eq!(writer.update(b"cdef"), Ok(()));
        assert_eq!(writer.remaining_bits(), 0);
        assert_eq!(writer.finish(), Ok(()));
    }
    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];
    assert_eq!(whole.finalize(&mut first), Ok(()));
    assert_eq!(streamed.finalize(&mut second), Ok(()));
    assert_eq!(first, second);
    assert_eq!(whole.item_count(), 0);
    assert_eq!(streamed.item_count(), 0);
}

#[test]
fn abandoned_or_incomplete_items_fail_closed() {
    let mut state = TupleHash128::new(b"").ok();
    assert!(state.is_some());
    let Some(mut state) = state.take() else {
        return;
    };
    {
        let writer = state.begin_item(16);
        assert!(writer.is_ok());
        let Ok(mut writer) = writer else { return };
        assert_eq!(writer.update(b"a"), Ok(()));
        assert_eq!(writer.finish(), Err(TupleHashError::IncompleteItem));
    }
    assert_eq!(
        state.push_item(b"later"),
        Err(TupleHashError::ItemAbandoned)
    );
    assert_eq!(
        state.finalize(&mut [0_u8; 32]),
        Err(TupleHashError::ItemAbandoned)
    );
}

#[test]
fn forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch() {
    let state = TupleHash128::new(b"");
    assert!(state.is_ok());
    let Ok(mut state) = state else { return };
    let mut writer = match state.begin_item(16) {
        Ok(writer) => writer,
        Err(error) => {
            assert_eq!(Some(error), None);
            return;
        }
    };
    assert_eq!(writer.update(b"a"), Ok(()));
    core::mem::forget(writer);
    assert_eq!(
        state.finalize(&mut [0_u8; 32]),
        Err(TupleHashError::ItemAbandoned)
    );

    let state = TupleHash128::new(b"");
    assert!(state.is_ok());
    let Ok(mut state) = state else { return };
    {
        let writer = match state.begin_item(8) {
            Ok(writer) => writer,
            Err(error) => {
                assert_eq!(Some(error), None);
                return;
            }
        };
        let _forgotten = core::mem::ManuallyDrop::new(writer);
    }
    assert_eq!(
        state.finalize(&mut [0_u8; 32]),
        Err(TupleHashError::ItemAbandoned)
    );
}

#[test]
fn arbitrary_bit_items_and_outputs_are_canonical() {
    let item = Fips202BitString::new(&[0b0001_0101], 5);
    let custom = Fips202BitString::new(&[], 0);
    assert!(item.is_ok());
    assert!(custom.is_ok());
    let (Ok(item), Ok(custom)) = (item, custom) else {
        return;
    };
    let mut state = TupleHash128::new_bits(custom).ok();
    assert!(state.is_some());
    let Some(mut state) = state.take() else {
        return;
    };
    assert_eq!(state.push_item_bits(item), Ok(()));
    let mut bytes = [0_u8; 3];
    let output = Fips202Output::new(&mut bytes, 3);
    assert!(output.is_ok());
    let Ok(output) = output else { return };
    assert_eq!(state.finalize_bits(output), Ok(()));
    assert_eq!(bytes.last().copied().unwrap_or_default() & 0b1111_1000, 0);

    let mut xof_bytes = [0xff_u8; 3];
    let xof_output = Fips202Output::new(&mut xof_bytes, 3);
    assert!(xof_output.is_ok());
    let Ok(xof_output) = xof_output else { return };
    assert_eq!(tuple_hash_xof128_bits(&[item], custom, xof_output), Ok(()));
    assert_eq!(
        xof_bytes.last().copied().unwrap_or_default() & 0b1111_1000,
        0
    );
}

#[test]
fn xof_partitions_and_hardened_output_match() {
    let mut ordinary = TupleHashXof128::new(b"xof").ok();
    assert!(ordinary.is_some());
    let Some(mut ordinary) = ordinary.take() else {
        return;
    };
    assert_eq!(ordinary.push_item(b"one"), Ok(()));
    let mut partitioned = [0_u8; 48];
    {
        let reader = ordinary.finalize_xof();
        assert!(reader.is_ok());
        let Ok(mut reader) = reader else { return };
        let (first, second) = partitioned.split_at_mut(7);
        assert_eq!(reader.squeeze(first), Ok(()));
        assert_eq!(reader.squeeze(second), Ok(()));
    }
    assert_eq!(ordinary.item_count(), 0);
    assert_eq!(
        ordinary.push_item(b"after finalize"),
        Err(TupleHashError::StateConsumed)
    );

    let mut direct = [0_u8; 48];
    let mut one = TupleHashXof128::new(b"xof").ok();
    assert!(one.is_some());
    let Some(mut one) = one.take() else { return };
    assert_eq!(one.push_item(b"one"), Ok(()));
    assert_eq!(
        one.finalize_xof()
            .and_then(|mut value| value.squeeze(&mut direct)),
        Ok(())
    );
    assert_eq!(one.item_count(), 0);
    assert_eq!(partitioned, direct);

    let mut hardened = HardenedTupleHash128::new(b"xof").ok();
    assert!(hardened.is_some());
    let Some(mut hardened) = hardened.take() else {
        return;
    };
    assert_eq!(hardened.push_item(b"one"), Ok(()));
    let mut fixed = [0_u8; 32];
    assert_eq!(
        hardened.finalize_public(&mut fixed, TupleHashPublicDeclassification::acknowledge()),
        Ok(())
    );
    assert_eq!(hardened.item_count(), 0);
    assert_eq!(
        hardened.push_item(b"after finalize"),
        Err(TupleHashError::StateConsumed)
    );

    let mut hardened_xof = HardenedTupleHashXof128::new(b"xof").ok();
    assert!(hardened_xof.is_some());
    let Some(mut hardened_xof) = hardened_xof.take() else {
        return;
    };
    assert_eq!(hardened_xof.push_item(b"one"), Ok(()));
    let mut secret_bytes = [0_u8; 16];
    let secret = hardened_xof
        .finalize_xof()
        .and_then(|mut value| value.squeeze_secret(&mut secret_bytes));
    assert!(secret.is_ok());
    drop(secret);
    assert!(secret_bytes.iter().all(|byte| *byte == 0));
    assert_eq!(hardened_xof.item_count(), 0);
}
