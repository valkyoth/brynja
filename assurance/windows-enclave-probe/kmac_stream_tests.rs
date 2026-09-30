use super::*;
use std::vec;
pub(super) fn bits(data: &[u8], last: u8) -> Fips202BitString<'_> {
    Fips202BitString::new(data, last).unwrap()
}
pub(super) fn empty() -> Fips202BitString<'static> {
    bits(&[], 0)
}
pub(super) fn whole(data: &[u8]) -> Fips202BitString<'_> {
    bits(data, if data.is_empty() { 0 } else { 8 })
}
pub(super) fn next(sequence: &mut u64) -> u64 {
    *sequence = sequence.checked_add(1).unwrap();
    *sequence
}
pub(super) fn clean(owner: &Owner) {
    assert!(matches!(owner.state, State::Empty));
    assert_eq!(owner.output, [0; 1024]);
    assert_eq!(owner.width, 0);
    assert_eq!(owner.last, 0);
    assert_eq!(owner.algorithm, None);
}
fn start(id: u64) -> Owner {
    let mut owner = Owner::new();
    owner.begin(1, id, whole(&[0xa5; 32]), empty()).unwrap();
    owner
}
pub(super) fn retain(id: u64) -> Owner {
    let mut owner = start(id);
    if id <= 2 {
        owner.finish(2, empty(), 32, 8).unwrap();
    } else {
        owner.finish(2, empty(), 0, 0).unwrap();
        owner.squeeze(3, 32, 8, true).unwrap();
    }
    owner
}

fn check_case(
    id: u64,
    key: &[u8],
    key_last: u8,
    custom: &[u8],
    custom_last: u8,
    message: &[u8],
    message_last: u8,
    expected: &[u8],
    last: u8,
) {
    let mut owner = Owner::new();
    let mut sequence = 0;
    owner
        .begin_setup(
            next(&mut sequence),
            id,
            bits(key, key_last).bit_len() as u128,
            bits(custom, custom_last).bit_len() as u128,
        )
        .unwrap();
    super::kmac_stream_setup_tests::feed(
        &mut owner,
        &mut sequence,
        bits(custom, custom_last),
        false,
    );
    owner.finish_customization(next(&mut sequence)).unwrap();
    super::kmac_stream_setup_tests::feed(&mut owner, &mut sequence, bits(key, key_last), true);
    owner.finish_setup(next(&mut sequence)).unwrap();
    let complete = message
        .len()
        .saturating_sub(usize::from(message_last != 8 && !message.is_empty()));
    for chunk in message[..complete].chunks(37) {
        owner.update(next(&mut sequence), chunk).unwrap();
    }
    let tail = bits(
        &message[complete..],
        if complete == message.len() {
            0
        } else {
            message_last
        },
    );
    let mut actual = vec![0; expected.len()];
    if id <= 2 {
        owner
            .finish(next(&mut sequence), tail, expected.len(), last)
            .unwrap();
        owner
            .export(next(&mut sequence), id, expected.len(), last, |bytes| {
                actual.copy_from_slice(bytes);
                true
            })
            .unwrap();
    } else {
        owner.finish(next(&mut sequence), tail, 0, 0).unwrap();
        owner.squeeze(next(&mut sequence), 0, 0, false).unwrap();
        owner
            .export(next(&mut sequence), id, 0, 0, |bytes| bytes.is_empty())
            .unwrap();
        let mut position = 0;
        while expected.len().saturating_sub(position) > 13 {
            owner.squeeze(next(&mut sequence), 13, 8, false).unwrap();
            owner
                .export(next(&mut sequence), id, 13, 8, |bytes| {
                    actual[position..position + 13].copy_from_slice(bytes);
                    true
                })
                .unwrap();
            position += 13;
        }
        let remaining = expected.len() - position;
        owner
            .squeeze(
                next(&mut sequence),
                remaining,
                if remaining == 0 { 0 } else { last },
                true,
            )
            .unwrap();
        owner
            .export(
                next(&mut sequence),
                id,
                remaining,
                if remaining == 0 { 0 } else { last },
                |bytes| {
                    actual[position..].copy_from_slice(bytes);
                    true
                },
            )
            .unwrap();
    }
    assert_eq!(actual, expected);
    clean(&owner);
    assert_eq!(owner.phase, Phase::Empty);
}

#[test]
fn fixed_verification_compares_every_byte_and_permits_reuse() {
    for id in 1..=2 {
        let original = retain(id);
        let tag = original.output[..32].to_vec();
        let mut wrong_identity = retain(id);
        assert_eq!(
            wrong_identity.verify(3, 99, whole(&tag)),
            Err(Error::Identity)
        );
        clean(&wrong_identity);
        for mutation in 0..=32 {
            let mut candidate = tag.clone();
            if mutation < 32 {
                candidate[mutation] ^= 1;
            }
            let mut owner = retain(id);
            assert_eq!(
                owner.verify(3, id, whole(&candidate)).unwrap(),
                mutation == 32
            );
            clean(&owner);
            assert_eq!(owner.phase, Phase::Empty);
            owner.begin(4, id, whole(&[0xa5; 32]), empty()).unwrap();
            owner.cancel(5).unwrap();
        }
    }
}
#[test]
fn strength_identity_bit_shape_and_bounded_input_reject() {
    for id in 1..=4 {
        let mut owner = Owner::new();
        assert_eq!(
            owner.begin(1, id, whole(&[0; 15]), empty()),
            Err(Error::Crypto)
        );
        clean(&owner);
        let mut owner = Owner::new();
        assert_eq!(
            owner.begin(1, id, whole(&[0; 1025]), empty()),
            Err(Error::Length)
        );
        clean(&owner);
        let mut owner = Owner::new();
        assert_eq!(
            owner.begin(1, id, whole(&[0; 32]), whole(&[0; 1025])),
            Err(Error::Length)
        );
        clean(&owner);
        let mut owner = start(id);
        assert_eq!(owner.update(2, &[0; 1025]), Err(Error::Length));
        clean(&owner);
        let mut owner = start(id);
        assert_eq!(owner.finish(2, whole(&[0; 1025]), 0, 0), Err(Error::Length));
        clean(&owner);
        let mut owner = retain(id);
        let sequence = if id <= 2 { 3 } else { 4 };
        let mut copied = false;
        assert_eq!(
            owner.export(sequence, 99, 32, 8, |_| {
                copied = true;
                true
            }),
            Err(Error::Identity)
        );
        assert!(!copied);
        clean(&owner);
        let mut owner = retain(id);
        assert_eq!(
            owner.export(sequence, id, 31, 8, |_| panic!("must not copy")),
            Err(Error::Length)
        );
        clean(&owner);
        let mut owner = retain(id);
        assert_eq!(
            owner.export(sequence, id, 32, 7, |_| panic!("must not copy")),
            Err(Error::Length)
        );
        clean(&owner);
        if id <= 2 {
            let mut owner = start(id);
            assert_eq!(owner.finish(2, empty(), 15, 8), Err(Error::Crypto));
            clean(&owner);
            let mut owner = retain(id);
            assert_eq!(owner.verify(3, id, whole(&[0; 31])), Err(Error::Length));
            clean(&owner);
        } else {
            let mut owner = start(id);
            assert_eq!(owner.finish(2, empty(), 1, 8), Err(Error::Length));
            clean(&owner);
            let mut owner = start(id);
            owner.finish(2, empty(), 0, 0).unwrap();
            assert_eq!(owner.squeeze(3, 1, 7, false), Err(Error::Bits));
            clean(&owner);
            let mut owner = retain(id);
            assert_eq!(owner.verify(4, id, whole(&[0; 32])), Err(Error::Identity));
            clean(&owner);
        }
    }
    assert_eq!(Algorithm::decode(0), Err(Error::Identity));
    assert_eq!(shape(1025, 8), Err(Error::Length));
    assert_eq!(shape(0, 8), Err(Error::Bits));
    assert_eq!(shape(1, 0), Err(Error::Bits));
    assert_eq!(shape(1, 9), Err(Error::Bits));
}
#[test]
fn retained_rekey_preserves_bits_and_strength() {
    for source in 1..=4 {
        for target in 1..=4 {
            for last in 1..=8 {
                let mut owner = start(source);
                let mut sequence = 1;
                if source <= 2 {
                    owner
                        .finish(next(&mut sequence), empty(), 33, last)
                        .unwrap();
                } else {
                    owner.finish(next(&mut sequence), empty(), 0, 0).unwrap();
                    owner.squeeze(next(&mut sequence), 33, last, true).unwrap();
                }
                let key = owner.output[..33].to_vec();
                owner.rekey(next(&mut sequence), target, empty()).unwrap();
                assert_eq!(owner.output, [0; 1024]);
                let mut reference = State::new(
                    Algorithm::decode(target).unwrap(),
                    bits(&key, last),
                    empty(),
                )
                .unwrap();
                let mut expected = [0; 32];
                if target <= 2 {
                    reference.fixed(empty(), &mut expected, 8).unwrap();
                    owner.finish(next(&mut sequence), empty(), 32, 8).unwrap();
                } else {
                    reference.finish_xof(empty()).unwrap();
                    reference.squeeze(&mut expected, 8, true).unwrap();
                    owner.finish(next(&mut sequence), empty(), 0, 0).unwrap();
                    owner.squeeze(next(&mut sequence), 32, 8, true).unwrap();
                }
                owner
                    .export(next(&mut sequence), target, 32, 8, |bytes| {
                        assert_eq!(bytes, expected);
                        true
                    })
                    .unwrap();
                clean(&owner);
            }
        }
    }
    let mut owner = start(3);
    owner.finish(2, empty(), 0, 0).unwrap();
    owner.squeeze(3, 1, 1, true).unwrap();
    assert_eq!(owner.rekey(4, 1, empty()), Err(Error::Crypto));
    clean(&owner);
}
#[test]
fn cancellation_and_copy_unwind_never_reopen_state() {
    for id in 1..=4 {
        let mut owner = start(id);
        owner.cancel(2).unwrap();
        clean(&owner);
        let mut owner = retain(id);
        let sequence = if id <= 2 { 3 } else { 4 };
        assert_eq!(
            owner.export(sequence, id, 32, 8, |_| false),
            Err(Error::Copy)
        );
        clean(&owner);
        assert_eq!(owner.phase, Phase::Quarantined);
        let mut owner = retain(id);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.export(sequence, id, 32, 8, |_| panic!("injected copy unwind"))
        }));
        assert!(result.is_err());
        clean(&owner);
        assert_eq!(owner.phase, Phase::Quarantined);
        let mut owner = start(id);
        assert_eq!(owner.update(1, b""), Err(Error::Sequence));
        clean(&owner);
        assert_eq!(owner.cancel(2), Err(Error::State));
        let mut owner = retain(id);
        owner.cancel(sequence).unwrap();
        clean(&owner);
    }
}
#[test]
fn focused_memory_lifecycle() {
    let mut owner = Owner::new();
    owner.phase = Phase::RetainedFinal;
    owner.algorithm = Some(Algorithm::Kmac128);
    owner.output.fill(0xa5);
    owner.width = 32;
    owner.last = 8;
    assert!(!owner.verify(1, 1, whole(&[0; 32])).unwrap());
    clean(&owner);
    owner.sequence = u64::MAX;
    assert_eq!(
        owner.begin(0, 1, whole(&[0; 32]), empty()),
        Err(Error::Sequence)
    );
    clean(&owner);
    let mut owner = Owner::new();
    owner.phase = Phase::RetainedFinal;
    owner.algorithm = Some(Algorithm::Kmac128);
    owner.output.fill(0xa5);
    owner.width = 32;
    owner.last = 8;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.export(1, 1, 32, 8, |_| panic!("injected"))
    }));
    assert!(result.is_err());
    clean(&owner);
}
#[test]
fn empty_and_million_byte_streams_match_existing_owners() {
    for id in 1..=4 {
        let mut owner = start(id);
        let mut reference =
            State::new(Algorithm::decode(id).unwrap(), whole(&[0xa5; 32]), empty()).unwrap();
        let mut seq = 1;
        for _ in 0..1000 {
            owner.update(next(&mut seq), &[b'a'; 1000]).unwrap();
            reference.update(&[b'a'; 1000]).unwrap();
        }
        let mut expected = [0; 32];
        if id <= 2 {
            owner.finish(next(&mut seq), empty(), 32, 8).unwrap();
            reference.fixed(empty(), &mut expected, 8).unwrap();
        } else {
            owner.finish(next(&mut seq), empty(), 0, 0).unwrap();
            owner.squeeze(next(&mut seq), 32, 8, true).unwrap();
            reference.finish_xof(empty()).unwrap();
            reference.squeeze(&mut expected, 8, true).unwrap();
        }
        owner
            .export(next(&mut seq), id, 32, 8, |bytes| {
                assert_eq!(bytes, expected);
                true
            })
            .unwrap();
        clean(&owner);
    }
}
