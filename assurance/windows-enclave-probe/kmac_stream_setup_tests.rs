use super::kmac_stream_tests::{bits, clean, empty, next, retain, whole};
use super::*;
use std::vec;

pub(super) fn feed(owner: &mut Owner, sequence: &mut u64, input: Fips202BitString<'_>, key: bool) {
    let mut offset = 0;
    let mut chunk = 0;
    while offset < input.bit_len() {
        let count = [1, 7, 17, 8191][chunk % 4].min(input.bit_len() - offset);
        let mut bytes = vec![0; count.div_ceil(8)];
        for i in 0..count {
            bytes[i / 8] |=
                ((input.as_bytes()[(offset + i) / 8] >> ((offset + i) % 8)) & 1) << (i % 8);
        }
        let value = bits(&bytes, ((count - 1) % 8 + 1) as u8);
        if key {
            owner.key(next(sequence), value).unwrap();
        } else {
            owner.customization(next(sequence), value).unwrap();
        }
        offset += count;
        chunk += 1;
    }
    if key {
        owner.key(next(sequence), empty()).unwrap();
    } else {
        owner.customization(next(sequence), empty()).unwrap();
    }
}
fn rejected(owner: &Owner) {
    clean(owner);
    assert_eq!(owner.phase, Phase::Quarantined);
}

#[test]
fn streamed_setup_rejects_protocol_errors_and_clears() {
    for id in 1..=4 {
        for case in 0..12 {
            let mut owner = Owner::new();
            owner.begin_setup(1, id, 256, 1).unwrap();
            let result = match case {
                0 => owner.finish_customization(2),
                1 => owner.customization(1, bits(&[1], 1)),
                2 => owner.customization(2, bits(&[3], 2)),
                3 => owner.customization(2, whole(&[0; 1025])),
                4 => owner.key(2, whole(&[0; 32])),
                5 => owner.update(2, b""),
                _ => {
                    owner.customization(2, bits(&[1], 1)).unwrap();
                    owner.finish_customization(3).unwrap();
                    match case {
                        6 => owner.finish_setup(4),
                        7 => owner.key(4, whole(&[0; 33])),
                        8 => owner.key(4, whole(&[0; 1025])),
                        9 => owner.customization(4, empty()),
                        10 => owner.finish_customization(4),
                        _ => {
                            owner.algorithm = Some(if id % 2 == 1 {
                                Algorithm::Kmac256
                            } else {
                                Algorithm::Kmac128
                            });
                            owner.key(4, whole(&[0; 32])).unwrap();
                            owner.finish_setup(5)
                        }
                    }
                }
            };
            assert!(result.is_err(), "id={id}; case={case}");
            rejected(&owner);
            assert!(owner.begin_setup(9, id, 256, 0).is_err());
            rejected(&owner);
        }
        for (key, custom) in [(0, 0), (127, 0), (256, u128::MAX)] {
            let mut owner = Owner::new();
            assert!(owner.begin_setup(1, id, key, custom).is_err());
            rejected(&owner);
        }
    }
    let mut owner = Owner::new();
    assert_eq!(owner.begin_setup(1, 0, 256, 0), Err(Error::Identity));
    rejected(&owner);
    // Separately satisfy the declared large lengths so the transport bounds,
    // rather than length accounting, are what reject the oversized fragments.
    let mut owner = Owner::new();
    owner.begin_setup(1, 1, 8200, 8200).unwrap();
    assert_eq!(
        owner.customization(2, whole(&[0; 1025])),
        Err(Error::Length)
    );
    rejected(&owner);
    let mut owner = Owner::new();
    owner.begin_setup(1, 1, 8200, 0).unwrap();
    owner.finish_customization(2).unwrap();
    assert_eq!(owner.key(3, whole(&[0; 1025])), Err(Error::Length));
    rejected(&owner);
}

#[test]
fn streamed_retained_rekey_binds_all_four_identities_and_exact_bits() {
    for source in 1..=4 {
        for target in 1..=4 {
            for last in 1..=8 {
                let mut owner = Owner::new();
                owner.begin(1, source, whole(&[0xa5; 32]), empty()).unwrap();
                let mut seq = 1;
                if source <= 2 {
                    owner.finish(next(&mut seq), empty(), 33, last).unwrap();
                } else {
                    owner.finish(next(&mut seq), empty(), 0, 0).unwrap();
                    owner.squeeze(next(&mut seq), 33, last, true).unwrap();
                }
                let key = owner.output[..33].to_vec();
                let mut custom = vec![0x96; 2050];
                *custom.last_mut().unwrap() = 1;
                let custom = bits(&custom, 1);
                owner
                    .rekey_setup(next(&mut seq), target, custom.bit_len() as u128)
                    .unwrap();
                feed(&mut owner, &mut seq, custom, false);
                owner.finish_customization(next(&mut seq)).unwrap();
                assert_eq!(owner.output, [0; 1024]);
                assert_eq!(owner.phase, Phase::Streaming);
                let key = bits(&key, last);
                let mut reference = match target {
                    1 => State::A(brynja_mac_kmac::Kmac128::new_bits(key, custom).unwrap()),
                    2 => State::B(brynja_mac_kmac::Kmac256::new_bits(key, custom).unwrap()),
                    3 => State::X(brynja_mac_kmac::KmacXof128::new_bits(key, custom).unwrap()),
                    _ => State::Y(brynja_mac_kmac::KmacXof256::new_bits(key, custom).unwrap()),
                };
                let mut expected = [0; 32];
                if target <= 2 {
                    owner.finish(next(&mut seq), empty(), 32, 8).unwrap();
                    reference.fixed(empty(), &mut expected, 8).unwrap();
                } else {
                    owner.finish(next(&mut seq), empty(), 0, 0).unwrap();
                    owner.squeeze(next(&mut seq), 32, 8, true).unwrap();
                    reference.finish_xof(empty()).unwrap();
                    reference.squeeze(&mut expected, 8, true).unwrap();
                }
                owner
                    .export(next(&mut seq), target, 32, 8, |bytes| {
                        assert_eq!(bytes, expected);
                        true
                    })
                    .unwrap();
                clean(&owner);
            }
        }
    }
}

#[test]
fn streamed_setup_cancel_unwind_and_retained_key_substitution() {
    for phase in 0..3 {
        for unwind in [false, true] {
            let mut owner = if phase == 2 { retain(1) } else { Owner::new() };
            let seq = if phase == 2 {
                owner.rekey_setup(3, 2, 0).unwrap();
                4
            } else {
                owner.begin_setup(1, 1, 256, 0).unwrap();
                if phase == 1 {
                    owner.finish_customization(2).unwrap();
                    3
                } else {
                    2
                }
            };
            if unwind {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _guard = owner
                            .operation(seq, &[Phase::Custom, Phase::Key, Phase::CustomRetained])
                            .unwrap();
                        panic!("injected setup unwind");
                    }))
                    .is_err()
                );
                rejected(&owner);
            } else {
                owner.cancel(seq).unwrap();
                clean(&owner);
                assert_eq!(owner.phase, Phase::Empty);
                owner.begin_setup(seq + 1, 1, 256, 0).unwrap();
            }
        }
    }
    let mut owner = retain(1);
    owner.rekey_setup(3, 2, 0).unwrap();
    assert_eq!(owner.key(4, whole(&[0; 32])), Err(Error::State));
    rejected(&owner);
    let mut owner = retain(1);
    owner.rekey_setup(3, 2, 1).unwrap();
    assert!(owner.finish_customization(4).is_err());
    rejected(&owner);
    let mut owner = Owner::new();
    owner.begin(1, 1, whole(&[0; 32]), empty()).unwrap();
    owner.finish(2, empty(), 16, 8).unwrap();
    assert!(owner.rekey_setup(3, 2, 0).is_err());
    rejected(&owner);
}
