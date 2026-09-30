use super::kmac_stream_tests::{bits, clean, next};
use super::kmac_stream_wire::*;
use super::*;
use std::vec::Vec;

fn bytes(words: [u64; 12]) -> [u8; 96] {
    let mut header = [0; 96];
    for (word, bytes) in words.into_iter().zip(header.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    header
}
fn send(
    owner: &mut Owner,
    seq: &mut u64,
    op: usize,
    mut words: [u64; 12],
    input: &[u8],
    copy: impl FnOnce(&[u8]) -> bool,
) -> Result<(), Error> {
    words[0] = VERSION;
    words[1] = next(seq);
    words[3] = input.len() as u64;
    words[5] = u64::from(!input.is_empty());
    Header::decode(op, &bytes(words))
        .unwrap()
        .execute(owner, input, copy)
}
fn no_copy(_: &[u8]) -> bool {
    panic!("unexpected output");
}
pub(super) fn check_case(
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
    let mut seq = 0;
    let mut w = [0; 12];
    w[2] = id;
    w[8] = bits(key, key_last).bit_len() as u64;
    w[10] = bits(custom, custom_last).bit_len() as u64;
    send(&mut owner, &mut seq, BEGIN, w, &[], no_copy).unwrap();
    for (op, input, last) in [(CUSTOM, custom, custom_last), (KEY, key, key_last)] {
        let mut offset = 0;
        for chunk in input.chunks(37) {
            offset += chunk.len();
            let mut w = [0; 12];
            w[4] = if offset == input.len() {
                u64::from(last)
            } else {
                8
            };
            send(&mut owner, &mut seq, op, w, chunk, no_copy).unwrap();
        }
        send(
            &mut owner,
            &mut seq,
            if op == CUSTOM { CUSTOM_END } else { SETUP_END },
            [0; 12],
            &[],
            no_copy,
        )
        .unwrap();
    }
    let complete = message
        .len()
        .saturating_sub(usize::from(message_last != 8 && !message.is_empty()));
    for chunk in message[..complete].chunks(37) {
        let mut w = [0; 12];
        w[4] = 8;
        send(&mut owner, &mut seq, UPDATE, w, chunk, no_copy).unwrap();
    }
    let mut w = [0; 12];
    w[4] = if complete == message.len() {
        0
    } else {
        message_last as u64
    };
    if id <= 2 {
        w[6] = bits(expected, last).bit_len() as u64;
    }
    send(
        &mut owner,
        &mut seq,
        FINISH,
        w,
        &message[complete..],
        no_copy,
    )
    .unwrap();
    if id > 2 {
        let mut w = [0; 12];
        w[6] = expected.len() as u64;
        w[4] = last as u64;
        w[7] = 1;
        send(&mut owner, &mut seq, SQUEEZE, w, &[], no_copy).unwrap();
    }
    let mut w = [0; 12];
    w[2] = id;
    w[6] = expected.len() as u64;
    w[4] = last as u64;
    send(&mut owner, &mut seq, EXPORT, w, &[], |actual| {
        assert_eq!(actual, expected);
        true
    })
    .unwrap();
    clean(&owner);
}

#[test]
fn canonical_header_rejects_unknown_reserved_and_bad_shapes() {
    for op in BEGIN..=CANCEL {
        let payload = matches!(op, CUSTOM | KEY | UPDATE | FINISH | VERIFY);
        let names = matches!(op, BEGIN | EXPORT | VERIFY | REKEY);
        let mut w = [0; 12];
        w[0] = VERSION;
        w[1] = 1;
        if payload {
            w[3] = 1;
            w[4] = 8;
            w[5] = 1;
        }
        if names {
            w[2] = 1;
        }
        if matches!(op, SQUEEZE | EXPORT) {
            w[6] = 32;
            w[4] = 8;
        }
        if op == FINISH {
            w[6] = 256;
        }
        if op == BEGIN {
            w[8] = 256;
        }
        assert!(Header::decode(op, &bytes(w)).is_ok(), "op={op}");
        for (index, value) in [(0, 7), (1, 0), (3, 1025), (4, 9), (6, 8193), (7, 2)] {
            let mut bad = w;
            bad[index] = value;
            assert!(
                Header::decode(op, &bytes(bad)).is_err(),
                "op={op} field={index}"
            );
        }
        for index in 2..12 {
            let reserved = match index {
                2 => !names,
                3 | 5 => !payload,
                4 => !payload && !matches!(op, SQUEEZE | EXPORT),
                6 => !matches!(op, FINISH | SQUEEZE | EXPORT),
                7 => op != SQUEEZE,
                8 | 9 => op != BEGIN,
                10 | 11 => !matches!(op, BEGIN | REKEY),
                _ => false,
            };
            if reserved {
                let mut bad = w;
                bad[index] = 1;
                assert!(
                    Header::decode(op, &bytes(bad)).is_err(),
                    "reserved op={op} field={index}"
                );
            }
        }
        if names {
            for identity in [0, 5, u64::MAX] {
                let mut bad = w;
                bad[2] = identity;
                assert!(Header::decode(op, &bytes(bad)).is_err());
            }
        }
        if payload {
            for (index, value) in [(5, 0), (5, u64::MAX), (4, 0)] {
                let mut bad = w;
                bad[index] = value;
                assert!(Header::decode(op, &bytes(bad)).is_err());
            }
        }
    }
    for op in [0, 3, 21, 31, 39, 52, usize::MAX] {
        let mut w = [0; 12];
        w[0] = VERSION;
        w[1] = 1;
        assert!(Header::decode(op, &bytes(w)).is_err());
    }
    let mut w = [0; 12];
    w[0] = VERSION;
    w[1] = 1;
    w[3] = 1;
    w[4] = 7;
    w[5] = 1;
    assert!(Header::decode(UPDATE, &bytes(w)).is_err());
}
fn retained() -> (Owner, u64, Vec<u8>) {
    let mut owner = Owner::new();
    owner
        .begin(1, 1, bits(&[0xa5; 32], 8), bits(&[], 0))
        .unwrap();
    owner.finish(2, bits(&[], 0), 33, 3).unwrap();
    let output = owner.output[..33].to_vec();
    (owner, 2, output)
}
#[test]
fn verification_exports_only_one_decision_and_copy_failure_quarantines() {
    for mismatch in [false, true] {
        let (mut owner, mut seq, mut candidate) = retained();
        if mismatch {
            candidate[0] ^= 1;
        }
        let mut w = [0; 12];
        w[2] = 1;
        w[4] = 3;
        send(&mut owner, &mut seq, VERIFY, w, &candidate, |decision| {
            assert_eq!(decision, &[u8::from(!mismatch)]);
            true
        })
        .unwrap();
        clean(&owner);
        assert_eq!(owner.phase, Phase::Empty);
    }
    for unwind in [false, true] {
        let (mut owner, mut seq, candidate) = retained();
        let mut w = [0; 12];
        w[2] = 1;
        w[4] = 3;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            send(&mut owner, &mut seq, VERIFY, w, &candidate, |_| {
                if unwind {
                    panic!("decision copy unwind");
                }
                false
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Error::Copy));
        }
        clean(&owner);
        assert_eq!(owner.phase, Phase::Quarantined);
    }
}
#[test]
fn payload_shape_failure_never_exports_or_reopens() {
    for malformed in [false, true] {
        let mut owner = Owner::new();
        owner.begin_setup(1, 1, 256, 1).unwrap();
        let mut w = [0; 12];
        w[0] = VERSION;
        w[1] = 2;
        w[3] = 1;
        w[4] = 1;
        w[5] = 1;
        let header = Header::decode(CUSTOM, &bytes(w)).unwrap();
        assert!(
            header
                .execute(&mut owner, if malformed { &[0xff] } else { &[] }, no_copy)
                .is_err()
        );
        clean(&owner);
        assert_eq!(owner.phase, Phase::Quarantined);
    }
}
