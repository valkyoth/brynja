use super::{Error, Owner, Phase, tuple_stream_wire::*};
fn header(op: usize, words: [u64; 12]) -> Result<Header, Error> {
    let mut data = [0; 96];
    for (part, word) in data.chunks_exact_mut(8).zip(words) {
        part.copy_from_slice(&word.to_le_bytes());
    }
    Header::decode(op, &data)
}
fn base() -> [u64; 12] {
    [VERSION, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}
#[test]
fn canonical_headers_reject_unused_fields_shapes_and_address_overflow() {
    let mut oversized = base();
    oversized[3] = 1025;
    oversized[4] = 8;
    oversized[5] = 0x1000;
    assert!(header(FRAGMENT, oversized).is_err());
    assert!(header(CUSTOM, oversized).is_err());
    for op in BEGIN..=CANCEL {
        let mut good = base();
        if matches!(op, BEGIN | EXPORT | REHASH) {
            good[2] = 1;
        }
        header(op, good).unwrap();
        for (field, value) in [(0, 8), (1, 0), (3, 1025), (4, 9), (6, 1025), (7, 2), (5, 1)] {
            let mut bad = good;
            bad[field] = value;
            assert!(header(op, bad).is_err(), "{op}:{field}");
        }
        for field in [2, 3, 4, 6, 7, 8, 9, 10, 11] {
            let allowed = match field {
                2 => matches!(op, BEGIN | EXPORT | REHASH),
                3 => matches!(op, CUSTOM | FRAGMENT),
                4 => matches!(op, CUSTOM | FRAGMENT | FINISH | SQUEEZE | EXPORT),
                6 => matches!(op, FINISH | SQUEEZE | EXPORT),
                7 => op == SQUEEZE,
                8 | 9 => op == ITEM_BEGIN,
                10 | 11 => matches!(op, BEGIN | REHASH),
                _ => false,
            };
            if !allowed {
                let mut bad = good;
                bad[field] = 1;
                assert!(header(op, bad).is_err(), "{op}:{field}");
            }
        }
    }
    for op in [59, 71, usize::MAX] {
        assert!(header(op, base()).is_err());
    }
    let mut p = base();
    p[3] = 1;
    p[4] = 8;
    p[5] = u64::MAX;
    assert!(header(FRAGMENT, p).is_err());
    p[5] = 0x1000;
    p[4] = 0;
    assert!(header(FRAGMENT, p).is_err());
    let mut p = base();
    p[6] = 1;
    p[4] = 7;
    assert!(header(SQUEEZE, p).is_err());
    p[7] = 1;
    header(SQUEEZE, p).unwrap();
}
#[test]
fn malformed_copied_bits_quarantine_before_further_work() {
    let mut owner = Owner::new();
    owner.begin(1, 1, 1).unwrap();
    let mut words = base();
    words[1] = 2;
    words[3] = 1;
    words[4] = 1;
    words[5] = 0x1000;
    assert_eq!(
        header(CUSTOM, words)
            .unwrap()
            .execute(&mut owner, &[0x80], |_| panic!("unexpected export")),
        Err(Error::Bits)
    );
    assert_eq!(owner.phase, Phase::Quarantined);
    let mut owner = Owner::new();
    owner.begin(1, 1, 8).unwrap();
    words[4] = 8;
    assert_eq!(
        header(CUSTOM, words)
            .unwrap()
            .execute(&mut owner, &[], |_| false),
        Err(Error::Length)
    );
    assert_eq!(owner.phase, Phase::Quarantined);
}
pub(super) fn check_case(
    id: u64,
    custom: &[u8],
    custom_bits: usize,
    items: &[(&[u8], usize)],
    expected: &[u8],
    last: u8,
) {
    let mut owner = Owner::new();
    let mut seq = 0_u64;
    let mut send =
        |op: usize, mut words: [u64; 12], input: &[u8], output: Option<&mut std::vec::Vec<u8>>| {
            seq = seq.checked_add(1).unwrap();
            words[0] = VERSION;
            words[1] = seq;
            words[3] = input.len() as u64;
            words[5] = if input.is_empty() { 0 } else { 0x1000 };
            let header = header(op, words).unwrap();
            assert_eq!(header.length(), input.len());
            assert_eq!(header.source(), words[5] as usize);
            header
                .execute(&mut owner, input, |bytes| {
                    output.unwrap().extend_from_slice(bytes);
                    true
                })
                .unwrap();
        };
    let mut words = base();
    words[2] = id;
    words[10] = custom_bits as u64;
    send(BEGIN, words, &[], None);
    super::tuple_stream_tests::fragments(
        |bits| {
            let mut w = base();
            w[4] = bits.valid_bits_in_last_byte() as u64;
            send(CUSTOM, w, bits.as_bytes(), None);
        },
        custom,
        custom_bits,
    );
    send(CUSTOM_END, base(), &[], None);
    for &(value, bits) in items {
        let mut w = base();
        w[8] = bits as u64;
        send(ITEM_BEGIN, w, &[], None);
        super::tuple_stream_tests::fragments(
            |bits| {
                let mut w = base();
                w[4] = bits.valid_bits_in_last_byte() as u64;
                send(FRAGMENT, w, bits.as_bytes(), None);
            },
            value,
            bits,
        );
        send(ITEM_END, base(), &[], None);
    }
    let mut w = base();
    w[6] = expected.len() as u64;
    w[4] = last as u64;
    if id <= 2 {
        send(FINISH, w, &[], None);
    } else {
        send(FINISH, base(), &[], None);
        w[7] = 1;
        send(SQUEEZE, w, &[], None);
        w[7] = 0;
    }
    w[2] = id;
    let mut actual = std::vec::Vec::new();
    send(EXPORT, w, &[], Some(&mut actual));
    assert_eq!(actual, expected);
}
