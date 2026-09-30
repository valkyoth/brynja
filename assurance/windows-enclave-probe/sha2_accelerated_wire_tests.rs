use super::sha2_accelerated_wire::Request;
use super::*;

fn header(words: [u64; 8]) -> [u8; 64] {
    let mut bytes = [0; 64];
    for (out, word) in bytes.chunks_exact_mut(8).zip(words) {
        out.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
#[test]
fn exact_version_route_and_snapshot_protocol() {
    let begin = [13, 1, 2, 0, 0, 0, 1, 0];
    for (index, values) in [
        (0, [0, 6, 12, 14]),
        (1, [0, 0, 0, 0]),
        (2, [0, 3, 4, 0x1001]),
        (3, [1, 1025, u64::MAX, 64]),
        (4, [1, 8, 256, u64::MAX]),
        (5, [1, 4096, u64::MAX, 64]),
        (6, [0, 2, 3, u64::MAX]),
        (7, [1, 2, 3, u64::MAX]),
    ] {
        for value in values {
            let mut words = begin;
            words[index] = value;
            assert!(
                Request::decode(11, &header(words)).is_err(),
                "{index}:{value}"
            );
        }
    }
    for op in [0, 10, 17, usize::MAX] {
        assert!(Request::decode(op, &header(begin)).is_err());
    }
    let authority = super::sha2_accelerated_tests::make_authority();
    let mut owner = Owner::new(&authority).unwrap();
    Request::decode(11, &header(begin))
        .unwrap()
        .execute(&mut owner, &[], |_| false)
        .unwrap();
    let update = [13, 2, 0, 3, 8, 4096, 1, 0];
    for (index, value) in [(2, 2), (3, 1025), (4, 1), (5, 0), (5, u64::MAX)] {
        let mut words = update;
        words[index] = value;
        assert!(Request::decode(12, &header(words)).is_err());
    }
    Request::decode(12, &header(update))
        .unwrap()
        .execute(&mut owner, b"abc", |_| false)
        .unwrap();
    Request::decode(13, &header([13, 3, 0, 0, 0, 0, 1, 0]))
        .unwrap()
        .execute(&mut owner, &[], |_| false)
        .unwrap();
    Request::decode(15, &header([13, 4, 2, 0, 0, 0, 1, 0]))
        .unwrap()
        .execute(&mut owner, &[], |bytes| {
            assert_eq!(bytes, brynja_hash_sha2::sha256(b"abc").unwrap().as_bytes());
            true
        })
        .unwrap();
    assert_eq!(owner.output, [0; 32]);
    Request::decode(11, &header([13, 5, 2, 0, 0, 0, 1, 0]))
        .unwrap()
        .execute(&mut owner, &[], |_| false)
        .unwrap();
    assert_eq!(
        Request::decode(12, &header([13, 6, 0, 3, 8, 4096, 1, 0]))
            .unwrap()
            .execute(&mut owner, b"ab", |_| false),
        Err(Error::Length)
    );
    assert_eq!(owner.phase, Phase::Quarantined);
    assert!(authority.session().is_err());
}
