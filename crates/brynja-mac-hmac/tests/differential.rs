//! Test-only independently generated Python/OpenSSL oracle; never a dependency.
#[macro_use]
mod support;

use brynja_mac_hmac::*;

fn check<A: Algorithm>(key: &[u8], input: &[u8], expected: &[u8]) {
    assert_eq!(expected.len(), A::TAG_BYTES);
    let mut one_shot = vec![0; A::TAG_BYTES];
    assert_eq!(
        require_ok!(Hmac::<A>::authenticate(key, input, &mut one_shot)).as_bytes(),
        expected
    );
    for chunk in [1, 7, A::BLOCK_BYTES, input.len().max(1)] {
        let mut state = require_ok!(Hmac::<A>::new(key));
        require_ok!(state.update(&[]));
        for part in input.chunks(chunk) {
            require_ok!(state.update(part));
        }
        let mut output = vec![0; A::TAG_BYTES];
        assert_eq!(
            require_ok!(state.finalize_tag(&mut output)).as_bytes(),
            expected
        );
    }
    let mut truncated = require_ok!(Hmac::<A>::with_tag_length(key, 16));
    require_ok!(truncated.update(input));
    assert_eq!(truncated.verify(require_some!(expected.get(..16))), Ok(()));
}

#[test]
#[ignore = "requires independent oracle: python3 scripts/hmac/check-hmac-differential.py"]
fn external_oracle() {
    let file = require_ok!(std::env::var("BRYNJA_HMAC_ORACLE"));
    let text = require_ok!(std::fs::read_to_string(file));
    const ALLOWED: &[&str] = &[
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512_224",
        "sha512_256",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
    ];
    let mut counts = [0_usize; 10];
    for row in text.lines() {
        let fields: Vec<_> = row.split(':').collect();
        let fields: [&str; 4] = require_ok!(fields.try_into());
        let key = require_some!(support::decode(fields[1]));
        let input = require_some!(support::decode(fields[2]));
        let expected = require_some!(support::decode(fields[3]));
        macro_rules! case {
            ($index:literal, $algorithm:ty) => {{
                check::<$algorithm>(&key, &input, &expected);
                counts[$index] = require_some!(counts[$index].checked_add(1));
            }};
        }
        match fields[0] {
            "sha224" => case!(0, Sha224),
            "sha256" => case!(1, Sha256),
            "sha384" => case!(2, Sha384),
            "sha512" => case!(3, Sha512),
            "sha512_224" => case!(4, Sha512_224),
            "sha512_256" => case!(5, Sha512_256),
            "sha3_224" => case!(6, Sha3_224),
            "sha3_256" => case!(7, Sha3_256),
            "sha3_384" => case!(8, Sha3_384),
            "sha3_512" => case!(9, Sha3_512),
            _ => {
                assert!(ALLOWED.contains(&fields[0]), "unknown oracle identity");
                return;
            }
        }
    }
    assert_eq!(counts, [110; 10], "oracle population is incomplete");
    println!("HMAC_ORACLE: 1100 cases; 10 algorithms; 4 partitions and truncation per case");
}
