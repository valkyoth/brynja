//! Explicit execution against Python bit-model HMAC, not a production dependency.
#[macro_use]
mod support;
mod bit_support;
use bit_support::BitCase;
use brynja_mac_hmac::*;

fn check<A: BitCase>(key: &[u8], input: &[u8], bits: usize, expected: &[u8]) {
    assert_eq!(expected.len(), A::TAG_BYTES);
    assert_eq!(input.len(), require_some!(bits.checked_add(7)) / 8);
    let remainder = require_some!(bits.checked_rem(8));
    let valid = if bits == 0 {
        0
    } else if remainder == 0 {
        8
    } else {
        require_ok!(u8::try_from(remainder))
    };
    if remainder != 0 {
        let last = require_some!(input.last());
        let unused = if A::LOW_BITS {
            0xff << valid
        } else {
            0xff >> valid
        };
        assert_eq!(last & unused, 0);
    }
    let message = require_some!(A::input(input, valid));
    let mut output = vec![0xa5; A::TAG_BYTES];
    assert_eq!(
        require_ok!(Hmac::<A>::authenticate_bits(key, message, &mut output)).as_bytes(),
        expected
    );
    // Representative byte-boundary splits retain the partial-byte meaning.
    for split in [
        0,
        input.len().saturating_sub(1) / 2,
        input.len().saturating_sub(1),
    ] {
        let mut state = require_ok!(Hmac::<A>::new(key));
        require_ok!(state.update(require_some!(input.get(..split))));
        let suffix = require_some!(A::input(require_some!(input.get(split..)), valid));
        {
            let secret = require_ok!(state.finalize_bits_secret(suffix, &mut output));
            assert_eq!(secret.expose(), expected);
        }
        assert!(output.iter().all(|byte| *byte == 0));
        let mut verifier = require_ok!(Hmac::<A>::with_tag_length(key, 16));
        require_ok!(verifier.update(require_some!(input.get(..split))));
        assert!(
            require_ok!(verifier.verify_bits(suffix, require_some!(expected.get(..16))))
                .expose_public()
        );
    }
}

#[test]
#[ignore = "requires bit oracle: python3 scripts/hmac/check-hmac-bit-differential.py"]
fn external_bit_oracle() {
    let file = require_ok!(std::env::var("BRYNJA_HMAC_BIT_ORACLE"));
    let text = require_ok!(std::fs::read_to_string(file));
    let mut counts = [0_usize; 10];
    for row in text.lines() {
        let fields: Vec<_> = row.split(':').collect();
        let fields: [&str; 5] = require_ok!(fields.try_into());
        let key = require_some!(support::decode(fields[1]));
        let input = require_some!(support::decode(fields[2]));
        let bits = require_ok!(fields[3].parse::<usize>());
        let expected = require_some!(support::decode(fields[4]));
        macro_rules! case {
            ($index:literal, $algorithm:ty) => {{
                check::<$algorithm>(&key, &input, bits, &expected);
                counts[$index] = require_some!(counts[$index].checked_add(1));
                true
            }};
        }
        let recognized = match fields[0] {
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
            _ => false,
        };
        assert!(recognized, "unknown HMAC oracle identity");
    }
    assert_eq!(counts, [104; 10]);
    println!(
        "HMAC_BIT_ORACLE: 1040 cases; 10 algorithms; bit finalization and truncated verification"
    );
}
