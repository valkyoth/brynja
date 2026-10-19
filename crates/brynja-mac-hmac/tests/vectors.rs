//! RFC 4231 sections 4.2, 4.6 and 4.7 (cases 1, 5 and 6).
//! https://www.rfc-editor.org/rfc/rfc4231.html

#[macro_use]
mod support;

use brynja_mac_hmac::{Algorithm, Hmac, Sha224, Sha256, Sha384, Sha512};

fn check<A: Algorithm>(key: &[u8], input: &[u8], expected: &str) {
    let expected = require_some!(support::decode(expected));
    let mut mac = require_ok!(Hmac::<A>::with_tag_length(key, expected.len()));
    for byte in input.chunks(1) {
        require_ok!(mac.update(byte));
    }
    let mut output = vec![0; expected.len()];
    assert_eq!(
        require_ok!(mac.finalize_tag(&mut output)).as_bytes(),
        expected
    );
}

#[test]
fn rfc4231_case1() {
    let key = [0x0b; 20];
    check::<Sha224>(
        &key,
        b"Hi There",
        "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
    );
    check::<Sha256>(
        &key,
        b"Hi There",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    );
    check::<Sha384>(
        &key,
        b"Hi There",
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
    );
    check::<Sha512>(
        &key,
        b"Hi There",
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    );
}

#[test]
fn rfc4231_case5_explicit_truncation() {
    let key = [0x0c; 20];
    let input = b"Test With Truncation";
    check::<Sha224>(&key, input, "0e2aea68a90c8d37c988bcdb9fca6fa8");
    check::<Sha256>(&key, input, "a3b6167473100ee06e0c796c2955552b");
    check::<Sha384>(&key, input, "3abf34c3503b2a23a46efc619baef897");
    check::<Sha512>(&key, input, "415fad6271580a531d4179bc891d87a6");
}

#[test]
fn rfc4231_case6_long_key_normalization() {
    let key = [0xaa; 131];
    let input = b"Test Using Larger Than Block-Size Key - Hash Key First";
    check::<Sha224>(
        &key,
        input,
        "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
    );
    check::<Sha256>(
        &key,
        input,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    );
    check::<Sha384>(
        &key,
        input,
        "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
    );
    check::<Sha512>(
        &key,
        input,
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    );
}
