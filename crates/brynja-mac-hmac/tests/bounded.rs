//! Small per-identity memory/lifecycle tasks; full native matrices remain intact.
#[macro_use]
mod support;
mod bit_support;
use bit_support::BitCase;
use brynja_mac_hmac::*;

fn exercise<A: BitCase>() {
    // One long key crosses the normalizer boundary; one streamed message
    // crosses the selected hash's block/rate without a Cartesian matrix.
    let key = vec![0x42; require_some!(A::BLOCK_BYTES.checked_add(1))];
    let message = vec![0xa5; require_some!(A::BLOCK_BYTES.checked_add(1))];
    let mut expected = vec![0; A::TAG_BYTES];
    let _ = require_ok!(Hmac::<A>::authenticate(&key, &message, &mut expected));
    let mut mac = require_ok!(Hmac::<A>::new(&key));
    require_ok!(mac.update(require_some!(message.get(..1))));
    require_ok!(mac.update(&[]));
    require_ok!(mac.update(require_some!(message.get(1..))));
    let mut output = vec![0xa5; A::TAG_BYTES];
    {
        let secret = require_ok!(mac.finalize_secret(&mut output));
        assert_eq!(secret.expose(), expected);
    }
    assert!(output.iter().all(|byte| *byte == 0));
    let mut verifier = require_ok!(Hmac::<A>::with_tag_length(b"short", 16));
    require_ok!(verifier.update(b"message"));
    assert!(!require_ok!(verifier.verify(&[0; 16])).expose_public());
    let mac = require_ok!(Hmac::<A>::new(&[]));
    let mut rejected = [0xa5; 1];
    assert!(matches!(
        mac.finalize_secret(&mut rejected),
        Err(Error::TagLength)
    ));
    assert_eq!(rejected, [0]);
    require_ok!(Hmac::<A>::new(&[])).cancel();
    // The same bounded per-identity task also exercises the distinct terminal
    // bit adapter. Full key/length/partition matrices stay native.
    let tail = [if A::LOW_BITS { 1 } else { 0x80 }];
    let input = require_some!(A::input(&tail, 1));
    let mac = require_ok!(Hmac::<A>::new(b"key"));
    {
        let secret = require_ok!(mac.finalize_bits_secret(input, &mut output));
        assert_eq!(secret.expose().len(), A::TAG_BYTES);
    }
    assert!(output.iter().all(|byte| *byte == 0));
}

macro_rules! cases {
    ($($name:ident: $algorithm:ty),* $(,)?) => {$(
        #[test]
        fn $name() { exercise::<$algorithm>(); }
    )*};
}

cases!(sha224: Sha224, sha256: Sha256, sha384: Sha384, sha512: Sha512,
       sha512_224: Sha512_224, sha512_256: Sha512_256, sha3_224: Sha3_224,
       sha3_256: Sha3_256, sha3_384: Sha3_384, sha3_512: Sha3_512,
       general_129: Sha512T<129>, general_511: Sha512T<511>);

#[test]
fn output_clears_during_consumer_unwind() {
    assert_eq!(support::decode("00"), Some(vec![0]));
    let mut output = [0xa5; 32];
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mac = require_ok!(Hmac::<Sha256>::new(b"key"));
        let secret = require_ok!(mac.finalize_secret(&mut output));
        assert!(secret.expose().is_empty(), "synthetic consumer unwind");
    }));
    assert!(caught.is_err());
    assert_eq!(output, [0; 32]);
}
