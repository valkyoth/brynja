use brynja_crypto::ghash::{Error, Ghash};

#[test]
fn unavailable_owner_cannot_publish_even_empty_output() {
    let (mut work, mut out) = ([0xa5; 16], [0x5a; 16]);
    let mut g = Ghash::new(&[0x12; 16], &mut work, 16);
    assert_eq!(g.native_blocks(), Err(Error::CandidateNotReady));
    assert_eq!(g.update(&[0x34; 16]), Err(Error::CandidateNotReady));
    assert!(matches!(g.finish(&mut out), Err(Error::CandidateNotReady)));
    assert_eq!((work, out), ([0; 16], [0x5a; 16]));
}
