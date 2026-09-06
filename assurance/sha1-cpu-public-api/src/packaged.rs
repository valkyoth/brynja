//! External packaged-source consumer: ordinary builds must not execute candidates.
#[test]
fn published_surface_retains_fail_closed_selection_and_portable_results() {
    use brynja_legacy_sha1::{BitString, Sha1BackendError, Sha1BackendSession};
    use brynja_legacy_sha1_std::{RequiredAccelerationUnavailable, RuntimeSha1Backend};
    assert!(matches!(Sha1BackendSession::for_compiled_target().err(),
        Some(Sha1BackendError::NotAdmitted | Sha1BackendError::MissingFeatures)));
    assert_eq!(RuntimeSha1Backend::required().err(), Some(RequiredAccelerationUnavailable));
    let selected = RuntimeSha1Backend::opportunistic();
    assert_eq!(selected.hash(b"abc"), Ok([
        0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
        0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d,
    ]));
    let mut stream = selected.start();
    assert_eq!(stream.update(b"a"),Ok(()));
    assert_eq!(stream.update(b"bc"),Ok(()));
    assert_eq!(selected.hash(b"abc"),Ok(stream.finalize()));
    if let Ok(bits) = BitString::new(&[0xa0],3) {
        assert_eq!(selected.hash_bits(bits),brynja_legacy_sha1::sha1_bits(bits));
    } else { assert!(false,"canonical bit input rejected"); }
}
