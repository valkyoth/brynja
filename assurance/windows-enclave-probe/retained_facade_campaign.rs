//! Fixed PUBLIC vectors through the concrete facade, not generic host handles.
use crate::retained_facade::{Error, PublicDeclassification, Session, State};
include!("retained_native_vectors.rs");

pub(crate) fn run(image: &[u16]) -> u32 {
    let Some(raw) = crate::open(image, 0) else {
        return 80;
    };
    let mut session = Session::from_retained(raw);
    if !matches!(session.hash(&[0; 1025]), Err(Error::Bounds)) || session.state() != State::Ready {
        return 81;
    }
    let mut input = [0; 3];
    input.copy_from_slice(MESSAGES[1]);
    let Ok(digest) = session.hash(&input) else {
        return 82;
    };
    input.fill(0);
    let Ok(digest) = digest.rehash() else {
        return 83;
    };
    let Ok(digest) = digest.rehash() else {
        return 83;
    };
    let mut output = [0xcc; 32];
    if digest
        .declassify(&mut output, PublicDeclassification::acknowledge())
        .is_err()
        || output != CHAINS[1]
        || output == DIGESTS[1]
    {
        return 84;
    }
    let Ok(digest) = session.hash(MESSAGES[1]) else {
        return 85;
    };
    if digest.cancel().is_err() || session.state() != State::Ready {
        return 86;
    }
    let Ok(digest) = session.hash(MESSAGES[1]) else {
        return 87;
    };
    drop(digest);
    if session.state() != State::Quarantined
        || session.hash(b"abc").is_ok()
        || session.close().is_err()
    {
        return 88;
    }
    if session.state() != State::Closed
        || !matches!(session.hash(b"abc"), Err(Error::Closed))
        || session.close().is_err()
    {
        return 89;
    }
    drop(session);
    let Some(raw) = crate::open(image, 0) else {
        return 90;
    };
    let mut session = Session::from_retained(raw);
    let Ok(digest) = session.hash(MESSAGES[1]) else {
        return 91;
    };
    core::mem::forget(digest);
    if session.state() != State::Busy || session.hash(b"abc").is_ok() || session.close().is_err() {
        return 92;
    }
    0
}
