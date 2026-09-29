use crate::retained_facade::{PublicDeclassification, Session as Facade};

fn facade(fault: u8) -> Facade {
    Facade::from_retained(open(&[65, 0], fault).unwrap())
}

#[test]
fn facade_declassification_and_cancel_preserve_reuse() {
    reset();
    let mut session = facade(0);
    let mut input = std::vec::Vec::from(MESSAGES[1]);
    let digest = session.hash(&input).unwrap();
    input.fill(0);
    drop(input);
    let mut output = [0xcc; 32];
    digest
        .declassify(&mut output, PublicDeclassification::acknowledge())
        .unwrap();
    assert_eq!(output, DIGESTS[1]);
    assert_eq!(session.state(), State::Ready);
    session
        .hash(MESSAGES[1])
        .unwrap()
        .rehash()
        .unwrap()
        .cancel()
        .unwrap();
    assert_eq!(session.state(), State::Ready);
    session.close().unwrap();
    MOCK.with(|l| assert_eq!(l.borrow().calls, [0, 1, 2, 3, 0, 1, 8, 4, 3]));
}

#[test]
fn facade_rejects_failure_without_public_commit_or_fallback() {
    for fault in [1, 2, 3, 7] {
        reset();
        let mut session = facade(fault);
        let mut output = [0xcc; 32];
        assert_eq!(
            session
                .hash(MESSAGES[1])
                .unwrap()
                .declassify(&mut output, PublicDeclassification::acknowledge()),
            Err(Error::Protocol)
        );
        assert_eq!(output, [0xcc; 32]);
        assert_eq!(session.state(), State::Quarantined);
        assert!(session.hash(MESSAGES[1]).is_err());
        session.close().unwrap();
    }
}

#[test]
fn facade_abandon_forget_unwind_and_closed_state_own_cleanup() {
    for mode in 0..3 {
        reset();
        let mut session = facade(0);
        let digest = session.hash(MESSAGES[1]).unwrap();
        match mode {
            0 => drop(digest),
            1 => core::mem::forget(digest),
            _ => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _held = digest;
                    panic!("recoverable component unwind");
                }));
                assert!(result.is_err());
            }
        }
        assert_eq!(
            session.state(),
            if mode == 1 {
                State::Busy
            } else {
                State::Quarantined
            }
        );
        assert!(session.hash(MESSAGES[1]).is_err());
        session.close().unwrap();
        assert_eq!(session.state(), State::Closed);
        assert!(matches!(session.hash(MESSAGES[1]), Err(Error::Closed)));
        drop(session);
        MOCK.with(|l| {
            let l = l.borrow();
            assert_eq!(l.calls, [0, 1, 3]);
            assert_eq!(l.close_calls, 1);
            assert!(!l.live);
        });
    }
}

#[test]
fn facade_preflight_and_rehash_failure_preserve_their_distinct_states() {
    reset();
    let mut session = facade(6);
    assert!(matches!(session.hash(&[0; 1025]), Err(Error::Bounds)));
    assert_eq!(session.state(), State::Ready);
    MOCK.with(|l| assert!(l.borrow().calls.is_empty()));
    assert!(matches!(
        session.hash(MESSAGES[1]).unwrap().rehash(),
        Err(Error::Protocol)
    ));
    assert_eq!(session.state(), State::Quarantined);
    session.close().unwrap();
    MOCK.with(|l| assert_eq!(l.borrow().calls, [0, 1, 8, 9, 3]));
}
