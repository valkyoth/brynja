extern crate std;
use super::*;
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};

fn run<R>(
    issuer: &mut Issuer,
    operation: impl for<'a> FnOnce(&mut ResultHandle<'a>) -> R,
) -> Result<R, Error> {
    let mut workspace = Sha256Workspace::new();
    let mut output = [0xa5; 32];
    let result = issuer.sha256(&mut workspace, &mut output, b"abc", operation);
    assert_eq!(output, [0; 32]);
    result
}

#[test]
fn successful_export_is_single_use_and_clears() {
    let mut issuer = Issuer::new(7).unwrap();
    let mut published = Vec::new();
    run(&mut issuer, |handle| {
        let token = handle.token();
        assert_eq!(token, [7, 1]);
        assert_eq!(
            handle.export_public(token, PUBLIC_OUTPUT, |data| {
                published.extend_from_slice(data);
                true
            }),
            Ok(())
        );
        assert_eq!(
            handle.export_public(token, PUBLIC_OUTPUT, |_| panic!("replay exported")),
            Err(Error::Spent)
        );
        assert_eq!(handle.cancel(token), Err(Error::Spent));
    })
    .unwrap();
    assert_eq!(
        published.as_slice(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
}

#[test]
fn wrong_identity_stale_future_and_missing_flag_are_terminal() {
    for (token, flag) in [
        ([8, 1], PUBLIC_OUTPUT),
        ([7, 0], PUBLIC_OUTPUT),
        ([7, 2], PUBLIC_OUTPUT),
        ([7, 1], 0),
        ([7, 1], PUBLIC_OUTPUT + 1),
    ] {
        let mut issuer = Issuer::new(7).unwrap();
        run(&mut issuer, |handle| {
            assert_eq!(
                handle.export_public(token, flag, |_| panic!("bad request exported")),
                Err(Error::Rejected)
            );
            assert_eq!(
                handle.export_public(handle.token(), PUBLIC_OUTPUT, |_| panic!("reopened")),
                Err(Error::Spent)
            );
        })
        .unwrap();
    }
    let mut issuer = Issuer::new(7).unwrap();
    let old = run(&mut issuer, |handle| handle.token()).unwrap();
    run(&mut issuer, |handle| {
        assert_eq!(handle.token(), [7, 2]);
        assert_eq!(
            handle.export_public(old, PUBLIC_OUTPUT, |_| panic!("old scope exported")),
            Err(Error::Rejected)
        );
    })
    .unwrap();
}

#[test]
fn cancellation_abandonment_and_failed_copy_clear() {
    let mut issuer = Issuer::new(9).unwrap();
    run(&mut issuer, |handle| {
        assert_eq!(handle.cancel(handle.token()), Ok(()));
        assert_eq!(
            handle.export_public(handle.token(), PUBLIC_OUTPUT, |_| panic!(
                "cancelled result exported"
            )),
            Err(Error::Spent)
        );
    })
    .unwrap();
    run(&mut issuer, |handle| {
        assert_eq!(handle.cancel([9, 0]), Err(Error::Rejected));
        assert_eq!(handle.cancel(handle.token()), Err(Error::Spent));
    })
    .unwrap();
    run(&mut issuer, |_| ()).unwrap(); // Independent owner survives abandoned handle.
    let mut partial = Vec::new();
    run(&mut issuer, |handle| {
        assert_eq!(
            handle.export_public(handle.token(), PUBLIC_OUTPUT, |bytes| {
                partial.extend_from_slice(&bytes[..7]);
                false
            }),
            Err(Error::Copy)
        );
        assert_eq!(handle.cancel(handle.token()), Err(Error::Spent));
    })
    .unwrap();
    assert_eq!(partial.len(), 7); // Deliberately no host rollback claim.
}

#[test]
fn callback_and_copy_unwind_clear_but_abort_is_not_tested() {
    for in_copy in [false, true] {
        let mut issuer = Issuer::new(10).unwrap();
        let mut workspace = Sha256Workspace::new();
        let mut output = [0xa5; 32];
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            issuer
                .sha256(&mut workspace, &mut output, b"abc", |handle| {
                    if in_copy {
                        handle
                            .export_public(handle.token(), PUBLIC_OUTPUT, |_| panic!("copy fault"))
                            .unwrap();
                    }
                    panic!("operation fault");
                })
                .unwrap();
        }));
        assert!(panicked.is_err());
        assert_eq!(output, [0; 32]);
        run(&mut issuer, |handle| assert_eq!(handle.token(), [10, 2])).unwrap();
    }
}

#[test]
fn sequence_exhaustion_never_wraps_or_invokes_callback() {
    assert!(matches!(Issuer::new(0), Err(Error::Identity)));
    let mut issuer = Issuer::new(11).unwrap();
    issuer.last = u64::MAX - 1;
    run(&mut issuer, |handle| {
        assert_eq!(handle.token(), [11, u64::MAX])
    })
    .unwrap();
    for _ in 0..3 {
        assert_eq!(
            run(&mut issuer, |_| panic!("exhausted callback")),
            Err(Error::Exhausted)
        );
        assert_eq!(issuer.last, u64::MAX);
    }
}

#[test]
fn all_message_lengths_repeat_without_stale_result_reuse() {
    let mut issuer = Issuer::new(12).unwrap();
    let mut workspace = Sha256Workspace::new();
    let mut output = [0; 32];
    let mut input = [0; 1024];
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let count = Cell::new(0_u64);
    for length in 0..=1024 {
        issuer
            .sha256(&mut workspace, &mut output, &input[..length], |handle| {
                assert_eq!(handle.token(), [12, length as u64 + 1]);
                handle
                    .export_public(handle.token(), PUBLIC_OUTPUT, |digest| {
                        assert_eq!(
                            digest,
                            brynja_hash_sha2::sha256(&input[..length])
                                .unwrap()
                                .as_bytes()
                        );
                        count.set(count.get() + 1);
                        true
                    })
                    .unwrap();
            })
            .unwrap();
        assert_eq!(output, [0; 32]);
    }
    assert_eq!(count.get(), 1025);
}
