//! Unit-test-only checkpoints; no Cargo feature, runtime branch or test
//! dependency in the shipped library. These simulate software failures.
extern crate std;

#[cfg(any(
    all(
        feature = "chacha20poly1305-x86",
        target_arch = "x86_64",
        target_os = "linux",
        target_feature = "sse2"
    ),
    all(
        feature = "chacha20poly1305-neon",
        target_arch = "aarch64",
        target_endian = "little",
        target_feature = "neon",
        any(target_os = "linux", target_os = "macos")
    )
))]
mod paired;

use super::*;
use core::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    BeforePayload,
    AfterPayload,
    AfterDerivation,
    AfterFraming,
    BeforeCommit,
}

std::thread_local! { static PLAN: Cell<Option<(Stage, bool)>> = const { Cell::new(None) }; }

impl Stage {
    pub(super) fn check(self) -> Result<(), Error> {
        if let Some((stage, unwind)) = PLAN.get()
            && self == stage
        {
            PLAN.set(None);
            if unwind {
                resume_unwind(std::boxed::Box::new(self));
            }
            return Err(Error::Invariant);
        }
        Ok(())
    }
}

#[test]
fn public_operations_burn_once_and_commit_only_on_success() -> Result<(), Error> {
    let key = [0x6d; 32];
    let first = u64::MAX - 1;
    let new = || Sealer::from_reserved_range(&key, *b"test", first, 2);
    let plain = [0x42; 65];
    let mut ct = plain;
    let (nonce, tag) = new()?.seal_in_place(b"header", &mut ct, &mut [0; 65])?;
    let open = Opener::new(&key);
    for stage in [
        Stage::BeforePayload,
        Stage::AfterPayload,
        Stage::AfterDerivation,
        Stage::AfterFraming,
        Stage::BeforeCommit,
    ] {
        for unwind in [false, true] {
            for in_place in [false, true] {
                for sealing in [false, true] {
                    let mut send = new()?;
                    let initial = if !in_place {
                        [0xa5; 65]
                    } else if sealing {
                        plain
                    } else {
                        ct
                    };
                    let mut dst = initial;
                    let mut work = [0x57; 65];
                    PLAN.set(Some((stage, unwind)));
                    let result = catch_unwind(AssertUnwindSafe(|| match (sealing, in_place) {
                        (true, true) => {
                            send.seal_in_place(b"header", &mut dst, &mut work).map(drop)
                        }
                        (true, false) => {
                            send.seal(b"header", &plain, &mut dst, &mut work).map(drop)
                        }
                        (false, true) => {
                            open.open_in_place(nonce, b"header", &tag, &mut dst, &mut work)
                        }
                        (false, false) => {
                            open.open(nonce, b"header", &tag, &ct, &mut dst, &mut work)
                        }
                    }));
                    assert_eq!(PLAN.take(), None);
                    match result {
                        Ok(value) => {
                            assert!(!unwind);
                            assert_eq!(value, Err(Error::Invariant));
                        }
                        Err(payload) => {
                            assert!(unwind);
                            assert_eq!(payload.downcast_ref::<Stage>(), Some(&stage));
                        }
                    }
                    assert_eq!(dst, initial);
                    assert_eq!(work, [0; 65]);
                    if sealing {
                        let (next, _) = send.seal_in_place(b"header", &mut dst, &mut work)?;
                        assert_eq!(
                            next.split_at(4),
                            (b"test".as_slice(), u64::MAX.to_be_bytes().as_slice())
                        );
                        assert_eq!(
                            send.seal_in_place(&[], &mut [], &mut []),
                            Err(Error::Exhausted)
                        );
                    } else {
                        open.open(nonce, b"header", &tag, &ct, &mut dst, &mut work)?;
                        assert_eq!(dst, plain);
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn rejection_never_starts_payload_decryption() -> Result<(), Error> {
    let key = [0x12; 32];
    let mut ct = [0x68; 17];
    let mut work = [0; 17];
    let mut send = Sealer::from_reserved_range(&key, *b"test", 123, 1)?;
    let (nonce, mut tag) = send.seal_in_place(b"header", &mut ct, &mut work)?;
    *tag.first_mut().ok_or(Error::Invariant)? ^= 1;
    let before = ct;
    PLAN.set(Some((Stage::BeforePayload, false)));
    let result = Opener::new(&key).open_in_place(nonce, b"header", &tag, &mut ct, &mut work);
    assert_eq!(PLAN.take(), Some((Stage::BeforePayload, false)));
    assert_eq!(result, Err(Error::Authentication));
    assert_eq!(ct, before);
    assert_eq!(work, [0; 17]);
    Ok(())
}
