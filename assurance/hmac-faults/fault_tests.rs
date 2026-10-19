//! Test-only synthetic hash faults against the copied, unchanged HMAC engine.
//! This checks composition ownership, not a hash kernel or compiler erasure.
extern crate std;

use crate::{Algorithm, Error, Hmac, algorithms::sealed};
use std::{cell::RefCell, panic::AssertUnwindSafe};

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    Error,
    Unwind,
}

struct Trace {
    step: usize,
    fail_at: usize,
    fault: Fault,
    live: usize,
    created: usize,
    dropped: usize,
    scratch: usize,
}

std::thread_local! {
    static TRACE: RefCell<Trace> = const { RefCell::new(Trace {
        step: 0, fail_at: 0, fault: Fault::None,
        live: 0, created: 0, dropped: 0, scratch: 0,
    }) };
}

fn reset(fail_at: usize, fault: Fault) {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        assert_eq!(trace.live, 0, "previous case leaked a hash owner");
        *trace = Trace {
            step: 0,
            fail_at,
            fault,
            live: 0,
            created: 0,
            dropped: 0,
            scratch: 0,
        };
    });
}

fn checkpoint() -> Result<(), Error> {
    let fault = TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.step += 1;
        if trace.step == trace.fail_at {
            trace.fault
        } else {
            Fault::None
        }
    });
    assert!(fault != Fault::Unwind, "synthetic hash unwind");
    if fault == Fault::Error {
        Err(Error::SecretMemory)
    } else {
        Ok(())
    }
}

// Invoked by an observer appended immediately AFTER the real Scratch::drop
// clearing statement in the private harness, while storage is still alive.
pub(crate) fn observe_scratch(bytes: &[u8]) {
    assert!(
        bytes.iter().all(|byte| *byte == 0),
        "HMAC scratch was not cleared"
    );
    TRACE.with(|trace| trace.borrow_mut().scratch += 1);
}

fn closed() -> usize {
    TRACE.with(|trace| {
        let trace = trace.borrow();
        assert_eq!(
            trace.live, 0,
            "hash owner retained after terminal operation"
        );
        assert_eq!(trace.created, trace.dropped);
        assert!(trace.scratch > 0, "scratch observer did not execute");
        trace.step
    })
}

struct State([u8; 32]);

impl Drop for State {
    fn drop(&mut self) {
        self.0.fill(0);
        TRACE.with(|trace| {
            let mut trace = trace.borrow_mut();
            trace.live -= 1;
            trace.dropped += 1;
        });
    }
}

enum Synthetic {}

impl Algorithm for Synthetic {
    const BLOCK_BYTES: usize = 64;
    const TAG_BYTES: usize = 32;
}

impl sealed::Hash for Synthetic {
    type State = State;

    fn start() -> State {
        TRACE.with(|trace| {
            let mut trace = trace.borrow_mut();
            trace.live += 1;
            trace.created += 1;
        });
        State([0xa5; 32])
    }

    fn update(state: &mut State, input: &[u8]) -> Result<(), Error> {
        checkpoint()?;
        // A synthetic length rejection is atomic, as required by each adapter.
        if input == b"length rejection" {
            return Err(Error::MessageTooLong);
        }
        for (index, byte) in input.iter().enumerate() {
            state.0[index % 32] ^= byte;
        }
        Ok(())
    }

    fn finish(
        state: State,
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        checkpoint()?;
        output.copy_from_slice(&state.0);
        // Error/unwind AFTER writing tests HMAC's scratch Drop, rather than
        // assuming the adapter always returns without touching its destination.
        checkpoint()?;
        consume(output)
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Public,
    Secret,
    Verify,
    Cancel,
}

fn operation(key: &[u8], mode: Mode, output: &mut [u8; 32]) -> Result<(), Error> {
    let mut mac = Hmac::<Synthetic>::new(key)?;
    mac.update(b"message")?;
    match mode {
        Mode::Public => {
            let _ = mac.finalize_tag(output)?;
        }
        Mode::Secret => {
            let tag = mac.finalize_secret(output)?;
            drop(tag);
        }
        Mode::Verify => {
            let _ = mac.verify(output)?;
        }
        Mode::Cancel => mac.cancel(),
    }
    Ok(())
}

#[test]
fn every_hash_boundary_releases_owners() {
    let mut injected = 0;
    for key in [&b"short"[..], &[0x5a; 65][..]] {
        for mode in [Mode::Public, Mode::Secret, Mode::Verify, Mode::Cancel] {
            reset(0, Fault::None);
            let mut output = [0x77; 32];
            assert!(operation(key, mode, &mut output).is_ok());
            let steps = closed();
            assert!(steps >= 3);
            for fail_at in 1..=steps {
                for fault in [Fault::Error, Fault::Unwind] {
                    injected += 1;
                    reset(fail_at, fault);
                    let mut output = [0x77; 32];
                    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                        operation(key, mode, &mut output)
                    }));
                    match fault {
                        Fault::Error => assert!(matches!(result, Ok(Err(Error::SecretMemory)))),
                        Fault::Unwind => assert!(result.is_err()),
                        Fault::None => unreachable!(),
                    }
                    closed();
                    match mode {
                        Mode::Secret => {
                            // Constructor/update errors precede destination
                            // admission; only finalization owns the output.
                            let construction_and_update = if key.len() > 64 { 6 } else { 3 };
                            let expected = if fail_at > construction_and_update {
                                0
                            } else {
                                0x77
                            };
                            assert_eq!(output, [expected; 32]);
                        }
                        _ => assert_eq!(output, [0x77; 32]),
                    }
                }
            }
        }
    }
    assert_eq!(injected, 132, "fault population changed");
}

#[test]
fn length_rejection_preserves_stream() {
    reset(0, Fault::None);
    let mut expected = [0; 32];
    assert!(Hmac::<Synthetic>::authenticate(b"key", b"prefixsuffix", &mut expected).is_ok());
    closed();
    reset(0, Fault::None);
    let Ok(mut mac) = Hmac::<Synthetic>::new(b"key") else {
        unreachable!()
    };
    // Use empty input around a rejection so synthetic block partitioning does
    // not itself change the model digest.
    assert!(mac.update(b"").is_ok());
    assert_eq!(mac.update(b"length rejection"), Err(Error::MessageTooLong));
    assert!(mac.update(b"prefixsuffix").is_ok());
    let mut actual = [0; 32];
    assert!(mac.finalize_tag(&mut actual).is_ok());
    assert_eq!(actual, expected);
    closed();
}

#[test]
fn invalid_destinations_reject_before_hash_finalization() {
    for secret in [false, true] {
        reset(0, Fault::None);
        let Ok(mac) = Hmac::<Synthetic>::new(b"key") else {
            unreachable!()
        };
        let before = TRACE.with(|trace| trace.borrow().step);
        let mut output = [0x77; 31];
        if secret {
            assert!(matches!(
                mac.finalize_secret(&mut output),
                Err(Error::TagLength)
            ));
            assert_eq!(output, [0; 31]);
        } else {
            assert!(matches!(
                mac.finalize_tag(&mut output),
                Err(Error::TagLength)
            ));
            assert_eq!(output, [0x77; 31]);
        }
        assert_eq!(closed(), before);
    }
}

#[test]
fn invalid_tag_policy_constructs_no_hash_owners() {
    for length in [0, 15, 33, usize::MAX] {
        reset(0, Fault::None);
        assert!(matches!(
            Hmac::<Synthetic>::with_tag_length(b"key", length),
            Err(Error::TagLength)
        ));
        TRACE.with(|trace| {
            let trace = trace.borrow();
            assert_eq!(trace.step, 0);
            assert_eq!(trace.created, 0);
            assert_eq!(trace.live, 0);
        });
    }
}

#[test]
fn scratch_clears_populated_regions() {
    reset(0, Fault::None);
    {
        let mut scratch = crate::scratch::Scratch::<144>::new();
        scratch.0.fill(0xa5);
    }
    assert_eq!(closed(), 0);
}
