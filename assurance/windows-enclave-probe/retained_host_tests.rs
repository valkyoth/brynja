extern crate std;
use super::*;
use std::{
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    vec::Vec,
};

#[derive(Default)]
struct Ledger {
    calls: Vec<Outcome>,
    releases: usize,
    destroyed: usize,
    retained: usize,
}
struct Mock {
    ledger: Rc<RefCell<Ledger>>,
    corrupt: Option<(Outcome, usize)>,
    fail: Option<Outcome>,
    panic: Option<Outcome>,
    release_failure: bool,
    released: bool,
}
impl Mock {
    fn receipt(&mut self, generation: u64, outcome: Outcome) -> Result<Receipt, ()> {
        self.ledger.borrow_mut().calls.push(outcome);
        assert_ne!(self.panic, Some(outcome), "injected transport unwind");
        if self.fail == Some(outcome) {
            return Err(());
        }
        let mut receipt = Receipt {
            identity: 7,
            generation,
            outcome,
            worker_clear: true,
            result_clear: outcome != Outcome::Ready,
            deleted: outcome == Outcome::Released,
        };
        if let Some((which, field)) = self.corrupt {
            if which == outcome {
                match field {
                    0 => receipt.identity += 1,
                    1 => receipt.generation += 1,
                    2 => {
                        receipt.outcome = if outcome == Outcome::Ready {
                            Outcome::Exported
                        } else {
                            Outcome::Ready
                        }
                    }
                    3 => receipt.worker_clear = false,
                    4 => receipt.result_clear = !receipt.result_clear,
                    5 => receipt.deleted = !receipt.deleted,
                    _ => panic!("invalid test field"),
                }
            }
        }
        Ok(receipt)
    }
}
impl Driver for Mock {
    fn begin(&mut self, _: u8, generation: u64) -> Result<Receipt, ()> {
        self.receipt(generation, Outcome::Ready)
    }
    fn export(&mut self, generation: u64, staging: &mut [u8; 32]) -> Result<Receipt, ()> {
        staging[..17].fill(0x5a); // partial copy is never committed on failure
        let receipt = self.receipt(generation, Outcome::Exported)?;
        staging[17..].fill(0x5a);
        Ok(receipt)
    }
    fn cancel(&mut self, generation: u64) -> Result<Receipt, ()> {
        self.receipt(generation, Outcome::Cancelled)
    }
    fn release(&mut self, generation: u64) -> Result<Receipt, ()> {
        self.ledger.borrow_mut().releases += 1;
        if self.release_failure {
            return Err(());
        }
        self.released = true;
        self.receipt(generation, Outcome::Released)
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        let mut ledger = self.ledger.borrow_mut();
        if self.released {
            ledger.destroyed += 1;
        } else {
            ledger.retained += 1;
        }
    }
}
fn session() -> (Session<Mock>, Rc<RefCell<Ledger>>) {
    let ledger = Rc::new(RefCell::new(Ledger::default()));
    (
        Session::from_driver(
            Mock {
                ledger: ledger.clone(),
                corrupt: None,
                fail: None,
                panic: None,
                release_failure: false,
                released: false,
            },
            NonZeroU64::new(7).unwrap(),
        ),
        ledger,
    )
}
fn vector() -> PublicVector {
    PublicVector::new(1).unwrap()
}

#[test]
fn affine_result_retains_session_until_export_or_cancel() {
    let (mut owner, ledger) = session();
    let pending = owner.begin(vector()).unwrap();
    assert_eq!(ledger.borrow().releases, 0);
    let mut output = [0xcc; 32];
    pending.export_public(&mut output).unwrap();
    assert_eq!(output, [0x5a; 32]);
    assert_eq!(owner.state(), State::Ready);
    owner.begin(vector()).unwrap().cancel().unwrap();
    assert_eq!(owner.generation, 2);
    assert_eq!(ledger.borrow().releases, 0);
    owner.close().unwrap();
    owner.close().unwrap();
    assert_eq!(owner.state(), State::Closed);
    assert!(matches!(owner.begin(vector()), Err(Error::Closed)));
    drop(owner);
    assert_eq!(ledger.borrow().releases, 1);
    assert_eq!(ledger.borrow().destroyed, 1);
}

#[test]
fn abandonment_and_forget_never_reopen_or_drop_resource_early() {
    for forget in [false, true] {
        let (mut owner, ledger) = session();
        let pending = owner.begin(vector()).unwrap();
        if forget {
            core::mem::forget(pending);
        } else {
            drop(pending);
        }
        let state = if forget {
            State::Busy
        } else {
            State::Quarantined
        };
        assert_eq!(owner.state(), state);
        assert!(owner.begin(vector()).is_err());
        assert_eq!(ledger.borrow().releases, 0);
        assert_eq!(ledger.borrow().calls, [Outcome::Ready]);
        drop(owner);
        assert_eq!(ledger.borrow().releases, 1);
        assert_eq!(ledger.borrow().destroyed, 1);
    }
}

#[test]
fn every_receipt_field_is_bound_and_output_is_transactional() {
    for outcome in [
        Outcome::Ready,
        Outcome::Exported,
        Outcome::Cancelled,
        Outcome::Released,
    ] {
        for field in 0..6 {
            let (mut owner, _) = session();
            owner.driver.corrupt = Some((outcome, field));
            let mut output = [0xcc; 32];
            let result = match outcome {
                Outcome::Ready => owner.begin(vector()).map(drop),
                Outcome::Exported => owner.begin(vector()).unwrap().export_public(&mut output),
                Outcome::Cancelled => owner.begin(vector()).unwrap().cancel(),
                Outcome::Released => owner.close(),
            };
            assert!(result.is_err(), "outcome {outcome:?}, field {field}");
            assert_eq!(owner.state(), State::Quarantined);
            assert_eq!(output, [0xcc; 32]);
        }
    }
}

#[test]
fn failures_and_unwind_preserve_output_and_quarantine() {
    for outcome in [Outcome::Ready, Outcome::Exported, Outcome::Cancelled] {
        for unwind in [false, true] {
            let (mut owner, ledger) = session();
            if unwind {
                owner.driver.panic = Some(outcome);
            } else {
                owner.driver.fail = Some(outcome);
            }
            let mut output = [0xcc; 32];
            let result = catch_unwind(AssertUnwindSafe(|| match outcome {
                Outcome::Ready => owner.begin(vector()).map(drop),
                Outcome::Exported => owner.begin(vector()).unwrap().export_public(&mut output),
                Outcome::Cancelled => owner.begin(vector()).unwrap().cancel(),
                _ => unreachable!(),
            }));
            assert_eq!(result.is_err(), unwind);
            if let Ok(value) = result {
                assert!(value.is_err());
            }
            assert_eq!(output, [0xcc; 32]);
            assert_eq!(owner.state(), State::Quarantined);
            drop(owner);
            assert_eq!(ledger.borrow().destroyed, 1);
        }
    }
}

#[test]
fn unconfirmed_release_never_claims_closed_or_destruction() {
    let (mut owner, ledger) = session();
    owner.driver.release_failure = true;
    core::mem::forget(owner.begin(vector()).unwrap());
    assert_eq!(owner.close(), Err(Error::Release));
    assert_eq!(owner.state(), State::Quarantined);
    assert!(matches!(owner.begin(vector()), Err(Error::Quarantined)));
    drop(owner);
    assert_eq!(ledger.borrow().destroyed, 0);
    assert_eq!(ledger.borrow().retained, 1);
    assert_eq!(ledger.borrow().releases, 2);
}

#[test]
fn caller_unwind_abandons_without_foreign_cancel_and_release_can_retry() {
    let (mut owner, ledger) = session();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _pending = owner.begin(vector()).unwrap();
        panic!("caller unwinds while retaining a result");
    }));
    assert!(result.is_err());
    assert_eq!(owner.state(), State::Quarantined);
    assert_eq!(ledger.borrow().calls, [Outcome::Ready]);
    owner.driver.release_failure = true;
    assert_eq!(owner.close(), Err(Error::Release));
    owner.driver.release_failure = false;
    owner.close().unwrap();
    assert_eq!(owner.state(), State::Closed);
    drop(owner);
    assert_eq!(ledger.borrow().releases, 2);
    assert_eq!(ledger.borrow().destroyed, 1);
}

#[test]
fn bounds_and_generation_overflow_do_not_enter_transport() {
    assert!(PublicVector::new(20).is_err());
    assert!(PublicVector::new(255).is_err());
    let (mut owner, ledger) = session();
    owner.generation = u64::MAX;
    assert!(matches!(owner.begin(vector()), Err(Error::Exhausted)));
    assert_eq!(owner.state(), State::Quarantined);
    assert!(ledger.borrow().calls.is_empty());
}
