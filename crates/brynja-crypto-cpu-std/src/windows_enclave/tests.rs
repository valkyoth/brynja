use super::{
    engine::{Driver, Engine},
    *,
};
use std::{cell::RefCell, rc::Rc};

#[derive(Default)]
struct Mock {
    fail: bool,
    calls: usize,
    closed: usize,
    unwind: bool,
}
struct TestDriver(Rc<RefCell<Mock>>);
impl TestDriver {
    fn step(&self) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.calls = m.calls.checked_add(1).ok_or(Error::Exhausted)?;
        if m.unwind {
            std::panic::resume_unwind(Box::new("controlled backend unwind"));
        }
        if m.fail { Err(Error::Protocol) } else { Ok(()) }
    }
}
impl Driver for TestDriver {
    fn begin(&mut self, _: &[u8], _: u64) -> Result<(), Error> {
        self.step()
    }
    fn rehash(&mut self) -> Result<(), Error> {
        self.step()
    }
    fn export(&mut self, out: &mut [u8; 32]) -> Result<(), Error> {
        out.fill(0x42);
        self.step()
    }
    fn cancel(&mut self) -> Result<(), Error> {
        self.step()
    }
    fn close(&mut self) -> Result<(), Error> {
        let next = self
            .0
            .borrow()
            .closed
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.0.borrow_mut().closed = next;
        self.step()
    }
}
fn fixture() -> (Engine<TestDriver>, Rc<RefCell<Mock>>) {
    let m = Rc::new(RefCell::new(Mock::default()));
    (Engine::new(TestDriver(m.clone())), m)
}
#[test]
fn request_bounds_do_not_quarantine_but_protocol_errors_do() -> Result<(), Error> {
    let (mut e, m) = fixture();
    assert_eq!(e.begin(&[0; 1025]), Err(Error::Bounds));
    assert_eq!(m.borrow().calls, 0);
    e.begin(b"abc")?;
    assert_eq!(e.begin(b"other"), Err(Error::Busy));
    e.cancel()?;
    e.begin(b"reusable")?;
    e.export(&mut [0; 32])?;
    m.borrow_mut().fail = true;
    assert_eq!(e.begin(b"failure"), Err(Error::Protocol));
    assert_eq!(e.state(), State::Quarantined);
    assert_eq!(e.begin(b"no fallback"), Err(Error::Quarantined));
    Ok(())
}
#[test]
fn output_is_transactional_on_failure_and_rehash_is_terminal() -> Result<(), Error> {
    let (mut e, m) = fixture();
    e.begin(b"abc")?;
    m.borrow_mut().fail = true;
    let mut out = [0xa5; 32];
    assert_eq!(e.export(&mut out), Err(Error::Protocol));
    assert_eq!(out, [0xa5; 32]);
    assert_eq!(e.state(), State::Quarantined);
    let (mut e, m) = fixture();
    e.begin(b"abc")?;
    m.borrow_mut().fail = true;
    assert_eq!(e.rehash(), Err(Error::Protocol));
    assert_eq!(e.state(), State::Quarantined);
    Ok(())
}
#[test]
fn abandoned_and_forgotten_results_stay_owned_until_close() -> Result<(), Error> {
    let (mut e, m) = fixture();
    e.begin(b"abc")?;
    e.abandon();
    assert_eq!(e.state(), State::Quarantined);
    e.close()?;
    e.close()?;
    assert_eq!(m.borrow().closed, 1);
    assert_eq!(e.begin(b"no reopen"), Err(Error::Closed));
    let (mut e, m) = fixture();
    e.begin(b"forgotten")?;
    drop(e);
    assert_eq!(m.borrow().closed, 1);
    Ok(())
}
#[test]
fn close_failure_never_reports_closed_and_unwind_never_reopens() -> Result<(), Error> {
    let (mut e, m) = fixture();
    e.begin(b"abc")?;
    m.borrow_mut().fail = true;
    assert_eq!(e.close(), Err(Error::Protocol));
    assert_eq!(e.state(), State::Quarantined);
    m.borrow_mut().fail = false;
    e.close()?;
    let (mut e, m) = fixture();
    m.borrow_mut().unwind = true;
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.begin(b"abc"))).is_err());
    assert_eq!(e.state(), State::Quarantined);
    m.borrow_mut().unwind = false;
    Ok(())
}
#[test]
fn headers_and_regions_reject_overflow_and_overlap() -> Result<(), Error> {
    assert_eq!(protocol::header(b"abc", 0), Err(Error::Bounds));
    assert_eq!(protocol::header(&[0; 1025], 1), Err(Error::Bounds));
    let h = protocol::header(b"", 1)?;
    assert_eq!(h.get(16..), Some([0; 16].as_slice()));
    assert!(protocol::regions(4096, [4096, 8192], [32, 1170]));
    assert!(!protocol::regions(4096, [4096, 4110], [32, 1170]));
    assert!(!protocol::inside(0, usize::MAX, usize::MAX, 1));
    assert!(!protocol::inside(4096, 65536, 4095, 1));
    Ok(())
}
#[test]
fn invalid_policy_and_arbitrary_images_never_admit() {
    let p = ImagePolicy::reviewed_sha256([0; 32], [0; 16], [0; 16], 0, 0, [0; 2]);
    assert!(!p.valid());
    for n in [0, 1, 511, 512, 1024] {
        assert!(image::admit(&vec![0; n], &p).is_err());
    }
}

#[test]
fn protocol_rejects_every_changed_receipt_word() -> Result<(), Error> {
    let context = protocol::Context {
        base: 0x100000,
        operation: 1,
        length: 3,
        epoch: 1,
        generation: 0,
        low: 0x101000,
        slot: 0x121000,
        phase: 2,
        slot_phase: 1,
        locked: false,
        slot_locked: true,
        error: false,
    };
    assert!(protocol::inside(
        context.base,
        0x10000000,
        context.slot,
        4096
    ));
    let outer = [0x101000, 0x111000, 0x110e00, 0x110f00, 31, 1, 1];
    let guards = [0x100000, 0x111000, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let inner = [2, 0x120000, 0x121000, 1, 1, 0, 0, 0, 1, 1];
    let input = [1, 1, 1, 1, 0x101000, 0x101040, 0x101600, 0x101c00, 3, 1, 1];
    let rehash = [0; 9];
    context.inspect(95, outer, guards, inner, input, rehash)?;
    for i in 0..outer.len() {
        let mut changed = outer;
        if let Some(word) = changed.get_mut(i) {
            *word = usize::MAX;
        }
        assert!(
            context
                .inspect(95, changed, guards, inner, input, rehash)
                .is_err()
        );
    }
    for i in 0..guards.len() {
        let mut changed = guards;
        if let Some(word) = changed.get_mut(i) {
            *word = usize::MAX;
        }
        assert!(
            context
                .inspect(95, outer, changed, inner, input, rehash)
                .is_err()
        );
    }
    for i in 0..inner.len() {
        let mut changed = inner;
        if let Some(word) = changed.get_mut(i) {
            *word = usize::MAX;
        }
        assert!(
            context
                .inspect(95, outer, guards, changed, input, rehash)
                .is_err()
        );
    }
    for i in 0..input.len() {
        let mut changed = input;
        if let Some(word) = changed.get_mut(i) {
            *word = usize::MAX;
        }
        assert!(
            context
                .inspect(95, outer, guards, inner, changed, rehash)
                .is_err()
        );
    }
    for i in 0..rehash.len() {
        let mut changed = rehash;
        if let Some(word) = changed.get_mut(i) {
            *word = usize::MAX;
        }
        assert!(
            context
                .inspect(95, outer, guards, inner, input, changed)
                .is_err()
        );
    }
    Ok(())
}
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
#[test]
fn unsupported_target_never_opens_an_ordinary_session() {
    static P: ImagePolicy = ImagePolicy::reviewed_sha256([1; 32], [2; 16], [3; 16], 1, 1, [0; 2]);
    assert!(matches!(
        Session::open(std::path::Path::new("C:\\example.dll"), &P),
        Err(Error::Unsupported)
    ));
}
