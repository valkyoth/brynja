use super::*;
use std::cell::RefCell;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Call(Step),
    Clear(bool),
}
#[derive(Default)]
struct State {
    fail: Option<Step>,
    events: Vec<Event>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
fn reset(fail: Option<Step>) {
    STATE.with(|state| {
        *state.borrow_mut() = State {
            fail,
            events: Vec::new(),
        }
    });
}
pub(super) fn hit(step: Step) -> bool {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.events.push(Event::Call(step));
        if state.fail == Some(step) {
            state.fail = None;
            true
        } else {
            false
        }
    })
}
pub(super) fn join_fails() -> bool {
    STATE.with(|state| state.borrow().fail == Some(Step::Join))
}
pub(super) fn cleared(zero: bool) {
    STATE.with(|state| state.borrow_mut().events.push(Event::Clear(zero)));
}
fn events() -> Vec<Event> {
    STATE.with(|state| state.borrow().events.clone())
}

#[test]
fn foreign_owner_never_clears_unmaps_or_launches() -> Result<(), Error> {
    reset(None);
    let mut owner = Mapping::new(262144, 1048576)?;
    owner.bytes_mut().fill(0x5a);
    // Model a child whose inherited metadata addresses a different live mapping.
    // PID zero cannot be the current user process. The real owner retains it.
    let mut foreign = Mapping {
        base: owner.base,
        data: owner.data,
        layout: owner.layout,
        used: owner.used,
        admitted: true,
        owner_pid: 0,
    };
    reset(None);
    foreign.clear();
    let mut ran = false;
    assert_eq!(foreign.run(|| ran = true), Err(Error::ThreadAttributes));
    assert!(!ran);
    foreign.close()?;
    assert!(foreign.base.is_none());
    assert!(!foreign.admitted);
    assert_eq!(foreign.used, 0);
    drop(foreign);
    assert!(events().is_empty());
    assert!(owner.bytes().iter().all(|b| *b == 0x5a));
    owner.verify_native()?;
    owner.clear();
    assert!(owner.bytes().iter().all(|b| *b == 0));
    Ok(())
}

#[test]
fn acquisition_faults_rollback_without_exposing_or_clearing() {
    for step in [Step::Map, Step::Fork, Step::Access, Step::Lock] {
        reset(Some(step));
        assert!(Mapping::new(32, 65536).is_err());
        let events = events();
        assert!(!events.iter().any(|e| matches!(e, Event::Clear(_))));
        assert_eq!(
            events.contains(&Event::Call(Step::Unmap)),
            step != Step::Map
        );
    }
    reset(None);
}
#[test]
fn release_failure_retains_cleared_owner_for_retry() -> Result<(), Error> {
    reset(None);
    let mut mapping = Mapping::new(32, 65536)?;
    mapping.bytes_mut().fill(0x5a);
    reset(Some(Step::Unmap));
    assert_eq!(mapping.close(), Err(Error::Release));
    assert!(mapping.base.is_some());
    assert!(mapping.bytes().iter().all(|b| *b == 0));
    assert_eq!(events(), [Event::Clear(true), Event::Call(Step::Unmap)]);
    mapping.close()?;
    assert!(mapping.base.is_none());
    reset(None);
    Ok(())
}
#[test]
fn worker_placement_join_and_whole_payload_clear() -> Result<(), Error> {
    reset(None);
    let mut stack = Mapping::new(262144, 1048576)?;
    super::observe::verify(&stack)?;
    stack.bytes_mut().fill(0x5a);
    let low = stack.data.as_ptr() as usize;
    let high = low
        .checked_add(stack.layout.payload)
        .ok_or(Error::InvalidSize)?;
    let mut placed = false;
    reset(None);
    stack.run(|| {
        let marker = core::hint::black_box([0x37u8; 512]);
        let address = marker.as_ptr() as usize;
        placed = address >= low && address.checked_add(512).is_some_and(|end| end <= high);
        core::hint::black_box(&marker);
    })?;
    assert!(placed);
    super::observe::verify(&stack)?;
    assert!(stack.bytes().iter().all(|b| *b == 0));
    let events = events();
    assert!(
        events
            .windows(2)
            .any(|pair| pair == [Event::Call(Step::Join), Event::Clear(true)])
    );
    Ok(())
}
#[test]
fn worker_setup_rejections_leave_reusable_owner() -> Result<(), Error> {
    reset(None);
    let mut stack = Mapping::new(262144, 1048576)?;
    for step in [Step::Init, Step::Stack, Step::Create] {
        reset(Some(step));
        let mut ran = false;
        assert!(stack.run(|| ran = true).is_err());
        assert!(!ran);
        reset(None);
        stack.run(|| ran = true)?;
        assert!(ran);
    }
    Ok(())
}
#[test]
#[cfg(panic = "unwind")]
fn worker_unwind_is_joined_and_cleared() -> Result<(), Error> {
    reset(None);
    let mut stack = Mapping::new(262144, 1048576)?;
    assert_eq!(
        stack.run(|| assert!(std::hint::black_box(false), "synthetic worker panic")),
        Err(Error::WorkerPanicked)
    );
    assert!(stack.bytes().iter().all(|b| *b == 0));
    stack.run(|| {})?;
    Ok(())
}
#[test]
fn fatal_lifecycle_failure_child() -> Result<(), Error> {
    let Ok(mode) = std::env::var("BRYNJA_DARWIN_FAILURE_CHILD") else {
        return Ok(());
    };
    reset(None);
    let mut stack = Mapping::new(262144, 1048576)?;
    if mode == "foreign-read" || mode == "foreign-write" {
        stack.owner_pid = 0;
        if mode == "foreign-read" {
            core::hint::black_box(stack.bytes());
        } else {
            core::hint::black_box(stack.bytes_mut());
        }
        assert!(
            std::hint::black_box(false),
            "foreign mapping access returned"
        );
    }
    reset(Some(if mode == "join" {
        Step::Join
    } else {
        Step::Destroy
    }));
    let _ = stack.run(|| {});
    assert!(
        std::hint::black_box(false),
        "fatal native lifecycle failure returned"
    );
    Ok(())
}
#[test]
fn join_and_attribute_destroy_failures_abort() -> Result<(), std::io::Error> {
    use std::os::unix::process::ExitStatusExt;
    for mode in ["join", "destroy", "foreign-read", "foreign-write"] {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "macos_resident::resource::darwin::tests::fatal_lifecycle_failure_child",
                "--nocapture",
            ])
            .env("BRYNJA_DARWIN_FAILURE_CHILD", mode)
            .output()?;
        assert_eq!(output.status.signal(), Some(6));
    }
    Ok(())
}
#[cfg(feature = "macos-resident-hmac-acceleration")]
#[test]
#[ignore = "requires native compiled SHA-256 features; explicit HMAC startup regression"]
fn hmac_preentry_failures_preserve_session() -> Result<(), crate::macos_resident::hmac::Error> {
    use crate::macos_resident::hmac::Error as HmacError;
    use crate::macos_resident::hmac::{
        Bits, Cancellation, CompiledSession, Limits, Request, Sha256, TagPolicy,
    };
    use brynja_crypto_cpu::static_execution::Kernel;
    reset(None);
    let limits = Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536,
        max_key_bytes: 8192,
        max_message_bits: 200000,
        max_chunks: 16,
    };
    let mut session = CompiledSession::<Sha256>::new(TagPolicy::Full, Kernel::ArmSha256, limits)?;
    let request = || Request {
        key: b"key",
        chunks: &[b"message"],
        tail: Bits::empty(),
    };
    let expected = session.authenticate(b"key", b"message")?.expose().to_vec();
    for step in [Step::Init, Step::Stack, Step::Create] {
        for verifying in [false, true] {
            // The failure must also clear a forgotten prior output loan.
            core::mem::forget(session.authenticate(b"key", b"message")?);
            reset(Some(step));
            let result = if verifying {
                session
                    .verify(request(), &expected, &Cancellation::new())
                    .map(|_| ())
            } else {
                session.authenticate(b"key", b"message").map(|_| ())
            };
            let error = if step == Step::Create {
                Error::ThreadStart
            } else {
                Error::ThreadAttributes
            };
            assert_eq!(result, Err(HmacError::Resource(error)));
            assert!(!events().contains(&Event::Call(Step::Join)));
            assert!(!session.is_quarantined());
            session.assert_preentry_cleared();
            assert_eq!(session.authenticate(b"key", b"message")?.expose(), expected);
            assert!(session.verify(request(), &expected, &Cancellation::new())?);
        }
    }
    Ok(())
}
