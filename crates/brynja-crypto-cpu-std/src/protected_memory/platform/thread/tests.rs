use super::{Error, Mapping, Step};
use std::cell::{Cell, RefCell};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

thread_local! {
    static FAILURE: Cell<Option<Step>> = const { Cell::new(None) };
    static JOIN_FAILURE: Cell<bool> = const { Cell::new(false) };
    static JOINS: Cell<usize> = const { Cell::new(0) };
    static DESTROYS: Cell<usize> = const { Cell::new(0) };
    static EXIT_PROBE: RefCell<Option<ExitProbe>> = const { RefCell::new(None) };
}
pub(super) fn fail(step: Step) -> bool {
    FAILURE.with(|slot| {
        if slot.get() == Some(step) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}
pub(super) fn fail_join() -> bool {
    JOIN_FAILURE.with(Cell::get)
}
pub(super) fn joined() {
    JOINS.with(|slot| slot.set(slot.get().saturating_add(1)));
}
pub(super) fn destroyed() {
    DESTROYS.with(|n| n.set(n.get().saturating_add(1)));
}

struct ExitProbe(Arc<AtomicUsize>);
impl Drop for ExitProbe {
    fn drop(&mut self) {
        self.0.store(2, Ordering::SeqCst);
    }
}

#[test]
fn public_stack_accepts_scoped_output_loan_without_moving_its_owner() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    use crate::protected_memory::{ProtectedBytes, ProtectedStack};
    let mut stack = ProtectedStack::new(256 * 1024, 1024 * 1024)?;
    let mut output = ProtectedBytes::new(32, 1024 * 1024)?;
    for _ in 0..16 {
        let bytes = output.as_bytes_mut();
        stack.run(|| bytes.fill(0x58))?;
        assert_eq!(output.as_bytes(), &[0x58; 32]);
        output.clear();
        assert_eq!(output.as_bytes(), &[0; 32]);
    }
    assert!(stack.close().is_ok());
    assert!(output.close().is_ok());
    Ok(())
}

#[test]
fn callback_really_runs_on_the_locked_guarded_mapping_and_then_it_is_cleared() -> Result<(), Error>
{
    let _resources = crate::protected_memory::test_resource_guard();
    let mut mapping = Mapping::stack(256 * 1024, 1024 * 1024)?;
    let begin = mapping.data.as_ptr() as usize;
    let end = begin
        .checked_add(mapping.layout.payload)
        .ok_or(Error::InvalidSize)?;
    let witnessed = AtomicUsize::new(0);
    let mut output = [0u8; 16];
    mapping.run(|| {
        let stack_marker = [0xb5u8; 256];
        let address = stack_marker.as_ptr() as usize;
        assert!(
            begin <= address && address < end,
            "callback was not on the supplied stack"
        );
        std::hint::black_box(&stack_marker);
        let maps = std::fs::read_to_string("/proc/self/smaps");
        assert!(maps.is_ok());
        if let Ok(maps) = maps {
            let mut selected = false;
            let mut verified = false;
            for line in maps.lines() {
                if let Some((range, _)) = line.split_once(' ')
                    && let Some((start, stop)) = range.split_once('-')
                    && let (Ok(start), Ok(stop)) = (
                        usize::from_str_radix(start, 16),
                        usize::from_str_radix(stop, 16),
                    )
                {
                    selected = start <= address && address < stop;
                }
                if selected && line.starts_with("VmFlags:") {
                    for required in ["lo", "dd", "dc"] {
                        assert!(
                            line.split_whitespace().any(|flag| flag == required),
                            "missing {required}"
                        );
                    }
                    verified = true;
                }
            }
            assert!(verified);
        }
        output.fill(0x97);
        witnessed.store(address, Ordering::SeqCst);
    })?;
    assert!((begin..end).contains(&witnessed.load(Ordering::SeqCst)));
    assert_eq!(output, [0x97; 16]);
    assert!(mapping.bytes().iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn borrowed_work_and_native_thread_destructors_finish_before_clear_and_return() -> Result<(), Error>
{
    let _resources = crate::protected_memory::test_resource_guard();
    let mut mapping = Mapping::stack(256 * 1024, 1024 * 1024)?;
    let stage = Arc::new(AtomicUsize::new(0));
    let child = Arc::clone(&stage);
    JOINS.with(|n| n.set(0));
    mapping.run(move || {
        child.store(1, Ordering::SeqCst);
        EXIT_PROBE.with(|slot| *slot.borrow_mut() = Some(ExitProbe(child)));
    })?;
    assert_eq!(stage.load(Ordering::SeqCst), 2);
    assert_eq!(JOINS.with(Cell::get), 1);
    assert!(mapping.bytes().iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn unwind_is_caught_on_worker_and_stack_can_be_reused() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let mut mapping = Mapping::stack(256 * 1024, 1024 * 1024)?;
    JOINS.with(|n| n.set(0));
    assert_eq!(
        mapping.run(|| {
            let scratch = [0xc7u8; 2048];
            std::hint::black_box(&scratch);
            assert!(
                std::hint::black_box(false),
                "intentional protected-stack unwind probe"
            );
        }),
        Err(Error::WorkerPanicked)
    );
    assert_eq!(JOINS.with(Cell::get), 1);
    assert!(mapping.bytes().iter().all(|byte| *byte == 0));
    let mut done = false;
    mapping.run(|| done = true)?;
    assert!(done);
    assert_eq!(JOINS.with(Cell::get), 2);
    assert!(mapping.bytes().iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn failed_startup_never_runs_callback_or_falls_back() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let mut mapping = Mapping::stack(256 * 1024, 1024 * 1024)?;
    for step in [Step::Init, Step::Stack, Step::Create] {
        FAILURE.with(|slot| slot.set(Some(step)));
        JOINS.with(|n| n.set(0));
        DESTROYS.with(|n| n.set(0));
        let mut called = false;
        let error = if step == Step::Create {
            Error::ThreadStart
        } else {
            Error::ThreadAttributes
        };
        assert_eq!(mapping.run(|| called = true), Err(error));
        assert!(!called);
        assert_eq!(JOINS.with(Cell::get), 0);
        assert_eq!(DESTROYS.with(Cell::get), usize::from(step != Step::Init));
        assert!(mapping.bytes().iter().all(|byte| *byte == 0));
        mapping.run(|| called = true)?;
        assert!(called);
    }
    Ok(())
}

#[test]
fn undersized_or_over_budget_stacks_are_rejected() {
    let _resources = crate::protected_memory::test_resource_guard();
    assert!(matches!(
        Mapping::stack(65535, 1 << 20),
        Err(Error::InvalidSize)
    ));
    assert!(matches!(
        Mapping::stack(65536, 65536),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        Mapping::stack(usize::MAX, usize::MAX),
        Err(Error::InvalidSize)
    ));
}

#[test]
#[ignore = "invoked by parent in isolated child; must abort rather than return"]
fn join_failure_child() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let mut mapping = Mapping::stack(256 * 1024, 1024 * 1024)?;
    JOIN_FAILURE.with(|slot| slot.set(true));
    mapping.run(|| {
        std::hint::black_box([0x9du8; 256]);
    })?;
    // A returned success is a lifecycle soundness regression, not acceptable.
    Ok(())
}

#[test]
fn unexpected_join_failure_cannot_return_with_live_borrows() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    expect_abort("join_failure_child")
}

#[test]
#[ignore = "invoked by parent in isolated child; must abort rather than return"]
fn destroy_failure_child() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let mut mapping = Mapping::stack(256 * 1024, 1024 * 1024)?;
    FAILURE.with(|slot| slot.set(Some(Step::Destroy)));
    mapping.run(|| {})
}

#[test]
fn unexpected_attribute_destruction_failure_never_reports_success() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    expect_abort("destroy_failure_child")
}

fn expect_abort(test: &str) -> Result<(), Error> {
    use std::os::unix::process::ExitStatusExt;
    let binary = std::env::current_exe().map_err(|_| Error::ThreadStart)?;
    let child = std::process::Command::new("bash")
        .args([
            "-c",
            "ulimit -c 0 || exit 97; exec \"$@\"",
            "protected-stack-join",
        ])
        .arg(binary)
        .args(["--ignored", "--exact"])
        .arg(format!("protected_memory::platform::thread::tests::{test}"))
        .output()
        .map_err(|_| Error::ThreadStart)?;
    assert_eq!(
        child.status.signal(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    Ok(())
}
