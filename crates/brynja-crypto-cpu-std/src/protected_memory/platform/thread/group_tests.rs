use super::{Error, Mapping, Step};
use std::cell::{Cell, RefCell};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

thread_local! {
    static FAILURE: Cell<Option<(Step, usize)>> = const { Cell::new(None) };
    static UNWIND_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
    static JOIN_FAILURE: Cell<bool> = const { Cell::new(false) };
    static EXIT: RefCell<Option<Exit>> = const { RefCell::new(None) };
}
pub(super) fn fail(step: Step) -> bool {
    FAILURE.with(|slot| match slot.get() {
        Some((wanted, remaining)) if wanted == step => {
            slot.set(remaining.checked_sub(1).map(|n| (wanted, n)));
            remaining == 0
        }
        _ => false,
    })
}
pub(super) fn fail_join() -> bool {
    JOIN_FAILURE.with(Cell::get)
}
pub(super) fn launched() {
    UNWIND_AFTER.with(|slot| {
        if let Some(remaining) = slot.get() {
            slot.set(remaining.checked_sub(1));
            assert!(
                remaining != 0,
                "intentional coordinator unwind after launch"
            );
        }
    });
}
struct Exit(Arc<AtomicUsize>);
impl Drop for Exit {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn stacks(n: usize) -> Result<Vec<Mapping>, Error> {
    (0..n).map(|_| Mapping::stack(262144, 1048576)).collect()
}
fn cleared(mappings: &[Mapping]) {
    assert!(mappings.iter().all(|m| m.bytes().iter().all(|b| *b == 0)));
}
fn protections(address: usize) {
    let text = std::fs::read_to_string("/proc/self/smaps");
    assert!(text.is_ok());
    if let Ok(text) = text {
        let mut selected = false;
        let mut verified = false;
        for line in text.lines() {
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
                for flag in ["lo", "dd", "dc"] {
                    assert!(line.split_whitespace().any(|v| v == flag));
                }
                verified = true;
            }
        }
        assert!(verified);
    }
}

#[test]
fn concurrent_group_uses_disjoint_protected_stacks_and_borrowed_outputs() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    use crate::protected_memory::ProtectedBytes;
    for width in [2, 4] {
        let mut mappings = stacks(width)?;
        let ranges: Vec<_> = mappings
            .iter()
            .map(|m| {
                let start = m.data.as_ptr() as usize;
                start..start + m.layout.payload
            })
            .collect();
        let mut output = ProtectedBytes::new(width * 32, 65536)?;
        for _ in 0..3 {
            let arrived = AtomicUsize::new(0);
            let mut jobs: Vec<_> = output
                .as_bytes_mut()
                .chunks_exact_mut(32)
                .zip(&ranges)
                .map(|(slot, range)| {
                    let arrived = &arrived;
                    move || {
                        let marker = [0xb7; 256];
                        let address = marker.as_ptr() as usize;
                        assert!(range.contains(&address));
                        protections(address);
                        protections(slot.as_ptr() as usize);
                        arrived.fetch_add(1, Ordering::SeqCst);
                        let start = std::time::Instant::now();
                        while arrived.load(Ordering::SeqCst) < width
                            && start.elapsed().as_secs() < 3
                        {
                            std::thread::yield_now();
                        }
                        assert_eq!(
                            arrived.load(Ordering::SeqCst),
                            width,
                            "workers did not overlap"
                        );
                        slot.copy_from_slice(&marker[..32]);
                        std::hint::black_box(&marker);
                    }
                })
                .collect();
            super::run_group(mappings.iter_mut(), &mut jobs)?;
            drop(jobs);
            assert!(output.as_bytes().iter().all(|b| *b == 0xb7));
            output.clear();
            cleared(&mappings);
        }
    }
    Ok(())
}

#[test]
fn every_partial_launch_and_attribute_failure_joins_started_workers() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let mut mappings = stacks(4)?;
    for step in [Step::Init, Step::Stack, Step::Create] {
        for index in 0..4 {
            let done = Arc::new(AtomicUsize::new(0));
            let mut jobs: Vec<_> = (0..4)
                .map(|_| {
                    let done = Arc::clone(&done);
                    move || {
                        let scratch = [0x97; 2048];
                        std::hint::black_box(&scratch);
                        EXIT.with(|slot| *slot.borrow_mut() = Some(Exit(Arc::clone(&done))));
                    }
                })
                .collect();
            FAILURE.with(|s| s.set(Some((step, index))));
            let expected = if step == Step::Create {
                Error::ThreadStart
            } else {
                Error::ThreadAttributes
            };
            assert_eq!(
                super::run_group(mappings.iter_mut(), &mut jobs),
                Err(expected)
            );
            assert_eq!(
                done.load(Ordering::SeqCst),
                if step == Step::Create { index } else { 0 }
            );
            cleared(&mappings);
            super::run_group(mappings.iter_mut(), &mut jobs)?;
            assert_eq!(
                done.load(Ordering::SeqCst),
                4 + if step == Step::Create { index } else { 0 }
            );
            cleared(&mappings);
        }
    }
    Ok(())
}

#[test]
fn worker_and_coordinator_unwind_join_tls_clear_and_allow_reuse() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let mut mappings = stacks(4)?;
    for worker_panic in [false, true] {
        for index in 0..4 {
            let done = Arc::new(AtomicUsize::new(0));
            let mut jobs: Vec<_> = (0..4)
                .map(|job| {
                    let done = Arc::clone(&done);
                    move || {
                        let marker = [0xc7; 2048];
                        std::hint::black_box(&marker);
                        EXIT.with(|slot| *slot.borrow_mut() = Some(Exit(Arc::clone(&done))));
                        assert!(
                            !worker_panic || job != index,
                            "intentional group worker unwind"
                        );
                    }
                })
                .collect();
            if worker_panic {
                assert_eq!(
                    super::run_group(mappings.iter_mut(), &mut jobs),
                    Err(Error::WorkerPanicked)
                );
                assert_eq!(done.load(Ordering::SeqCst), 4);
            } else {
                UNWIND_AFTER.with(|s| s.set(Some(index)));
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    super::run_group(mappings.iter_mut(), &mut jobs)
                }));
                assert!(caught.is_err());
                assert_eq!(done.load(Ordering::SeqCst), index + 1);
            }
            cleared(&mappings);
            let completed = AtomicUsize::new(0);
            let mut healthy: Vec<_> = (0..4)
                .map(|_| {
                    || {
                        completed.fetch_add(1, Ordering::SeqCst);
                    }
                })
                .collect();
            super::run_group(mappings.iter_mut(), &mut healthy)?;
            assert_eq!(completed.load(Ordering::SeqCst), 4);
            cleared(&mappings);
        }
    }
    Ok(())
}

#[test]
fn group_shape_and_cap_are_rejected_before_launch() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    use crate::protected_memory::ProtectedStack;
    let mut empty: [ProtectedStack; 0] = [];
    let mut none: [fn(); 0] = [];
    assert_eq!(
        ProtectedStack::run_group(&mut empty, &mut none),
        Err(Error::InvalidSize)
    );
    let mut mappings = stacks(1)?;
    assert_eq!(
        super::run_group(mappings.iter_mut(), &mut none),
        Err(Error::InvalidSize)
    );
    let mut excessive = [|| {}; 65];
    // A size error must not even inspect a mapping or initialize attributes.
    struct Oversized;
    impl Iterator for Oversized {
        type Item = &'static mut Mapping;
        fn next(&mut self) -> Option<Self::Item> {
            assert!(std::hint::black_box(false), "unexpected mapping access");
            None
        }
        fn size_hint(&self) -> (usize, Option<usize>) {
            (65, Some(65))
        }
    }
    impl ExactSizeIterator for Oversized {}
    assert_eq!(
        super::run_group(Oversized, &mut excessive),
        Err(Error::ResourceLimit)
    );
    let mut output = [0usize; 2];
    let mut stacks = [
        ProtectedStack::new(262144, 1048576)?,
        ProtectedStack::new(262144, 1048576)?,
    ];
    let mut jobs: Vec<_> = output.iter_mut().map(|slot| move || *slot = 7).collect();
    ProtectedStack::run_group(&mut stacks, &mut jobs)?;
    drop(jobs);
    assert_eq!(output, [7; 2]);
    Ok(())
}

#[test]
#[ignore = "invoked in isolated child; unexpected join failure must abort"]
fn group_join_failure_child() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    let mut mappings = stacks(2)?;
    JOIN_FAILURE.with(|s| s.set(true));
    super::run_group(mappings.iter_mut(), &mut [|| {}; 2])
}

#[test]
fn group_join_failure_never_returns_borrowed_work() -> Result<(), Error> {
    let _resources = crate::protected_memory::test_resource_guard();
    use std::os::unix::process::ExitStatusExt;
    let child = std::process::Command::new("bash")
        .args([
            "-c",
            "ulimit -c 0 || exit 97; exec \"$@\"",
            "protected-group",
        ])
        .arg(std::env::current_exe().map_err(|_| Error::ThreadStart)?)
        .args([
            "--ignored",
            "--exact",
            "protected_memory::platform::thread::group_tests::group_join_failure_child",
        ])
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
