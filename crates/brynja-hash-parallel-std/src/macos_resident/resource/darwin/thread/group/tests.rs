use super::{Error, Mapping};
use std::cell::{Cell, RefCell};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

thread_local! {
    static PREPARE: Cell<Option<usize>> = const { Cell::new(None) };
    static LAUNCH: Cell<Option<usize>> = const { Cell::new(None) };
    static UNWIND: Cell<Option<usize>> = const { Cell::new(None) };
    static JOIN_FAILURE: Cell<bool> = const { Cell::new(false) };
    static JOINED: Cell<usize> = const { Cell::new(0) };
    static EXIT: RefCell<Option<Exit>> = const { RefCell::new(None) };
}
fn hit(slot: &Cell<Option<usize>>) -> bool {
    let Some(remaining) = slot.get() else {
        return false;
    };
    slot.set(remaining.checked_sub(1));
    remaining == 0
}
pub(super) fn prepare() -> Result<(), Error> {
    if PREPARE.with(hit) {
        Err(Error::ThreadAttributes)
    } else {
        Ok(())
    }
}
pub(super) fn before_launch() -> Result<(), Error> {
    if LAUNCH.with(hit) {
        Err(Error::ThreadStart)
    } else {
        Ok(())
    }
}
pub(super) fn after_launch() {
    assert!(!UNWIND.with(hit), "intentional coordinator unwind");
}
pub(super) fn fail_join() -> bool {
    JOIN_FAILURE.with(Cell::get)
}
pub(super) fn joined() {
    JOINED.with(|n| {
        assert_ne!(n.get(), usize::MAX, "test join counter overflow");
        n.set(n.get().saturating_add(1));
    });
}
struct Exit(Arc<AtomicUsize>);
impl Drop for Exit {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn stacks(width: usize) -> Result<Vec<Mapping>, Error> {
    (0..width).map(|_| Mapping::new(262144, 1048576)).collect()
}
fn cleared(mappings: &[Mapping]) {
    assert!(mappings.iter().all(|m| m.bytes().iter().all(|b| *b == 0)));
}

#[test]
fn concurrent_workers_use_disjoint_resident_stacks_and_borrowed_outputs() -> Result<(), Error> {
    for width in [1, 2, 4] {
        let mut mappings = stacks(width)?;
        let ranges: Vec<_> = mappings
            .iter()
            .map(|m| {
                assert_eq!(m.verify_native(), Ok(()));
                let start = m.data.as_ptr() as usize;
                start..start + m.layout.payload
            })
            .collect();
        for (index, a) in ranges.iter().enumerate() {
            for b in ranges.iter().skip(index + 1) {
                assert!(a.end <= b.start || b.end <= a.start);
            }
        }
        let mut output = Mapping::new(width * 32, 65536)?;
        assert_eq!(output.verify_native(), Ok(()));
        for _ in 0..3 {
            let arrived = AtomicUsize::new(0);
            let mut jobs: Vec<_> = output
                .bytes_mut()
                .chunks_exact_mut(32)
                .zip(&ranges)
                .map(|(slot, range)| {
                    let arrived = &arrived;
                    move || {
                        let marker = core::hint::black_box([0xb7; 256]);
                        let address = marker.as_ptr() as usize;
                        assert!(range.contains(&address) && address + marker.len() <= range.end);
                        arrived.fetch_add(1, Ordering::SeqCst);
                        let started = std::time::Instant::now();
                        while arrived.load(Ordering::SeqCst) < width
                            && started.elapsed().as_secs() < 5
                        {
                            std::thread::yield_now();
                        }
                        assert_eq!(
                            arrived.load(Ordering::SeqCst),
                            width,
                            "workers did not overlap"
                        );
                        slot.copy_from_slice(
                            marker.get(..32).ok_or(Error::Invariant).unwrap_or(&[]),
                        );
                        core::hint::black_box(&marker);
                    }
                })
                .collect();
            super::run(&mut mappings, &mut jobs)?;
            drop(jobs);
            assert!(output.bytes().iter().all(|b| *b == 0xb7));
            output.clear();
            cleared(&mappings);
        }
    }
    Ok(())
}

#[test]
fn each_partial_launch_or_setup_failure_joins_tls_and_allows_reuse() -> Result<(), Error> {
    let mut mappings = stacks(4)?;
    for launch in [false, true] {
        for index in 0..4 {
            let done = Arc::new(AtomicUsize::new(0));
            let mut jobs: Vec<_> = (0..4)
                .map(|_| {
                    let done = Arc::clone(&done);
                    move || {
                        let marker = core::hint::black_box([0x97; 2048]);
                        EXIT.with(|slot| *slot.borrow_mut() = Some(Exit(Arc::clone(&done))));
                        core::hint::black_box(&marker);
                    }
                })
                .collect();
            JOINED.with(|n| n.set(0));
            if launch {
                LAUNCH.with(|n| n.set(Some(index)));
            } else {
                PREPARE.with(|n| n.set(Some(index)));
            }
            let expected = if launch {
                Error::ThreadStart
            } else {
                Error::ThreadAttributes
            };
            assert_eq!(super::run(&mut mappings, &mut jobs), Err(expected));
            let launched = if launch { index } else { 0 };
            assert_eq!(done.load(Ordering::SeqCst), launched);
            assert_eq!(JOINED.with(Cell::get), launched);
            cleared(&mappings);
            super::run(&mut mappings, &mut jobs)?;
            assert_eq!(done.load(Ordering::SeqCst), launched + 4);
            cleared(&mappings);
        }
    }
    Ok(())
}

#[test]
fn worker_and_coordinator_unwind_join_before_clearing_and_reuse() -> Result<(), Error> {
    let mut mappings = stacks(4)?;
    for worker_panic in [false, true] {
        for index in 0..4 {
            let done = Arc::new(AtomicUsize::new(0));
            let mut jobs: Vec<_> = (0..4)
                .map(|job| {
                    let done = Arc::clone(&done);
                    move || {
                        let marker = core::hint::black_box([0xc7; 2048]);
                        EXIT.with(|slot| *slot.borrow_mut() = Some(Exit(Arc::clone(&done))));
                        core::hint::black_box(&marker);
                        assert!(!worker_panic || job != index, "intentional worker unwind");
                    }
                })
                .collect();
            if worker_panic {
                assert_eq!(
                    super::run(&mut mappings, &mut jobs),
                    Err(Error::WorkerPanicked)
                );
                assert_eq!(done.load(Ordering::SeqCst), 4);
            } else {
                UNWIND.with(|n| n.set(Some(index)));
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    super::run(&mut mappings, &mut jobs)
                }));
                assert!(caught.is_err());
                assert_eq!(done.load(Ordering::SeqCst), index + 1);
            }
            cleared(&mappings);
            let count = AtomicUsize::new(0);
            let mut healthy: Vec<_> = (0..4)
                .map(|_| {
                    || {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                })
                .collect();
            super::run(&mut mappings, &mut healthy)?;
            assert_eq!(count.load(Ordering::SeqCst), 4);
            cleared(&mappings);
        }
    }
    Ok(())
}

#[test]
fn invalid_shapes_and_unusable_stack_are_rejected() -> Result<(), Error> {
    let mut none: [fn(); 0] = [];
    assert_eq!(super::run(&mut [], &mut none), Err(Error::InvalidSize));
    let mut mappings = stacks(1)?;
    assert_eq!(
        super::run(&mut mappings, &mut none),
        Err(Error::InvalidSize)
    );
    let mut small = [Mapping::new(32, 65536)?];
    assert_eq!(
        super::run(&mut small, &mut [|| {}]),
        Err(Error::ThreadAttributes)
    );
    let mut excessive: Vec<_> = (0..65)
        .map(|_| Mapping::new(1, 65536))
        .collect::<Result<_, _>>()?;
    assert_eq!(
        super::run(&mut excessive, &mut [|| {}; 65]),
        Err(Error::ResourceLimit)
    );
    Ok(())
}

#[test]
fn join_failure_child() -> Result<(), Error> {
    if std::env::var_os("BRYNJA_DARWIN_GROUP_JOIN_CHILD").is_none() {
        return Ok(());
    }
    let mut mappings = stacks(2)?;
    JOIN_FAILURE.with(|n| n.set(true));
    let _ = super::run(&mut mappings, &mut [|| {}; 2]);
    assert!(
        std::hint::black_box(false),
        "join failure returned borrowed work"
    );
    Ok(())
}

#[test]
fn join_failure_aborts_instead_of_returning_live_borrows() -> Result<(), std::io::Error> {
    use std::os::unix::process::ExitStatusExt;
    let output = std::process::Command::new("bash")
        .args(["-c", "ulimit -c 0 || exit 97; exec \"$@\"", "darwin-group"])
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "macos_resident::resource::darwin::thread::group::tests::join_failure_child",
        ])
        .env("BRYNJA_DARWIN_GROUP_JOIN_CHILD", "1")
        .output()?;
    assert_eq!(
        output.status.signal(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
