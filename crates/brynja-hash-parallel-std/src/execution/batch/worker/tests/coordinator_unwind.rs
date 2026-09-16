use super::*;
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Sender, channel};

struct Observation {
    finished: Arc<AtomicUsize>,
    dropped: Option<(usize, bool)>,
}
thread_local! {
    static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

pub(super) fn observe(storage: &Storage) {
    // Record rather than assert in Drop: a failing observation must not cause
    // a second panic and abort the test process while already unwinding.
    OBSERVATION.with(|cell| {
        if let Some(observation) = cell.borrow_mut().as_mut() {
            observation.dropped = Some((
                observation.finished.load(Ordering::SeqCst),
                storage.0.iter().flatten().flatten().all(|v| *v == 0),
            ));
        }
    });
}

struct CoordinatorPanic {
    panic_at: usize,
    started: usize,
    finished: Arc<AtomicUsize>,
    gates: Vec<Sender<()>>,
}
impl Spawner for CoordinatorPanic {
    fn spawn<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        if self.started == self.panic_at {
            // Workers cannot start their real work until this vector of
            // senders drops during coordinator unwinding. No sleep or timing
            // threshold is used to impose the ordering.
            let _release_on_unwind = core::mem::take(&mut self.gates);
            assert_ne!(
                self.started, self.panic_at,
                "injected coordinator spawn unwind"
            );
        }
        let next = self
            .started
            .checked_add(1)
            .ok_or_else(|| io::Error::other("test counter overflow"))?;
        let (sender, receiver) = channel();
        let finished = Arc::clone(&self.finished);
        let result = thread::Builder::new().spawn_scoped(scope, move || {
            let _completion = Completion(finished);
            assert!(receiver.recv().is_err());
            work()
        });
        if result.is_ok() {
            self.started = next;
            self.gates.push(sender);
        } else {
            // A genuine OS spawn error must release already started workers
            // too, so the fixture itself cannot deadlock scope teardown.
            self.gates.clear();
        }
        result
    }
}

fn campaign(identity: Identity) -> Result<(), Error> {
    for panic_at in 0..3 {
        let plan = Plan::new(identity, &[0xa5; 48], 4, 16)?;
        let mut root = Collector::new(&plan, Mode::Portable, &[])?;
        let token = CancellationToken::new();
        let executor = executor()?;
        let finished = Arc::new(AtomicUsize::new(0));
        let mut spawner = CoordinatorPanic {
            panic_at,
            started: 0,
            finished: Arc::clone(&finished),
            gates: Vec::new(),
        };
        OBSERVATION.with(|cell| {
            *cell.borrow_mut() = Some(Observation {
                finished: Arc::clone(&finished),
                dropped: None,
            });
        });
        let caught = catch_unwind(AssertUnwindSafe(|| {
            run_with(&plan, &mut root, &executor, &token, &mut spawner)
        }));
        let observation = OBSERVATION.with(|cell| cell.borrow_mut().take());
        let Err(payload) = caught else {
            return Err(Error::Limits);
        };
        assert!(
            payload
                .downcast_ref::<String>()
                .is_some_and(|message| message.contains("injected coordinator spawn unwind"))
        );
        assert_eq!(spawner.started, panic_at);
        assert_eq!(finished.load(Ordering::SeqCst), panic_at);
        assert_eq!(
            observation.and_then(|value| value.dropped),
            Some((panic_at, true))
        );
        assert_eq!(root.merged_leaves(), 0);
        assert!(root.execute_serial(|_| Ok(Mode::Portable)).is_err());
        let mut output = [0xa5; 32];
        assert!(root.finalize_secret(&mut output).is_err());
        assert_eq!(output, [0; 32]);
    }
    Ok(())
}

#[test]
fn coordinator_unwind_fixed128() -> Result<(), Error> {
    campaign(Identity::ParallelHash128)
}
#[test]
fn coordinator_unwind_fixed256() -> Result<(), Error> {
    campaign(Identity::ParallelHash256)
}
#[test]
fn coordinator_unwind_xof128() -> Result<(), Error> {
    campaign(Identity::ParallelHashXof128)
}
#[test]
fn coordinator_unwind_xof256() -> Result<(), Error> {
    campaign(Identity::ParallelHashXof256)
}
