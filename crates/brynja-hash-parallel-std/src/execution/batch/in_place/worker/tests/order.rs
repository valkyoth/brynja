use super::*;
use std::sync::mpsc::{Receiver, Sender, channel};

struct Reversed {
    wait: Option<Receiver<()>>,
    signal: Option<Sender<()>>,
    started: usize,
    completed: Arc<AtomicUsize>,
}
impl Spawner for Reversed {
    fn spawn<'s, 'e: 's, F, T>(
        &mut self,
        scope: &'s thread::Scope<'s, 'e>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'s, T>>
    where
        F: FnOnce() -> T + Send + 's,
        T: Send + 's,
    {
        let first = self.started == 0;
        self.started = self.started.checked_add(1).ok_or(io::ErrorKind::Other)?;
        let wait = if first { self.wait.take() } else { None };
        let signal = if first { None } else { self.signal.take() };
        let completed = Arc::clone(&self.completed);
        thread::Builder::new().spawn_scoped(scope, move || {
            if let Some(wait) = wait {
                assert!(wait.recv().is_ok());
            }
            let result = work();
            let previous = completed.fetch_add(1, Ordering::SeqCst);
            assert_eq!(previous, usize::from(first));
            if let Some(signal) = signal {
                assert!(signal.send(()).is_ok());
            }
            result
        })
    }
}
struct SpawnPanic {
    started: usize,
    gates: Vec<Sender<()>>,
    completed: Arc<AtomicUsize>,
}
impl Spawner for SpawnPanic {
    fn spawn<'s, 'e: 's, F, T>(
        &mut self,
        scope: &'s thread::Scope<'s, 'e>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'s, T>>
    where
        F: FnOnce() -> T + Send + 's,
        T: Send + 's,
    {
        if self.started == 2 {
            let _release = core::mem::take(&mut self.gates);
            std::panic::resume_unwind(Box::new(()));
        }
        let (sender, receiver) = channel();
        let completed = Arc::clone(&self.completed);
        let handle = thread::Builder::new().spawn_scoped(scope, move || {
            let _completed = Complete(completed);
            assert!(receiver.recv().is_err());
            work()
        });
        if handle.is_ok() {
            self.started = self.started.checked_add(1).ok_or(io::ErrorKind::Other)?;
            self.gates.push(sender);
        } else {
            self.gates.clear();
        }
        handle
    }
}
macro_rules! tests {
    ($order:ident,$panic:ident,$plan:ident,$root:ident,$run:ident,$width:expr) => {
        #[test]
        fn $order() -> Result<(), Error> {
            let plan = hash::$plan::new(b"abcdefgh", 1).map_err(crypto)?;
            let mut workspace = hash::hardened_in_place::$root::new();
            let executor = executor()?;
            let token = CancellationToken::new();
            let (sender, receiver) = channel();
            let completed = Arc::new(AtomicUsize::new(0));
            let mut spawner = Reversed {
                wait: Some(receiver),
                signal: Some(sender),
                started: 0,
                completed: Arc::clone(&completed),
            };
            let mut expected = [0; 32];
            workspace
                .with(&plan, b"", |mut root| {
                    for index in 0..plan.leaf_count() {
                        // Width-specific reference values are produced by each plan's jobs.
                        let mut leaf = [0; $width];
                        root.merge(plan.job(index)?.execute(&mut leaf)?)?;
                    }
                    root.finalize_public(
                        &mut expected,
                        hash::ParallelHashPublicDeclassification::acknowledge(),
                    )
                })
                .map_err(crypto)?
                .map_err(crypto)?;
            workspace
                .with(&plan, b"", |mut root| -> Result<(), Error> {
                    let report = $run(
                        &plan,
                        &executor,
                        &token,
                        |leaves| root.merge_batch(leaves),
                        &mut spawner,
                    )?;
                    assert_eq!(report.groups, 2);
                    assert_eq!(completed.load(Ordering::SeqCst), 2);
                    let mut output = [0xa5; 32];
                    root.finalize_public(
                        &mut output,
                        hash::ParallelHashPublicDeclassification::acknowledge(),
                    )
                    .map_err(crypto)?;
                    assert_eq!(output, expected);
                    Ok(())
                })
                .map_err(crypto)??;
            Ok(())
        }
        #[test]
        fn $panic() -> Result<(), Error> {
            let plan = hash::$plan::new(b"abcdefghijkl", 1).map_err(crypto)?;
            let executor = executor()?;
            let token = CancellationToken::new();
            let completed = Arc::new(AtomicUsize::new(0));
            let mut spawner = SpawnPanic {
                started: 0,
                gates: Vec::new(),
                completed: Arc::clone(&completed),
            };
            DROPS.with(|d| d.borrow_mut().clear());
            let result = catch_unwind(AssertUnwindSafe(|| {
                $run(&plan, &executor, &token, |_| Ok(()), &mut spawner)
            }));
            assert!(result.is_err());
            assert_eq!(completed.load(Ordering::SeqCst), 2);
            DROPS.with(|d| assert_eq!(&*d.borrow(), &[true]));
            Ok(())
        }
    };
}
tests!(
    scoped_multibuffer_order128,
    scoped_multibuffer_spawn_unwind128,
    ParallelHash128Plan,
    ParallelHash128CollectorWorkspace,
    run128_with,
    32
);
tests!(
    scoped_multibuffer_order256,
    scoped_multibuffer_spawn_unwind256,
    ParallelHash256Plan,
    ParallelHash256CollectorWorkspace,
    run256_with,
    64
);
