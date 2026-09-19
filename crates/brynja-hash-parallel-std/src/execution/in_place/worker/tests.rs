use super::super::super::Preference;
use super::*;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Inject<'a> {
    fail: Option<usize>,
    panic: bool,
    cancel: Option<usize>,
    started: usize,
    finished: Arc<AtomicUsize>,
    token: &'a CancellationToken,
}
impl Spawner for Inject<'_> {
    fn spawn<'s, 'e: 's, F, T>(
        &mut self,
        scope: &'s thread::Scope<'s, 'e>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'s, T>>
    where
        F: FnOnce() -> T + Send + 's,
        T: Send + 's,
    {
        if self.fail == Some(self.started) {
            return Err(io::Error::other("injected launch failure"));
        }
        if self.cancel == Some(self.started) {
            self.token.cancel();
        }
        self.started = self.started.checked_add(1).ok_or(io::ErrorKind::Other)?;
        let finished = Arc::clone(&self.finished);
        let panic = self.panic;
        thread::Builder::new().spawn_scoped(scope, move || {
            let result = work();
            finished.fetch_add(1, Ordering::SeqCst);
            if panic {
                std::panic::resume_unwind(Box::new(()));
            }
            result
        })
    }
}

macro_rules! tests {
    ($faults:ident, $revocation:ident, $batch:ident, $leaf:ident, $plan:ident, $root:ident, $width:expr) => {
        #[test]
        fn $faults() -> Result<(), Error> {
            let plan = hash::$plan::new(b"AB", 1).map_err(crypto)?;
            for (fail, panic, cancel, expected) in [
                (Some(1), false, None, Error::Resource),
                (None, true, None, Error::WorkerPanicked),
                (None, false, Some(1), Error::Cancelled),
                (
                    None,
                    false,
                    None,
                    crypto(hash::ParallelHashError::LeafIdentity),
                ),
            ] {
                let token = CancellationToken::new();
                let finished = Arc::new(AtomicUsize::new(0));
                let mut spawner = Inject {
                    fail,
                    panic,
                    cancel,
                    started: 0,
                    finished: Arc::clone(&finished),
                    token: &token,
                };
                let mut slots = [[0; $width]; 2];
                let mut merged = 0usize;
                let result = $batch(
                    &plan,
                    0,
                    &mut slots,
                    Preference::Portable,
                    &token,
                    &mut |_| {
                        merged = merged.saturating_add(1);
                        Err(hash::ParallelHashError::LeafIdentity)
                    },
                    &mut spawner,
                );
                assert_eq!(result, Err(expected));
                assert_eq!(finished.load(Ordering::SeqCst), spawner.started);
                assert_eq!(
                    merged,
                    usize::from(fail.is_none() && !panic && cancel.is_none())
                );
                assert_eq!(slots, [[0; $width]; 2]);
            }
            Ok(())
        }
        #[test]
        fn $revocation() -> Result<(), Error> {
            let owner = match Selection::new(Preference::RequireStatic) {
                Ok(owner) => owner,
                Err(
                    Error::Static(
                        brynja_crypto_cpu::static_execution::Error::MissingTargetFeatures,
                    )
                    | Error::Unavailable,
                ) if std::env::var_os("BRYNJA_REQUIRE_SCOPED_PARALLEL").is_none() => return Ok(()),
                Err(error) => return Err(error),
            };
            let plan = hash::$plan::new(b"x", 1).map_err(crypto)?;
            let mut output = [0xa5; $width];
            let (result, accelerated) = $leaf(plan.job(0).map_err(crypto)?, &mut output, &owner)?;
            assert!(accelerated);
            drop(result);
            assert_eq!(output, [0; $width]);
            let Selection::Static(authority) = &owner else {
                return Err(Error::Unavailable);
            };
            authority.quarantine();
            output.fill(0xa5);
            assert!($leaf(plan.job(0).map_err(crypto)?, &mut output, &owner).is_err());
            assert_eq!(output, [0; $width]);
            // A root revoked after workers complete must reject merge without
            // fallback. Every launched worker still joins and its output clears.
            let root_owner = Selection::new(Preference::RequireStatic)?;
            let Mode::Require(Some(session)) = root_owner.mode()? else {
                return Err(Error::Unavailable);
            };
            let mut workspace = accelerated::$root::new(session).map_err(crypto)?;
            let token = CancellationToken::new();
            let finished = Arc::new(AtomicUsize::new(0));
            let mut spawner = Inject {
                fail: None,
                panic: false,
                cancel: None,
                started: 0,
                finished: Arc::clone(&finished),
                token: &token,
            };
            let mut slots = [[0; $width]; 1];
            workspace
                .with(&plan, b"", |mut root| {
                    let result = $batch(
                        &plan,
                        0,
                        &mut slots,
                        Preference::RequireStatic,
                        &token,
                        &mut |leaf| {
                            if let Selection::Static(authority) = &root_owner {
                                authority.quarantine();
                            }
                            root.merge(leaf)
                        },
                        &mut spawner,
                    );
                    assert!(result.is_err());
                    let mut destination = [0xa5; 9];
                    assert!(root.finalize_secret(&mut destination).is_err());
                    assert_eq!(destination, [0; 9]);
                })
                .map_err(crypto)?;
            assert_eq!(finished.load(Ordering::SeqCst), 1);
            assert_eq!(slots, [[0; $width]; 1]);
            Ok(())
        }
    };
}
tests!(
    scoped_execution_workers_join128,
    scoped_execution_leaf_revocation128,
    batch128,
    leaf128,
    ParallelHash128Plan,
    ParallelHash128CollectorWorkspace,
    32
);
tests!(
    scoped_execution_workers_join256,
    scoped_execution_leaf_revocation256,
    batch256,
    leaf256,
    ParallelHash256Plan,
    ParallelHash256CollectorWorkspace,
    64
);
