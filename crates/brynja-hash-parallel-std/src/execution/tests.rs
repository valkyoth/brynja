use super::*;

/// Interpreted selectors only; native tests always retain every original case.
pub(super) struct MiriCases {
    selected: Option<usize>,
    total: usize,
    visited: usize,
    executed: usize,
}

impl MiriCases {
    pub(super) fn new(total: usize) -> Self {
        let selected = if cfg!(miri) {
            std::env::var("BRYNJA_MIRI_CASE").ok().map(|value| {
                let parsed = value.parse::<usize>();
                assert!(parsed.is_ok());
                parsed.unwrap_or(usize::MAX)
            })
        } else {
            None
        };
        assert!(total > 0 && selected.is_none_or(|case| case < total));
        Self {
            selected,
            total,
            visited: 0,
            executed: 0,
        }
    }

    pub(super) fn run(&mut self) -> Result<bool, Error> {
        let case = self.visited;
        self.visited = self.visited.checked_add(1).ok_or(Error::Limits)?;
        assert!(self.visited <= self.total);
        let run = self.selected.is_none_or(|wanted| wanted == case);
        if run {
            self.executed = self.executed.checked_add(1).ok_or(Error::Limits)?;
        }
        Ok(run)
    }

    pub(super) fn finish(self, _name: &str) {
        assert_eq!(self.visited, self.total);
        assert_eq!(
            self.executed,
            if self.selected.is_some() {
                1
            } else {
                self.total
            }
        );
        #[cfg(miri)]
        if let Some(case) = self.selected {
            println!("\nMIRI_CASE_PASS: {_name}:{case}");
        }
    }
}

#[test]
fn miri_case_accounting_rejects_missing_duplicate_and_unexecuted_work() -> Result<(), Error> {
    // Construct directly: this checks interpreted case accounting without
    // making native test coverage depend on an environment variable.
    let selected = || MiriCases {
        selected: Some(1),
        total: 2,
        visited: 0,
        executed: 0,
    };
    let mut valid = selected();
    assert!(!valid.run()?);
    assert!(valid.run()?);
    // Do not emit a task marker from this accounting-only test.
    assert_eq!((valid.visited, valid.executed), (2, 1));
    assert!(std::panic::catch_unwind(|| selected().finish("missing")).is_err());
    assert!(
        std::panic::catch_unwind(|| {
            let mut duplicate = selected();
            assert!(duplicate.run().is_ok());
            assert!(duplicate.run().is_ok());
            let _ = duplicate.run();
        })
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| {
            MiriCases {
                selected: Some(1),
                total: 2,
                visited: 2,
                executed: 0,
            }
            .finish("unexecuted");
        })
        .is_err()
    );
    Ok(())
}

fn executor() -> Result<Executor, Error> {
    Executor::new(Config {
        workers: 2,
        max_leaves: 4,
        root: Preference::Portable,
        leaves: Preference::Portable,
    })
}
fn rejected_outputs(executor: &Executor, error: Error) -> Result<(), Error> {
    let request = Request {
        identity: Identity::ParallelHashXof128,
        input: Fips202BitString::new(b"input", 8).map_err(|_| Error::Limits)?,
        block_size: 8,
        customization: Fips202BitString::new(&[], 0).map_err(|_| Error::Limits)?,
    };
    let token = CancellationToken::new();
    let mut public = [0xa5; 32];
    let mut secret = [0xa5; 32];
    let mut scratch = [0xa5; 40];
    assert_eq!(
        executor.hash_public(&request, &mut public, &mut scratch, &token),
        Err(error)
    );
    assert_eq!(public, [0xa5; 32]);
    assert_eq!(scratch, [0; 40]);
    assert!(
        matches!(executor.hash_secret(&request, &mut secret, &token), Err(actual) if actual == error)
    );
    assert_eq!(secret, [0; 32]);
    Ok(())
}

#[test]
fn operation_permit_rejects_reentry_without_touching_public_output() -> Result<(), Error> {
    let executor = executor()?;
    let _held = executor.gate()?;
    rejected_outputs(&executor, Error::Resource)
}

#[test]
fn poisoned_permit_is_terminal_and_still_clears_destinations() -> Result<(), Error> {
    let executor = executor()?;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = executor.gate();
        std::panic::resume_unwind(Box::new("injected permit unwind"));
    }));
    assert!(caught.is_err());
    rejected_outputs(&executor, Error::WorkerPanicked)?;
    rejected_outputs(&executor, Error::WorkerPanicked)
}
