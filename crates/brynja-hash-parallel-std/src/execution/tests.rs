use super::*;

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
