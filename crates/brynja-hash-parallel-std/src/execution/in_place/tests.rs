use super::super::Preference;
use super::*;

#[test]
fn scoped_execution_gate_rejects_overlap_and_poison() -> Result<(), Error> {
    let executor = Executor::new(Config {
        workers: 2,
        max_leaves: 8,
        root: Preference::Portable,
        leaves: Preference::Portable,
    })?;
    let empty = hash::Fips202BitString::new(&[], 0).map_err(|_| Error::Limits)?;
    let request = Request {
        identity: Identity::ParallelHash128,
        input: empty,
        block_size: 1,
        customization: empty,
    };
    let cancel = CancellationToken::new();
    let mut output = [0xa5; 8];
    let mut scratch = [0xa5; 16];
    let gate = executor.inner.gate()?;
    assert_eq!(
        executor
            .hash_public(&request, &mut output, &mut scratch, &cancel)
            .err(),
        Some(Error::Resource)
    );
    assert_eq!(output, [0xa5; 8]);
    assert_eq!(scratch, [0; 16]);
    assert_eq!(
        executor.hash_secret(&request, &mut output, &cancel).err(),
        Some(Error::Resource)
    );
    assert_eq!(output, [0; 8]);
    drop(gate);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let gate = executor.inner.gate();
        assert!(gate.is_ok());
        std::panic::resume_unwind(Box::new(()));
    }));
    assert!(unwind.is_err());
    assert_eq!(
        executor.hash_secret(&request, &mut output, &cancel).err(),
        Some(Error::WorkerPanicked)
    );
    assert_eq!(output, [0; 8]);
    Ok(())
}

#[test]
fn scoped_execution_fixed_xof_domains_and_zero_output() -> Result<(), Error> {
    let executor = Executor::new(Config {
        workers: 2,
        max_leaves: 8,
        root: Preference::Portable,
        leaves: Preference::Portable,
    })?;
    let empty = hash::Fips202BitString::new(&[], 0).map_err(|_| Error::Limits)?;
    let input = hash::Fips202BitString::new(b"input", 8).map_err(|_| Error::Limits)?;
    let cancel = CancellationToken::new();
    for (fixed, xof) in [
        (Identity::ParallelHash128, Identity::ParallelHashXof128),
        (Identity::ParallelHash256, Identity::ParallelHashXof256),
    ] {
        let mut request = Request {
            identity: fixed,
            input,
            block_size: 2,
            customization: empty,
        };
        let mut a = [0; 32];
        let mut b = [0; 32];
        let mut scratch = [0; 32];
        executor.hash_public(&request, &mut a, &mut scratch, &cancel)?;
        request.identity = xof;
        executor.hash_public(&request, &mut b, &mut scratch, &cancel)?;
        assert_ne!(a, b);
        for identity in [fixed, xof] {
            request.identity = identity;
            let report = executor.hash_public_bits(&request, &mut [], 0, &mut [], &cancel)?;
            assert_eq!(report.leaves, 3);
            assert_eq!(report.accelerated_leaves, 0);
            assert!(
                executor
                    .hash_public_bits(&request, &mut [], 8, &mut [], &cancel)
                    .is_err()
            );
            assert!(
                executor
                    .hash_public_bits(&request, &mut a, 8, &mut [], &cancel)
                    .is_err()
            );
        }
    }
    Ok(())
}
