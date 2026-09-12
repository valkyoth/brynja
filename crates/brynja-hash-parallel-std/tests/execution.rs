//! Bounded threaded accelerated ParallelHash consumer and error acceptance.
#![cfg(feature = "runtime-execution")]

use brynja_hash_parallel::{
    Fips202BitString,
    execution::{Collector, Identity, Mode, Plan},
};
use brynja_hash_parallel_std::{
    CancellationToken,
    execution::{Config, Error, Executor, Preference, Request},
};

const IDENTITIES: [Identity; 4] = [
    Identity::ParallelHash128,
    Identity::ParallelHash256,
    Identity::ParallelHashXof128,
    Identity::ParallelHashXof256,
];
fn bits(input: &[u8], valid: u8) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(input, valid).map_err(|_| Error::Limits)
}
fn xof(identity: Identity) -> bool {
    matches!(
        identity,
        Identity::ParallelHashXof128 | Identity::ParallelHashXof256
    )
}

#[test]
fn all_thread_widths_identities_and_mixed_routes_match_serial() -> Result<(), Error> {
    for identity in IDENTITIES {
        for count in [0, 1, 65] {
            let input = [0x15; 65];
            let message = bits(
                input.get(..count).ok_or(Error::Limits)?,
                if count == 0 { 0 } else { 5 },
            )?;
            let request = Request {
                identity,
                input: message,
                block_size: 8,
                customization: bits(&[3], 2)?,
            };
            let plan = Plan::new_bits(identity, message, 8, 128)?;
            let mut root = Collector::new_bits(&plan, Mode::Portable, request.customization)?;
            root.execute_serial(|_| Ok(Mode::Portable))?;
            let mut expected = [0; 173];
            let mut stage = [0; 173];
            let public = brynja_hash_parallel::ParallelHashPublicDeclassification::acknowledge();
            if xof(identity) {
                root.finalize_xof()?
                    .squeeze_final_public(&mut expected, 5, &mut stage, public)?;
            } else {
                root.finalize_public_bits(&mut expected, 5, &mut stage, public)?;
            }
            for workers in [1, 2, 4] {
                for (root, leaves) in [
                    (Preference::Portable, Preference::Portable),
                    (Preference::Prefer, Preference::Prefer),
                    (Preference::Portable, Preference::Prefer),
                    (Preference::Prefer, Preference::Portable),
                ] {
                    let executor = Executor::new(Config {
                        workers,
                        max_leaves: 128,
                        root,
                        leaves,
                    })?;
                    let token = CancellationToken::new();
                    let mut output = [0xa5; 173];
                    let mut scratch = [0xa5; 190];
                    let report = executor.hash_public_bits(
                        &request,
                        &mut output,
                        5,
                        &mut scratch,
                        &token,
                    )?;
                    assert_eq!(output, expected);
                    assert_eq!(scratch, [0; 190]);
                    assert_eq!(report.leaves, plan.leaf_count());
                    assert!(report.thread_width <= workers);
                    if leaves == Preference::Portable {
                        assert_eq!(report.accelerated_leaves, 0);
                    }
                    if root == Preference::Portable {
                        assert!(report.root.is_none());
                    }
                    let (secret, secret_report) =
                        executor.hash_secret_bits(&request, &mut output, 5, &token)?;
                    assert_eq!(secret.expose(), &expected);
                    assert_eq!(secret_report.leaves, plan.leaf_count());
                    drop(secret);
                    assert_eq!(output, [0; 173]);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn early_failures_preserve_public_and_clear_secret_and_scratch() -> Result<(), Error> {
    let input = bits(b"eightbit", 8)?;
    for (block, budget, valid, cancel) in [
        (0, 4, 8, false),
        (1, 1, 8, false),
        (8, 1, 9, false),
        (8, 1, 8, true),
    ] {
        let request = Request {
            identity: Identity::ParallelHash128,
            input,
            block_size: block,
            customization: bits(&[], 0)?,
        };
        let executor = Executor::new(Config {
            workers: 2,
            max_leaves: budget,
            root: Preference::Portable,
            leaves: Preference::Portable,
        })?;
        let token = CancellationToken::new();
        if cancel {
            token.cancel();
        }
        let mut output = [0xa5; 32];
        let mut scratch = [0xa5; 64];
        assert!(
            executor
                .hash_public_bits(&request, &mut output, valid, &mut scratch, &token)
                .is_err()
        );
        assert_eq!(output, [0xa5; 32]);
        assert_eq!(scratch, [0; 64]);
        assert!(
            executor
                .hash_secret_bits(&request, &mut output, valid, &token)
                .is_err()
        );
        assert_eq!(output, [0; 32]);
    }
    for workers in [0, 65, usize::MAX] {
        assert!(
            Executor::new(Config {
                workers,
                max_leaves: 1,
                root: Preference::Portable,
                leaves: Preference::Portable
            })
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn required_native_routes_are_real_or_fail_without_output() -> Result<(), Error> {
    let request = Request {
        identity: Identity::ParallelHash256,
        input: bits(b"native", 8)?,
        block_size: 2,
        customization: bits(&[], 0)?,
    };
    let executor = Executor::new(Config {
        workers: 2,
        max_leaves: 16,
        root: Preference::Require,
        leaves: Preference::Require,
    })?;
    let token = CancellationToken::new();
    let mut output = [0xa5; 64];
    let mut scratch = [0xa5; 64];
    match executor.hash_public(&request, &mut output, &mut scratch, &token) {
        Ok(report) => {
            assert!(report.root.is_some());
            assert_eq!(report.accelerated_leaves, 3);
            eprintln!(
                "PARALLELHASH_NATIVE_THREADS: root={:?}; accelerated_leaves={}; width={}",
                report.root, report.accelerated_leaves, report.thread_width
            );
        }
        Err(
            Error::Unavailable
            | Error::Hosted(brynja_crypto_cpu_std::execution::Error::Unavailable(_)),
        ) => {
            assert_eq!(output, [0xa5; 64]);
            eprintln!("PARALLELHASH_NATIVE_THREADS: unsupported; no native evidence");
        }
        Err(error) => return Err(error),
    }
    assert_eq!(scratch, [0; 64]);
    Ok(())
}

#[test]
fn static_workers_require_compiled_features_and_never_silently_fall_back() -> Result<(), Error> {
    for identity in [
        Identity::ParallelHash128,
        Identity::ParallelHash256,
        Identity::ParallelHashXof128,
        Identity::ParallelHashXof256,
    ] {
        let request = Request {
            identity,
            input: bits(b"static worker message", 8)?,
            block_size: 8,
            customization: bits(&[], 0)?,
        };
        let executor = Executor::new(Config {
            workers: 2,
            max_leaves: 16,
            root: Preference::RequireStatic,
            leaves: Preference::RequireStatic,
        })?;
        let token = CancellationToken::new();
        let mut output = [0xa5; 32];
        let mut scratch = [0xa5; 32];
        match executor.hash_public(&request, &mut output, &mut scratch, &token) {
            Ok(report) => {
                assert!(report.root.is_some());
                assert_eq!(report.leaves, 3);
                assert_eq!(report.accelerated_leaves, 3);
                let portable = Executor::new(Config {
                    workers: 1,
                    max_leaves: 16,
                    root: Preference::Portable,
                    leaves: Preference::Portable,
                })?;
                let mut expected = [0x5a; 32];
                portable.hash_public(&request, &mut expected, &mut scratch, &token)?;
                assert_eq!(output, expected);
            }
            Err(
                Error::Static(brynja_crypto_cpu::static_execution::Error::MissingTargetFeatures)
                | Error::Unavailable,
            ) => {
                assert_eq!(output, [0xa5; 32]);
                let mut secret = [0xa5; 32];
                assert!(executor.hash_secret(&request, &mut secret, &token).is_err());
                assert_eq!(secret, [0; 32]);
            }
            Err(error) => return Err(error),
        }
        assert_eq!(scratch, [0; 32]);
    }
    Ok(())
}
