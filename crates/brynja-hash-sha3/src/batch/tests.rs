use super::*;
use crate::Fips202Output;
extern crate std;
use std::{vec, vec::Vec};

const ALGORITHMS: [Algorithm; 8] = [
    Algorithm::Sha3_224,
    Algorithm::Sha3_256,
    Algorithm::Sha3_384,
    Algorithm::Sha3_512,
    Algorithm::Shake128,
    Algorithm::Shake256,
    Algorithm::Cshake128,
    Algorithm::Cshake256,
];
fn bits(bytes: &[u8], n: usize) -> Result<Fips202BitString<'_>, Error> {
    Fips202BitString::new(
        bytes,
        if n == 0 {
            0
        } else {
            u8::try_from((n.saturating_sub(1) % 8).saturating_add(1))
                .map_err(|_| Error::Invariant)?
        },
    )
    .map_err(|_| Error::InvalidInput)
}
fn oracle(input: Input<'_>) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; input.output_bytes()];
    let valid = if input.output_bits == 0 {
        0
    } else {
        u8::try_from((input.output_bits.saturating_sub(1) % 8).saturating_add(1))
            .map_err(|_| Error::Invariant)?
    };
    macro_rules! fixed {
        ($function:expr) => {
            out.copy_from_slice(
                $function(input.message)
                    .map_err(|_| Error::Invariant)?
                    .as_bytes(),
            )
        };
    }
    macro_rules! xof {
        ($function:expr) => {
            $function(
                input.message,
                Fips202Output::new(&mut out, valid).map_err(|_| Error::Invariant)?,
            )
            .map_err(|_| Error::Invariant)?
        };
    }
    macro_rules! custom {
        ($function:expr) => {
            $function(
                input.message,
                input.name,
                input.customization,
                Fips202Output::new(&mut out, valid).map_err(|_| Error::Invariant)?,
            )
            .map_err(|_| Error::Invariant)?
        };
    }
    match input.algorithm {
        Algorithm::Sha3_224 => fixed!(crate::sha3_224_bits),
        Algorithm::Sha3_256 => fixed!(crate::sha3_256_bits),
        Algorithm::Sha3_384 => fixed!(crate::sha3_384_bits),
        Algorithm::Sha3_512 => fixed!(crate::sha3_512_bits),
        Algorithm::Shake128 => xof!(crate::shake128_bits),
        Algorithm::Shake256 => xof!(crate::shake256_bits),
        Algorithm::Cshake128 => custom!(crate::cshake128_bits),
        Algorithm::Cshake256 => custom!(crate::cshake256_bits),
    }
    Ok(out)
}

fn campaign(executor: &Executor<'_>, vector: bool) -> Result<(), Error> {
    let mut workspace = Workspace::new();
    for case in 0_usize..128 {
        let mut identities = Vec::new();
        let mut lengths = Vec::new();
        let mut messages = Vec::new();
        for i in 0_usize..4 {
            let algorithm = *ALGORITHMS
                .get(case.saturating_add(i) % 8)
                .ok_or(Error::Invariant)?;
            let rate = algorithm.rate().saturating_mul(8);
            let boundaries = [
                0,
                1,
                7,
                8,
                rate.saturating_sub(5),
                rate.saturating_sub(3),
                rate.saturating_sub(1),
                rate,
                rate.saturating_add(1),
                rate.saturating_mul(2).saturating_add(7),
            ];
            let n = *boundaries
                .get(case.saturating_add(i) % 10)
                .ok_or(Error::Invariant)?;
            let mut message = vec![0xa3; n.div_ceil(8)];
            if !n.is_multiple_of(8)
                && let Some(last) = message.last_mut()
            {
                *last &= super::framing::mask(n % 8);
            }
            identities.push(algorithm);
            lengths.push(n);
            messages.push(message);
        }
        let mut inputs = Vec::new();
        for (i, ((algorithm, message), n)) in identities
            .into_iter()
            .zip(&messages)
            .zip(lengths)
            .enumerate()
        {
            let output_bits = algorithm.fixed_output_bits().unwrap_or(
                *[0, 1, 7, 8, 1089, 2701, 4096]
                    .get(case.saturating_add(i) % 7)
                    .ok_or(Error::Invariant)?,
            );
            let (name, custom) = if algorithm.customized() && case % 3 != 0 {
                (bits(&[0x15], 5)?, bits(&[0x25, 1], 9)?)
            } else {
                (bits(&[], 0)?, bits(&[], 0)?)
            };
            inputs.push(Input::with_customization(
                algorithm,
                bits(message, n)?,
                name,
                custom,
                output_bits,
            )?);
        }
        if case % 2 == 0 {
            inputs.reverse();
        }
        let expected: Vec<_> = inputs
            .iter()
            .map(|i| oracle(*i))
            .collect::<Result<_, _>>()?;
        // Every byte starts guaranteed incorrect, catching stale/no-op output.
        let mut actual: Vec<Vec<u8>> = expected
            .iter()
            .map(|o| o.iter().map(|b| !b).collect())
            .collect();
        let mut output: Vec<_> = actual.iter_mut().map(Vec::as_mut_slice).collect();
        let mut staging = vec![0x71; expected.iter().map(Vec::len).sum()];
        let mut cancel = || false;
        let mut control = Control::new(1024, &mut cancel);
        let before = executor
            .session
            .as_ref()
            .map_or(0, Session::completed_vector_calls);
        let report = executor.digest(
            PublicData::new(inputs.as_slice()),
            &mut output,
            &mut workspace,
            &mut staging,
            &mut control,
        )?;
        assert_eq!(actual, expected, "case {case}");
        let after = executor
            .session
            .as_ref()
            .map_or(0, Session::completed_vector_calls);
        assert_eq!(after.checked_sub(before), Some(report.vector_calls));
        assert_eq!(
            report
                .vector_permutations
                .checked_add(report.scalar_permutations),
            Some(control.used())
        );
        assert_eq!(report.vector_calls != 0, vector);
    }
    Ok(())
}
#[test]
fn mixed_domains_bit_tails_prefixes_and_reordered_outputs() -> Result<(), Error> {
    campaign(&Executor::portable(), false)
}
#[test]
fn native_vector_campaign() -> Result<(), Error> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let owner = brynja_crypto_cpu::keccak_batch::Authority::for_compiled_target(kernel)
            .map_err(Error::Backend)?;
        let executor =
            Executor::with_session(owner.session().map_err(Error::Backend)?, Mode::Require, 1)?;
        campaign(&executor, true)?;
        std::println!("KECCAK_BATCH_API: {kernel:?}; comparisons=512");
    }
    Ok(())
}
#[test]
fn invalid_identity_and_output_are_rejected() -> Result<(), Error> {
    for algorithm in ALGORITHMS {
        if let Some(n) = algorithm.fixed_output_bits() {
            assert!(matches!(
                Input::new(algorithm, bits(&[], 0)?, n + 1),
                Err(Error::InvalidInput)
            ));
        }
        if !algorithm.customized() {
            assert!(matches!(
                Input::with_customization(
                    algorithm,
                    bits(&[], 0)?,
                    bits(&[1], 1)?,
                    bits(&[], 0)?,
                    256
                ),
                Err(Error::InvalidInput)
            ));
        }
    }
    Ok(())
}
fn failures(executor: &Executor<'_>) -> Result<(), Error> {
    let inputs = [Input::new(Algorithm::Shake128, bits(&[0x37; 337], 337 * 8)?, 2049)?; 4];
    let mut workspace = Workspace::new();
    for budget in 0..16 {
        let mut storage = [[0x5a; 257]; 4];
        let mut output: Vec<_> = storage.iter_mut().map(|a| a.as_mut_slice()).collect();
        let mut staging = [0x19; 1028];
        let mut cancel = || false;
        let mut control = Control::new(budget, &mut cancel);
        assert_eq!(
            executor.digest(
                PublicData::new(&inputs),
                &mut output,
                &mut workspace,
                &mut staging,
                &mut control
            ),
            Err(Error::WorkLimit)
        );
        assert_eq!(storage, [[0x5a; 257]; 4]);
        executor.check()?;
    }
    for stop in 0_usize..24 {
        let mut polls = 0_usize;
        let mut cancel = || {
            polls = polls.saturating_add(1);
            polls == stop.saturating_add(1)
        };
        let mut storage = [[0x5a; 257]; 4];
        let mut output: Vec<_> = storage.iter_mut().map(|a| a.as_mut_slice()).collect();
        let mut control = Control::new(1000, &mut cancel);
        let result = executor.digest(
            PublicData::new(&inputs),
            &mut output,
            &mut workspace,
            &mut [0; 1028],
            &mut control,
        );
        if result == Err(Error::Cancelled) {
            assert_eq!(storage, [[0x5a; 257]; 4]);
        } else {
            result?;
        }
        executor.check()?;
    }
    campaign(executor, executor.session.is_some())
}
#[test]
fn request_failures_are_atomic_and_reusable() -> Result<(), Error> {
    failures(&Executor::portable())?;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let owner = brynja_crypto_cpu::keccak_batch::Authority::for_compiled_target(kernel)
            .map_err(Error::Backend)?;
        failures(&Executor::with_session(
            owner.session().map_err(Error::Backend)?,
            Mode::Prefer,
            1,
        )?)?;
    }
    Ok(())
}

#[test]
fn bounded_batch_lifecycle() -> Result<(), Error> {
    let executor = Executor::portable();
    let input = Input::new(Algorithm::Sha3_256, bits(b"abc", 24)?, 256)?;
    let expected = oracle(input)?;
    let mut workspace = Workspace::new();
    for (budget, cancel_now) in [(0, false), (3, false), (4, true), (4, false)] {
        let mut storage = [[0x59; 32]; 4];
        let mut outputs: Vec<_> = storage.iter_mut().map(|a| a.as_mut_slice()).collect();
        let mut cancel = || cancel_now;
        let result = executor.digest(
            PublicData::new(&[input; 4]),
            &mut outputs,
            &mut workspace,
            &mut [0; 128],
            &mut Control::new(budget, &mut cancel),
        );
        if cancel_now {
            assert_eq!(result, Err(Error::Cancelled));
        } else if budget < 4 {
            assert_eq!(result, Err(Error::WorkLimit));
        } else {
            assert_eq!(result?.scalar_permutations, 4);
            for output in storage {
                assert_eq!(output.as_slice(), expected);
            }
        }
        if cancel_now || budget < 4 {
            assert_eq!(storage, [[0x59; 32]; 4]);
        }
        executor.check()?;
    }
    Ok(())
}

#[test]
fn shape_staging_empty_and_scalar_tail_boundaries() -> Result<(), Error> {
    let input = Input::new(Algorithm::Sha3_256, bits(b"abc", 24)?, 256)?;
    let executor = Executor::portable();
    let mut workspace = Workspace::new();
    let mut cancel = || false;
    let mut control = Control::new(1000, &mut cancel);
    for count in 0..=4 {
        let inputs = vec![input; count];
        let mut storage = vec![[0xa5; 32]; count];
        let mut outputs: Vec<_> = storage.iter_mut().map(|a| a.as_mut_slice()).collect();
        let report = executor.digest(
            PublicData::new(&inputs),
            &mut outputs,
            &mut workspace,
            &mut [0; 128],
            &mut control,
        )?;
        assert_eq!(
            report.scalar_permutations,
            u64::try_from(count).map_err(|_| Error::Invariant)?
        );
        for result in storage {
            assert_eq!(result.as_slice(), oracle(input)?);
        }
    }
    let mut output = [0xa5; 32];
    let mut scratch = [0x51; 31];
    assert_eq!(
        executor.digest(
            PublicData::new(&[input]),
            &mut [&mut output],
            &mut workspace,
            &mut scratch,
            &mut control
        ),
        Err(Error::InsufficientScratch)
    );
    assert_eq!(output, [0xa5; 32]);
    assert_eq!(scratch, [0x51; 31]);
    assert_eq!(
        executor.digest(
            PublicData::new(&[input]),
            &mut [&mut output],
            &mut workspace,
            &mut [0; 128],
            &mut Control::new(0, &mut || false)
        ),
        Err(Error::WorkLimit)
    );
    assert_eq!(output, [0xa5; 32]);
    assert_eq!(
        executor.digest(
            PublicData::new(&[input]),
            &mut [],
            &mut workspace,
            &mut [0; 128],
            &mut control
        ),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        executor.digest(
            PublicData::new(&[input]),
            &mut [&mut [0; 31]],
            &mut workspace,
            &mut [0; 128],
            &mut control
        ),
        Err(Error::InvalidDestination)
    );
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let owner = brynja_crypto_cpu::keccak_batch::Authority::for_compiled_target(kernel)
            .map_err(Error::Backend)?;
        let required =
            Executor::with_session(owner.session().map_err(Error::Backend)?, Mode::Require, 1)?;
        assert_eq!(
            required.digest(
                PublicData::new(&[input]),
                &mut [&mut output],
                &mut workspace,
                &mut [0; 128],
                &mut control
            ),
            Err(Error::IneligibleWorkload)
        );
        assert!(owner.is_healthy());
        let preferred =
            Executor::with_session(owner.session().map_err(Error::Backend)?, Mode::Prefer, 1)?;
        let report = preferred.digest(
            PublicData::new(&[input]),
            &mut [&mut output],
            &mut workspace,
            &mut [0; 128],
            &mut control,
        )?;
        assert_eq!(report.vector_calls, 0);
        assert_eq!(report.scalar_permutations, 1);
        assert_eq!(output.as_slice(), oracle(input)?);
        let threshold =
            Executor::with_session(owner.session().map_err(Error::Backend)?, Mode::Require, 2)?;
        assert_eq!(
            threshold.digest(
                PublicData::new(&[input; 4]),
                &mut [&mut [0; 32], &mut [0; 32], &mut [0; 32], &mut [0; 32]],
                &mut workspace,
                &mut [0; 128],
                &mut control
            ),
            Err(Error::IneligibleWorkload)
        );
    }
    Ok(())
}

#[test]
fn callback_unwind_and_revocation_never_commit_output() -> Result<(), Error> {
    let input = Input::new(Algorithm::Shake128, bits(b"abc", 24)?, 256)?;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        for unwind in [false, true] {
            let owner = brynja_crypto_cpu::keccak_batch::Authority::for_compiled_target(kernel)
                .map_err(Error::Backend)?;
            let executor =
                Executor::with_session(owner.session().map_err(Error::Backend)?, Mode::Require, 1)?;
            let mut storage = [[0x59; 32]; 4];
            let mut outputs: Vec<_> = storage.iter_mut().map(|a| a.as_mut_slice()).collect();
            let mut polls = 0_u32;
            let mut cancel = || {
                polls = polls.saturating_add(1);
                if polls == 3 {
                    if unwind {
                        std::panic::resume_unwind(std::boxed::Box::new("cancel callback"));
                    }
                    owner.quarantine();
                }
                false
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                executor.digest(
                    PublicData::new(&[input; 4]),
                    &mut outputs,
                    &mut Workspace::new(),
                    &mut [0; 128],
                    &mut Control::new(100, &mut cancel),
                )
            }));
            assert!(matches!(result, Err(_) | Ok(Err(Error::Backend(_)))));
            assert_eq!(storage, [[0x59; 32]; 4]);
            assert!(!owner.is_healthy());
        }
    }
    Ok(())
}
