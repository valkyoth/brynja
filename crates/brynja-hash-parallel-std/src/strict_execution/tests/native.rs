use super::*;
use brynja_hash_parallel::{self as api, Fips202BitString, Fips202Output};
pub(crate) fn guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}
pub(crate) fn identities(n: usize) -> [Algorithm; 4] {
    [
        Algorithm::ParallelHash128(n),
        Algorithm::ParallelHash256(n),
        Algorithm::ParallelHashXof128(n),
        Algorithm::ParallelHashXof256(n),
    ]
}
pub(crate) fn reference(
    algorithm: Algorithm,
    input: Bits<'_>,
    block: usize,
    custom: Bits<'_>,
) -> Result<Vec<u8>, Error> {
    let input =
        Fips202BitString::new(input.bytes, input.valid_bits).map_err(|_| Error::InvalidBits)?;
    let custom =
        Fips202BitString::new(custom.bytes, custom.valid_bits).map_err(|_| Error::InvalidBits)?;
    let mut output = vec![0; algorithm.output_bytes()];
    let valid = if output.is_empty() {
        0
    } else {
        let last = algorithm
            .output_bits()
            .checked_sub(1)
            .ok_or(Error::Invariant)?;
        u8::try_from((last % 8).checked_add(1).ok_or(Error::Invariant)?)
            .map_err(|_| Error::Invariant)?
    };
    let destination = Fips202Output::new(&mut output, valid).map_err(|_| Error::InvalidBits)?;
    let mut buffer = vec![0; block];
    macro_rules! fixed {
        ($name:ident) => {{
            api::$name::new_bits(&mut buffer, custom)
                .map_err(|_| Error::Invariant)?
                .finalize_bits(input, destination)
                .map_err(|_| Error::Invariant)?;
        }};
    }
    macro_rules! xof {
        ($name:ident) => {{
            api::$name::new_bits(&mut buffer, custom)
                .map_err(|_| Error::Invariant)?
                .finalize_bits_xof(input)
                .map_err(|_| Error::Invariant)?
                .squeeze_final_bits(destination)
                .map_err(|_| Error::Invariant)?;
        }};
    }
    match algorithm {
        Algorithm::ParallelHash128(_) => fixed!(ParallelHash128),
        Algorithm::ParallelHash256(_) => fixed!(ParallelHash256),
        Algorithm::ParallelHashXof128(_) => xof!(ParallelHashXof128),
        Algorithm::ParallelHashXof256(_) => xof!(ParallelHashXof256),
    }
    Ok(output)
}
fn cleared(session: &Session) {
    for bytes in [&session.cvs, &session.staging, &session.output] {
        assert!(bytes.as_bytes().iter().all(|b| *b == 0));
    }
}
#[test]
fn all_identities_bits_and_multiple_waves_match_portable() -> Result<(), Error> {
    let _guard = guard();
    for algorithm in identities(257) {
        let mut session = Session::new(algorithm, limits())?;
        for length in [0, 1, 31, 32, 33, 135, 136, 137, 167, 168, 169, 1025] {
            for valid in 1..=8 {
                let mut input: Vec<u8> = (0..=250).cycle().take(length).collect();
                if let Some(last) = input.last_mut() {
                    *last &= u8::MAX >> (8 - valid);
                }
                let valid = if input.is_empty() { 0 } else { valid };
                let expected = reference(
                    algorithm,
                    Bits {
                        bytes: &input,
                        valid_bits: valid,
                    },
                    32,
                    Bits {
                        bytes: &[3],
                        valid_bits: 2,
                    },
                )?;
                let output = session.compute(
                    Bits {
                        bytes: &input,
                        valid_bits: valid,
                    },
                    32,
                    Bits {
                        bytes: &[3],
                        valid_bits: 2,
                    },
                    &CancellationToken::new(),
                )?;
                assert_eq!(output.algorithm(), algorithm);
                assert_eq!(output.expose(), expected);
                drop(output);
                cleared(&session);
            }
        }
    }
    Ok(())
}
#[test]
fn zero_partial_and_large_xof_output() -> Result<(), Error> {
    let _guard = guard();
    for bits in [0, 1, 7, 8, 9, 32769] {
        for algorithm in identities(bits) {
            let mut session = Session::new(algorithm, limits())?;
            assert_eq!(
                session.hash(b"abc", 1, b"custom")?.expose(),
                reference(algorithm, Bits::bytes(b"abc"), 1, Bits::bytes(b"custom"))?
            );
            cleared(&session);
        }
    }
    Ok(())
}
#[test]
fn failures_after_leaf_root_and_output_clear_and_allow_reuse() -> Result<(), Error> {
    let _guard = guard();
    for algorithm in identities(256) {
        let mut session = Session::new(algorithm, limits())?;
        for point in [
            Point::Leaf(0),
            Point::Leaf(1),
            Point::Leaf(2),
            Point::Leaf(3),
            Point::Leaf(6),
            Point::Root,
            Point::Output,
        ] {
            for fault in [Fault::Cancel(point), Fault::Panic(point)] {
                session.fault = fault;
                let result = session.hash(b"1234567", 1, b"custom");
                match fault {
                    Fault::Cancel(_) => assert!(matches!(result, Err(Error::Cancelled))),
                    Fault::Panic(_) => assert!(matches!(
                        result,
                        Err(Error::Resource(
                            brynja_crypto_cpu_std::protected_memory::Error::WorkerPanicked
                        ))
                    )),
                    _ => return Err(Error::Invariant),
                }
                drop(result);
                cleared(&session);
                session.fault = Fault::None;
                assert_eq!(
                    session.hash(b"1234567", 1, b"custom")?.expose(),
                    reference(
                        algorithm,
                        Bits::bytes(b"1234567"),
                        1,
                        Bits::bytes(b"custom")
                    )?
                );
                cleared(&session);
            }
        }
    }
    Ok(())
}
#[test]
fn malformed_budget_cancelled_and_forgotten_outputs_clear() -> Result<(), Error> {
    let _guard = guard();
    let mut session = Session::new(Algorithm::ParallelHash128(256), limits())?;
    core::mem::forget(session.hash(b"secret", 1, b"")?);
    assert!(matches!(session.hash(b"", 0, b""), Err(Error::WorkLimit)));
    cleared(&session);
    for input in [
        Bits {
            bytes: &[255],
            valid_bits: 1,
        },
        Bits {
            bytes: &[],
            valid_bits: 8,
        },
        Bits {
            bytes: &[1],
            valid_bits: 0,
        },
    ] {
        assert!(matches!(
            session.compute(input, 1, Bits::bytes(b""), &CancellationToken::new()),
            Err(Error::InvalidBits)
        ));
        cleared(&session);
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        session.compute(Bits::bytes(b"abc"), 1, Bits::bytes(b""), &cancel),
        Err(Error::Cancelled)
    ));
    cleared(&session);
    assert!(matches!(
        session.hash(&[0; 129], 1, b""),
        Err(Error::WorkLimit)
    ));
    cleared(&session);
    let mut public = [0xa5; 31];
    assert_eq!(
        session
            .hash(b"secret", 1, b"")?
            .declassify(&mut public, PublicDeclassification::acknowledge()),
        Err(Error::OutputLength)
    );
    assert_eq!(public, [0xa5; 31]);
    cleared(&session);
    Ok(())
}

#[test]
fn reordered_leaf_loans_fail_closed_for_every_identity() -> Result<(), Error> {
    let _guard = guard();
    for algorithm in identities(256) {
        let mut session = Session::new(algorithm, limits())?;
        session.fault = Fault::Reorder;
        assert!(matches!(
            session.hash(b"abcdefg", 1, b""),
            Err(Error::Invariant)
        ));
        cleared(&session);
        session.fault = Fault::None;
        assert_eq!(
            session.hash(b"abcdefg", 1, b"")?.expose(),
            reference(algorithm, Bits::bytes(b"abcdefg"), 1, Bits::bytes(b""))?
        );
        cleared(&session);
    }
    Ok(())
}
