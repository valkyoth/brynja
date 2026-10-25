//! Explicit native caller failure coverage shared by the three output profiles.
use super::{BitString, Error, Input, Md5BatchControl, Md5Executor, executor, select};

#[derive(Clone, Copy)]
enum Route {
    Public,
    Secret,
    Verify,
}

fn tick(value: &mut usize) {
    *value = match value.checked_add(1) {
        Some(next) => next,
        None => std::process::abort(), // Test-counter overflow must fail the child.
    };
}

fn run(
    route: Route,
    executor: &Md5Executor,
    inputs: &[Option<Input<'_>>; 8],
    output: &mut [[u8; 16]; 8],
    expected: &[[u8; 16]; 8],
    control: &mut Md5BatchControl<'_>,
) -> Result<(), Error> {
    let token = select(executor, 16)?;
    match route {
        Route::Public => token.authenticate(inputs, output, control).map(|_| ()),
        Route::Secret => token
            .authenticate_secret(inputs, output, control)
            .map(|(tags, _)| drop(tags)),
        Route::Verify => {
            let candidates = expected.each_ref().map(|row| Some(row.as_slice()));
            match token.verify(inputs, &candidates, control) {
                Ok(_) => Ok(()),
                Err(brynja_legacy_hmac::VerificationError::Operation(error)) => Err(error),
                Err(brynja_legacy_hmac::VerificationError::Mismatch(_)) => {
                    // Never mistake a bad fixture tag for the injected unwind.
                    eprintln!("matching fixture tags must authenticate");
                    std::process::abort()
                }
            }
        }
    }
}

pub(super) fn check() -> Result<(), Error> {
    // Public shape selects scalar or SIMD normalization before processing.
    for all_long in [false, true] {
        let key = [0x42; 80];
        let message = BitString::new(&[0x39; 129], 8).map_err(|_| Error::MessageTooLong)?;
        let inputs = core::array::from_fn(|lane| {
            Some(Input::new(
                if lane == 0 || all_long {
                    &key
                } else {
                    b"short"
                },
                message,
            ))
        });
        let reference = executor()?;
        let mut expected = [[0; 16]; 8];
        let _ = select(&reference, 16)?.authenticate(
            &inputs,
            &mut expected,
            &mut Md5BatchControl::new(1000),
        )?;
        for route in [Route::Public, Route::Secret, Route::Verify] {
            // Measure each route independently: do not infer verification's
            // reachable callback count from the public-output route.
            let mut count = 0;
            let mut callback = || {
                tick(&mut count);
                false
            };
            run(
                route,
                &reference,
                &inputs,
                &mut [[0; 16]; 8],
                &expected,
                &mut Md5BatchControl::with_cancellation(1000, &mut callback),
            )?;
            assert!(count > 0);
            for boundary in 1..=count {
                for mode in 0..3 {
                    let executor = executor()?;
                    let mut output = [[0xa5; 16]; 8];
                    let mut calls = 0;
                    let mut callback = || {
                        tick(&mut calls);
                        if calls != boundary {
                            return false;
                        }
                        match mode {
                            0 => true,
                            1 => {
                                executor.quarantine();
                                false
                            }
                            _ => std::panic::resume_unwind(Box::new("HMAC MD5 unwind")),
                        }
                    };
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run(
                            route,
                            &executor,
                            &inputs,
                            &mut output,
                            &expected,
                            &mut Md5BatchControl::with_cancellation(1000, &mut callback),
                        )
                    }));
                    if mode == 1 {
                        // Scalar long-key normalization has no borrowed SIMD
                        // authority. Revocation is observed at the next executor
                        // readiness check, not necessarily this callback return.
                        assert!((boundary..=count).contains(&calls));
                    } else {
                        assert_eq!(calls, boundary);
                    }
                    match mode {
                        0 => assert!(matches!(result, Ok(Err(Error::Cancelled)))),
                        1 => assert!(matches!(result, Ok(Err(Error::ExecutionFailed)))),
                        _ => assert!(result.is_err()),
                    }
                    assert_eq!(
                        output,
                        if matches!(route, Route::Secret) {
                            [[0; 16]; 8]
                        } else {
                            [[0xa5; 16]; 8]
                        }
                    );
                    if mode == 0 {
                        run(
                            route,
                            &executor,
                            &inputs,
                            &mut output,
                            &expected,
                            &mut Md5BatchControl::new(1000),
                        )?;
                        if matches!(route, Route::Public) {
                            assert_eq!(output, expected);
                        }
                    } else {
                        assert!(matches!(select(&executor, 16), Err(Error::ExecutionFailed)));
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn preflight(executor: &Md5Executor) -> Result<(), Error> {
    let key = [0x42; 80];
    let bytes = [0x39; 129];
    let message = BitString::new(&bytes, 8).map_err(|_| Error::MessageTooLong)?;
    let full = core::array::from_fn(|_| Some(Input::new(&key, message)));
    let candidate = [0; 17];
    for width in 10..=16 {
        for lane in 0..8 {
            for length in [
                None,
                Some(0),
                Some(9),
                Some(10),
                Some(15),
                Some(16),
                Some(17),
            ] {
                if length == Some(width) {
                    continue;
                }
                let mut candidates = [candidate.get(..width); 8];
                *candidates.get_mut(lane).ok_or(Error::SecretMemory)? =
                    length.and_then(|length| candidate.get(..length));
                rejects_before_work(executor, width, &full, &candidates)?;
            }
            let inactive =
                core::array::from_fn(|index| (index != lane).then(|| Input::new(&key, message)));
            rejects_before_work(executor, width, &inactive, &[candidate.get(..width); 8])?;
        }
    }
    Ok(())
}

fn rejects_before_work(
    executor: &Md5Executor,
    width: usize,
    inputs: &[Option<Input<'_>>; 8],
    candidates: &[Option<&[u8]>; 8],
) -> Result<(), Error> {
    let mut calls = 0;
    let mut callback = || {
        tick(&mut calls);
        false
    };
    let mut control = Md5BatchControl::with_cancellation(777, &mut callback);
    assert!(matches!(
        select(executor, width)?.verify(inputs, candidates, &mut control),
        Err(brynja_legacy_hmac::VerificationError::Operation(
            Error::TagLength
        ))
    ));
    assert_eq!(control.remaining(), 777);
    assert_eq!(calls, 0);
    let _ = select(executor, width)?;
    Ok(())
}
