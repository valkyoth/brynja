use super::*;
pub(super) fn routes() -> Vec<Route> {
    let mut routes = vec![
        Route::Sha256(None),
        Route::Sha512(None),
        Route::Keccak(None),
    ];
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        assert!(sha256::Kernel::Avx2.compiled());
        assert!(sha512::Kernel::Avx2.compiled());
        assert!(keccak::Kernel::Avx2.compiled());
        routes.extend([
            Route::Sha256(Some(sha256::Kernel::Avx2)),
            Route::Sha512(Some(sha512::Kernel::Avx2)),
            Route::Keccak(Some(keccak::Kernel::Avx2)),
        ]);
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        assert!(sha256::Kernel::Neon.compiled());
        assert!(sha512::Kernel::Neon.compiled());
        assert!(keccak::Kernel::Neon.compiled());
        routes.extend([
            Route::Sha256(Some(sha256::Kernel::Neon)),
            Route::Sha512(Some(sha512::Kernel::Neon)),
            Route::Keccak(Some(keccak::Kernel::Neon)),
        ]);
    }
    // Keep the generic build warning-free without changing native coverage.
    routes.shrink_to_fit();
    routes
}
fn algorithm(route: Route, index: usize) -> Algorithm {
    match route {
        Route::Sha256(_) => Algorithm::Sha256(if index.is_multiple_of(2) {
            sha256::Algorithm::Sha224
        } else {
            sha256::Algorithm::Sha256
        }),
        Route::Sha512(_) => Algorithm::Sha512(match index % 4 {
            0 => sha512::Algorithm::Sha384,
            1 => sha512::Algorithm::Sha512,
            2 => sha512::Algorithm::Sha512_224,
            _ => sha512::Algorithm::Sha512_256,
        }),
        Route::Keccak(_) => Algorithm::Keccak(keccak::Algorithm::Shake256, 257),
    }
}
pub(super) fn clear(s: &Session) {
    for data in [
        s.stack.bytes(),
        s.output.bytes(),
        s.staging.bytes(),
        s.scratch.bytes(),
    ] {
        assert!(data.iter().all(|v| *v == 0));
    }
}
fn compare_sha2(raw: &Input<'_>, actual: &[u8]) -> Result<(), Error> {
    use brynja_hash_sha2::*;
    let bits = BitString::new(raw.message.bytes, raw.message.valid_bits)
        .map_err(|_| Error::InvalidInput)?;
    macro_rules! compare {
        ($state:expr) => {
            assert_eq!(
                actual,
                $state
                    .finalize_bits(bits)
                    .map_err(|_| Error::Invariant)?
                    .as_bytes()
            )
        };
    }
    match raw.algorithm {
        Algorithm::Sha256(sha256::Algorithm::Sha224) => compare!(Sha224::new()),
        Algorithm::Sha256(sha256::Algorithm::Sha256) => compare!(Sha256::new()),
        Algorithm::Sha512(sha512::Algorithm::Sha384) => compare!(Sha384::new()),
        Algorithm::Sha512(sha512::Algorithm::Sha512) => compare!(Sha512::new()),
        Algorithm::Sha512(sha512::Algorithm::Sha512_224) => compare!(Sha512_224::new()),
        Algorithm::Sha512(sha512::Algorithm::Sha512_256) => compare!(Sha512_256::new()),
        Algorithm::Sha512(sha512::Algorithm::Sha512T(t)) => compare!(Sha512T::new(t)),
        _ => return Err(Error::Invariant),
    }
    Ok(())
}
#[test]
fn native_batch_routes_bits_boundaries_and_general_parameters() -> Result<(), Error> {
    for route in routes() {
        if matches!(route, Route::Keccak(_)) {
            continue;
        }
        let mut session = Session::new(route, limits())?;
        let mut count = 0;
        for length in [129usize, 135, 136, 167, 168, 255, 256, 4097] {
            for valid in 1u8..=8 {
                let mut bytes = vec![0x53; length];
                if let Some(last) = bytes.last_mut() {
                    *last &= u8::MAX << (8 - valid);
                }
                let raw = core::array::from_fn(|i| {
                    if i < route.capacity() {
                        Some(Input {
                            algorithm: algorithm(route, i),
                            message: Bits {
                                bytes: &bytes,
                                valid_bits: valid,
                            },
                            name: Bits::bytes(&[]),
                            customization: Bits::bytes(&[]),
                        })
                    } else {
                        None
                    }
                });
                let output = session.digest(&raw, 10000, &Cancellation::new())?;
                for (i, raw) in raw.iter().enumerate() {
                    if let Some(raw) = raw {
                        compare_sha2(raw, output.expose(i).ok_or(Error::Invariant)?)?;
                        count += 1;
                    } else {
                        assert!(output.expose(i).is_none());
                    }
                }
                drop(output);
                clear(&session);
            }
        }
        if matches!(route, Route::Sha512(_)) {
            for t in 1..=511 {
                if t == 384 {
                    continue;
                }
                let t = brynja_hash_sha2::Sha512TBits::new(t).map_err(|_| Error::Invariant)?;
                let bytes = [0x71; 129];
                let raw = core::array::from_fn(|i| {
                    if i < 4 {
                        Some(Input::bytes(
                            Algorithm::Sha512(sha512::Algorithm::Sha512T(t)),
                            &bytes,
                        ))
                    } else {
                        None
                    }
                });
                let output = session.digest(&raw, 100, &Cancellation::new())?;
                for (i, raw) in raw.iter().enumerate().take(4) {
                    compare_sha2(
                        raw.as_ref().ok_or(Error::Invariant)?,
                        output.expose(i).ok_or(Error::Invariant)?,
                    )?;
                }
            }
        }
        println!("MACOS_RESIDENT_BATCH: {route:?}; named_differential={count}");
    }
    Ok(())
}
#[test]
fn failures_and_forgotten_outputs_preserve_only_ordinary_reuse() -> Result<(), Error> {
    for route in routes() {
        let bytes = [0x4a; 1024];
        let raw = core::array::from_fn(|i| {
            if i < route.capacity() {
                Some(Input::bytes(algorithm(route, i), &bytes))
            } else {
                None
            }
        });
        let mut session = Session::new(route, limits())?;
        assert!(session.digest(&raw, 0, &Cancellation::new()).is_err());
        clear(&session);
        assert!(!session.is_quarantined());
        drop(session.digest(&raw, 10000, &Cancellation::new())?);
        for point in [0, 1, usize::MAX] {
            for fault in [
                Fault::Cancel(point),
                Fault::Panic(point),
                Fault::Revoke(point),
            ] {
                if matches!(fault, Fault::Revoke(_))
                    && matches!(
                        route,
                        Route::Sha256(None) | Route::Sha512(None) | Route::Keccak(None)
                    )
                {
                    continue;
                }
                let mut s = Session::new(route, limits())?;
                s.fault = fault;
                assert!(s.digest(&raw, 10000, &Cancellation::new()).is_err());
                clear(&s);
                assert_eq!(s.is_quarantined(), !matches!(fault, Fault::Cancel(_)));
                s.fault = Fault::None;
                if !s.is_quarantined() {
                    drop(s.digest(&raw, 10000, &Cancellation::new())?);
                } else {
                    assert!(matches!(
                        s.digest(&raw, 10000, &Cancellation::new()),
                        Err(Error::Quarantined)
                    ));
                }
            }
        }
        core::mem::forget(session.digest(&raw, 10000, &Cancellation::new())?);
        // Exercise the session's whole-buffer defense independently of the
        // leaf executors, which already clear their own used scratch regions.
        session.scratch.bytes_mut().fill(0xa5);
        session.staging.bytes_mut().fill(0x5a);
        session.quarantine();
        clear(&session);
    }
    Ok(())
}

#[test]
fn sparse_outputs_invalid_bits_and_declassification_are_transactional() -> Result<(), Error> {
    let route = Route::Sha256(None);
    let mut s = Session::new(route, limits())?;
    let mut inputs = [const { None }; 8];
    for (index, slot) in inputs.iter_mut().enumerate() {
        if index == 1 || index == 6 {
            *slot = Some(Input::bytes(
                Algorithm::Sha256(sha256::Algorithm::Sha256),
                b"abc",
            ));
        }
    }
    let output = s.digest(&inputs, 100, &Cancellation::new())?;
    for index in 0..8 {
        assert_eq!(output.expose(index).is_some(), index == 1 || index == 6);
    }
    assert!(output.expose(8).is_none());
    let mut first = [0xa5; 32];
    let mut wrong = [0x5a; 31];
    assert_eq!(
        output.declassify(
            [
                None,
                Some(&mut first),
                None,
                None,
                None,
                None,
                Some(&mut wrong),
                None
            ],
            PublicDeclassification::acknowledge()
        ),
        Err(Error::InvalidInput)
    );
    assert_eq!(first, [0xa5; 32]);
    assert_eq!(wrong, [0x5a; 31]);
    clear(&s);
    let mut second = [0xa5; 32];
    s.digest(&inputs, 100, &Cancellation::new())?.declassify(
        [
            None,
            Some(&mut first),
            None,
            None,
            None,
            None,
            Some(&mut second),
            None,
        ],
        PublicDeclassification::acknowledge(),
    )?;
    assert_eq!(
        &first,
        brynja_hash_sha2::Sha256::new()
            .finalize_bits(
                brynja_hash_sha2::BitString::new(b"abc", 8).map_err(|_| Error::Invariant)?
            )
            .map_err(|_| Error::Invariant)?
            .as_bytes()
    );
    assert_eq!(first, second);
    clear(&s);
    core::mem::forget(s.digest(&inputs, 100, &Cancellation::new())?);
    let invalid = inputs
        .get_mut(6)
        .and_then(Option::as_mut)
        .ok_or(Error::Invariant)?;
    invalid.message = Bits {
        bytes: &[0xff],
        valid_bits: 1,
    };
    assert!(matches!(
        s.digest(&inputs, 100, &Cancellation::new()),
        Err(Error::InvalidInput)
    ));
    clear(&s);
    assert!(!s.is_quarantined());
    drop(s.digest(&[const { None }; 8], 0, &Cancellation::new())?);
    clear(&s);
    Ok(())
}

#[test]
fn distinct_sparse_lanes_short_tails_and_required_work_are_preserved() -> Result<(), Error> {
    for route in routes() {
        let mut s = Session::new(route, limits())?;
        // NEON width is four narrow lanes and two wide/sponge lanes. The odd
        // final active lane forces a scalar tail without losing exact slot identity.
        let capacity = route.capacity();
        let messages: [Vec<u8>; 8] = core::array::from_fn(|i| {
            (0..337 + i * 131)
                .map(|n| (n * 31 + i * 17).to_le_bytes()[0])
                .collect()
        });
        for mask in [0b10110111u8, 0b01111101, 0b11111111] {
            let raw = core::array::from_fn(|i| {
                if i < capacity && mask & (1 << i) != 0 {
                    messages
                        .get(i)
                        .map(|bytes| Input::bytes(algorithm(route, i), bytes))
                } else {
                    None
                }
            });
            let out = s.digest(&raw, 10000, &Cancellation::new())?;
            for (i, raw) in raw.iter().enumerate() {
                if let Some(raw) = raw {
                    let actual = out.expose(i).ok_or(Error::Invariant)?;
                    if matches!(route, Route::Keccak(_)) {
                        assert_eq!(actual, super::sponge::oracle(raw)?);
                    } else {
                        compare_sha2(raw, actual)?;
                    }
                    assert_eq!(out.algorithm(i), Some(raw.algorithm));
                } else {
                    assert!(out.expose(i).is_none());
                }
            }
            drop(out);
            clear(&s);
        }
        // Required SIMD with one active input is never silently portable.
        if matches!(
            route,
            Route::Sha256(Some(_)) | Route::Sha512(Some(_)) | Route::Keccak(Some(_))
        ) {
            let mut raw = [const { None }; 8];
            *raw.get_mut(capacity - 1).ok_or(Error::Invariant)? = Some(Input::bytes(
                algorithm(route, 0),
                messages.first().ok_or(Error::Invariant)?,
            ));
            assert!(matches!(
                s.digest(&raw, 1000, &Cancellation::new()),
                Err(Error::Sha256(sha256::Error::IneligibleWorkload)
                    | Error::Sha512(sha512::Error::IneligibleWorkload)
                    | Error::Keccak(keccak::Error::IneligibleWorkload))
            ));
            assert!(!s.is_quarantined());
            clear(&s);
        }
    }
    Ok(())
}
