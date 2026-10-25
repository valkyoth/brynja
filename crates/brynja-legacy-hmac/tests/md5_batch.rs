//! Real SIMD is explicit; unavailable generic builds never count as native PASS.
#![cfg(feature = "md5-batch")]
use brynja_legacy_hmac::md5_batch::{
    Input, Md5Batch, Md5BatchControl, Md5Executor, Md5Mode, Report,
};
use brynja_legacy_hmac::{BitString, Error, Hmac, LegacyUse, Md5};

mod failures;

mod lanes;

mod support;

#[test]
#[ignore = "requires actual AVX2 / NEON instructions with complete target features"]
fn native_md5_distinct_lane_prefixes() -> Result<(), Error> {
    println!();
    lanes::run(&executor()?)
}

fn executor() -> Result<Md5Executor, Error> {
    Md5Executor::for_compiled_target(Md5Mode::Require).map_err(|_| Error::ExecutionUnavailable)
}
fn select(executor: &Md5Executor, width: usize) -> Result<Md5Batch<'_>, Error> {
    Md5Batch::with_tag_length(LegacyUse::acknowledge(), executor, width)
}
fn work(report: Report) -> Result<usize, Error> {
    [report.normalization, report.inner, report.outer]
        .iter()
        .try_fold(0usize, |total, w| {
            total
                .checked_add(w.scalar_blocks)
                .and_then(|n| n.checked_add(w.vector_blocks))
                .ok_or(Error::SecretMemory)
        })
}

#[test]
fn portable_authority_and_invalid_truncation_reject() {
    let executor = Md5Executor::portable();
    assert!(matches!(
        select(&executor, 16),
        Err(Error::ExecutionUnavailable)
    ));
    for size in [0, 9, 17, usize::MAX] {
        assert!(matches!(select(&executor, size), Err(Error::TagLength)));
    }
}

#[test]
#[ignore = "requires actual AVX2 / NEON instructions with complete target features"]
fn native_md5_differential_shapes_bits_and_truncations() -> Result<(), Error> {
    let executor = executor()?;
    let width = executor
        .backend()
        .ok_or(Error::ExecutionUnavailable)?
        .lane_width();
    for mask in 0..=255u16 {
        let keys = [0, 1, 63, 64, 65, 80, 129, 1024].map(support::key);
        let messages = [0, 55, 56, 63, 64, 65, 128, 193].map(support::message);
        let mut inputs = core::array::from_fn(|_| None);
        let mut expected = [[0; 16]; 8];
        for (lane, ((key, bytes), input)) in keys.iter().zip(&messages).zip(&mut inputs).enumerate()
        {
            if mask & (1 << lane) == 0 {
                continue;
            }
            let bits = BitString::new(bytes, if bytes.is_empty() { 0 } else { 8 })
                .map_err(|_| Error::MessageTooLong)?;
            *input = Some(Input::new(key, bits));
            let _ = Hmac::<Md5>::authenticate(
                LegacyUse::acknowledge(),
                key,
                bytes,
                expected.get_mut(lane).ok_or(Error::SecretMemory)?,
            )?;
        }
        let eligible = inputs.chunks(width).any(|g| g.iter().all(Option::is_some));
        let mut output = [[0xa5; 16]; 8];
        let result = select(&executor, 16)?.authenticate(
            &inputs,
            &mut output,
            &mut Md5BatchControl::new(1000),
        );
        if eligible {
            let (_, report) = result?;
            assert_eq!(report.inner.active_lanes, mask.count_ones() as usize);
            assert_eq!(report.outer.active_lanes, report.inner.active_lanes);
            assert!(report.inner.vector_blocks >= width && report.outer.vector_blocks >= width);
            assert_eq!(output, expected);
        } else {
            assert!(matches!(result, Err(Error::IneligibleWorkload)));
            assert_eq!(output, [[0xa5; 16]; 8]);
            assert!(matches!(
                select(&executor, 16)?.authenticate_secret(
                    &inputs,
                    &mut output,
                    &mut Md5BatchControl::new(1000)
                ),
                Err(Error::IneligibleWorkload)
            ));
            assert_eq!(output, [[0; 16]; 8]);
        }
    }
    println!();
    for length in [0, 1, 63, 64, 65, 80, 1024] {
        let key = support::key(length);
        for size in [0, 1, 55, 56, 63, 64, 65, 127, 128, 4096] {
            let bytes = support::message(size);
            let message = BitString::new(&bytes, if size == 0 { 0 } else { 8 })
                .map_err(|_| Error::MessageTooLong)?;
            let actual = check_case(&executor, &key, message)?;
            print!("LEGACY_MD5_BATCH_BYTE:{length}:{size}:");
            for byte in actual {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    for length in [0, 64, 65, 129] {
        let key = vec![0xa7; length];
        for bits in [
            0usize, 1, 2, 3, 4, 5, 6, 7, 8, 9, 447, 448, 449, 503, 504, 505, 511, 512, 513, 1023,
            1024, 1025,
        ] {
            let mut bytes = vec![0xa5; bits.div_ceil(8)];
            let valid = if bits == 0 {
                0
            } else if bits % 8 == 0 {
                8
            } else {
                u8::try_from(bits % 8).map_err(|_| Error::SecretMemory)?
            };
            if valid != 0 && valid != 8 {
                *bytes.last_mut().ok_or(Error::SecretMemory)? &= 255 << (8 - valid);
            }
            let message = BitString::new(&bytes, valid).map_err(|_| Error::MessageTooLong)?;
            let actual = check_case(&executor, &key, message)?;
            print!("LEGACY_MD5_BATCH_BITS:{length}:{bits}:");
            for byte in actual {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    println!("LEGACY_MD5_BATCH: 256 masks, 70 byte cases, 88 bit cases; no fallback");
    Ok(())
}

fn check_case(
    executor: &Md5Executor,
    key: &[u8],
    message: BitString<'_>,
) -> Result<[u8; 16], Error> {
    let inputs = core::array::from_fn(|_| Some(Input::new(key, message)));
    let mut expected = [0; 16];
    let _ = Hmac::<Md5>::new(LegacyUse::acknowledge(), key)?
        .finalize_bits_tag(message, &mut expected)?;
    let mut full = [0; 16];
    for length in 10..=16 {
        let mut output = [[0xa5; 16]; 8];
        let mut budget = Md5BatchControl::new(10000);
        let (tags, report) =
            select(executor, length)?.authenticate(&inputs, &mut output, &mut budget)?;
        for lane in 0..8 {
            assert_eq!(tags.get(lane), expected.get(..length));
        }
        assert_eq!(tags.get(8), None);
        assert_eq!(
            10000usize.checked_sub(budget.remaining()),
            Some(work(report)?)
        );
        if length == 16 {
            full.copy_from_slice(tags.get(0).ok_or(Error::SecretMemory)?);
        }
        for row in &output {
            assert!(
                row.get(length..)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|b| *b == 0)
            );
        }
        let candidates = output.each_ref().map(|row| row.get(..length));
        let verified = select(executor, length)?.verify(
            &inputs,
            &candidates,
            &mut Md5BatchControl::new(work(report)?),
        );
        assert_eq!(verified, Ok(report));
        let (secret, actual) = select(executor, length)?.authenticate_secret(
            &inputs,
            &mut output,
            &mut Md5BatchControl::new(work(report)?),
        )?;
        for lane in 0..8 {
            assert_eq!(secret.expose(lane), expected.get(..length));
        }
        assert_eq!(actual, report);
        assert_eq!(secret.expose(8), None);
        drop(secret);
        assert_eq!(output, [[0; 16]; 8]);
    }
    Ok(full)
}

#[test]
#[ignore = "requires actual AVX2 / NEON instructions with complete target features"]
fn native_md5_verification_and_lifecycle() -> Result<(), Error> {
    println!();
    let executor = executor()?;
    failures::preflight(&executor)?;
    let bytes = [0x39; 129];
    let key = [0xa7; 80];
    let message = BitString::new(&bytes, 8).map_err(|_| Error::MessageTooLong)?;
    let inputs = core::array::from_fn(|_| Some(Input::new(&key, message)));
    let mut expected = [[0; 16]; 8];
    let (_, report) = select(&executor, 16)?.authenticate(
        &inputs,
        &mut expected,
        &mut Md5BatchControl::new(1000),
    )?;
    let initial_health = executor.health();
    for lane in 0..8 {
        for byte in 0..16 {
            let mut wrong = expected;
            *wrong
                .get_mut(lane)
                .and_then(|row| row.get_mut(byte))
                .ok_or(Error::SecretMemory)? ^= 1;
            let candidates = wrong.each_ref().map(|row| Some(row.as_slice()));
            let rejected = select(&executor, 16)?.verify(
                &inputs,
                &candidates,
                &mut Md5BatchControl::new(1000),
            );
            fn authorize<T, E>(result: Result<T, E>) -> Result<bool, E> {
                let _ = result?;
                Ok(true)
            }
            assert!(!rejected.is_ok());
            assert_eq!(
                authorize(rejected),
                Err(brynja_legacy_hmac::VerificationError::Mismatch(report))
            );
            assert_eq!(executor.health(), initial_health);
        }
    }
    assert!(matches!(
        select(&executor, 16)?.verify(&inputs, &[None; 8], &mut Md5BatchControl::new(0)),
        Err(brynja_legacy_hmac::VerificationError::Operation(
            Error::TagLength
        ))
    ));
    for budget in 0..work(report)? {
        let mut output = [[0xa5; 16]; 8];
        let candidates = expected.each_ref().map(|row| Some(row.as_slice()));
        assert!(matches!(
            select(&executor, 16)?.verify(&inputs, &candidates, &mut Md5BatchControl::new(budget)),
            Err(brynja_legacy_hmac::VerificationError::Operation(
                Error::WorkLimit
            ))
        ));
        assert!(matches!(
            select(&executor, 16)?.authenticate(
                &inputs,
                &mut output,
                &mut Md5BatchControl::new(budget)
            ),
            Err(Error::WorkLimit)
        ));
        assert_eq!(output, [[0xa5; 16]; 8]);
        assert!(matches!(
            select(&executor, 16)?.authenticate_secret(
                &inputs,
                &mut output,
                &mut Md5BatchControl::new(budget)
            ),
            Err(Error::WorkLimit)
        ));
        assert_eq!(output, [[0; 16]; 8]);
        let _ = select(&executor, 16)?.authenticate(
            &inputs,
            &mut output,
            &mut Md5BatchControl::new(work(report)?),
        )?;
        assert_eq!(output, expected);
    }
    let token = select(&executor, 16)?;
    let public = select(&executor, 16)?;
    let verify = select(&executor, 16)?;
    executor.quarantine();
    let mut output = [[0xa5; 16]; 8];
    assert!(matches!(
        public.authenticate(&inputs, &mut output, &mut Md5BatchControl::new(1000)),
        Err(Error::ExecutionFailed)
    ));
    assert_eq!(output, [[0xa5; 16]; 8]);
    let candidates = expected.each_ref().map(|row| Some(row.as_slice()));
    assert!(matches!(
        verify.verify(&inputs, &candidates, &mut Md5BatchControl::new(1000)),
        Err(brynja_legacy_hmac::VerificationError::Operation(
            Error::ExecutionFailed
        ))
    ));
    assert!(matches!(
        token.authenticate_secret(&inputs, &mut output, &mut Md5BatchControl::new(1000)),
        Err(Error::ExecutionFailed)
    ));
    assert_eq!(output, [[0; 16]; 8]);
    assert!(matches!(select(&executor, 16), Err(Error::ExecutionFailed)));
    println!(
        "LEGACY_MD5_BATCH_LIFECYCLE: all tag bytes checked; preflight before work; three profiles budget/revocation"
    );
    Ok(())
}

#[test]
#[ignore = "requires actual AVX2 / NEON instructions with complete target features"]
fn native_md5_cancel_revoke_unwind_each_boundary() -> Result<(), Error> {
    println!();
    failures::check()?;
    println!(
        "LEGACY_MD5_BATCH_FAILURES: scalar/SIMD normalization; public/secret/verify; every cancel/revoke/unwind boundary"
    );
    Ok(())
}
