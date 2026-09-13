//! Operational MD5 batch routing and transactional output acceptance.
#![cfg(feature = "execution")]
use brynja_legacy_md5::{
    BitString, Md5BatchControl, Md5BatchError,
    execution::{Error, Executor, Mode, PublicData},
};

#[test]
fn masks_permutations_unequal_lengths_and_bit_tails() -> Result<(), Box<dyn std::error::Error>> {
    let accelerated = Executor::for_compiled_target(Mode::Prefer)?;
    if std::env::var_os("BRYNJA_REQUIRE_MD5_EXECUTION").is_some() {
        assert!(
            accelerated.backend().is_some(),
            "native SIMD required, not portable success"
        );
    }
    let portable = Executor::portable();
    let data: [[u8; 257]; 8] = core::array::from_fn(|i| [u8::try_from(i * 32).unwrap_or(0); 257]);
    let mut vector_total = 0;
    for mask in 0..256u16 {
        for valid in 1..=8 {
            let mut data = data;
            let mut inputs = [None; 8];
            for (i, (slot, bytes)) in inputs.iter_mut().zip(data.iter_mut()).enumerate() {
                if mask & (1 << i) != 0 {
                    let lengths = if mask == 255 {
                        [65, 128, 129, 200, 256, 257, 128, 200]
                    } else {
                        [0, 55, 64, 65, 128, 129, 200, 257]
                    };
                    let length = lengths
                        .get((i + usize::from(valid)) % 8)
                        .copied()
                        .ok_or("test length")?;
                    let bytes = bytes.get_mut(..length).ok_or("test slice")?;
                    if let Some(last) = bytes.last_mut() {
                        *last &= u8::MAX << (8 - valid);
                    }
                    *slot = Some(
                        BitString::new(bytes, if length == 0 { 0 } else { valid })
                            .map_err(|_| "invalid test bits")?,
                    );
                }
            }
            let mut expected = [[0u8; 16]; 8];
            for (dst, input) in expected.iter_mut().zip(inputs) {
                if let Some(input) = input {
                    *dst = brynja_legacy_md5::md5_bits(input)?;
                }
            }
            for executor in [&portable, &accelerated] {
                let mut output = expected.map(|lane| lane.map(|byte| !byte));
                let mut control = Md5BatchControl::new(128);
                let report = executor.digest(
                    &inputs,
                    &mut output,
                    &mut control,
                    PublicData::acknowledge(),
                )?;
                assert_eq!(output, expected);
                let mut wanted_vector = 0;
                if let Some(backend) = executor.backend() {
                    let width = backend.lane_width();
                    for group in inputs.chunks(width) {
                        let blocks = group
                            .iter()
                            .map(|b| b.map_or(0, |b| b.bit_len() / 512))
                            .min()
                            .unwrap_or(0);
                        wanted_vector += blocks * width;
                    }
                }
                let mut total = 0usize;
                for input in inputs.iter().flatten() {
                    total += (input.bit_len() + 65).div_ceil(512);
                }
                assert_eq!(report.work.vector_blocks, wanted_vector);
                assert_eq!(report.work.scalar_blocks, total - wanted_vector);
                assert_eq!(report.work.active_lanes, inputs.iter().flatten().count());
                assert_eq!(control.remaining(), 128 - total);
                assert_eq!(
                    report.backend,
                    executor.backend().filter(|_| wanted_vector > 0)
                );
                assert_eq!(
                    report.vector_width,
                    report.backend.map_or(0, |b| b.lane_width())
                );
                vector_total += wanted_vector;
            }
        }
    }
    if let Some(backend) = accelerated.backend() {
        assert!(vector_total > 0);
        println!(
            "MD5_OPERATIONAL: {}; cases=2048; normal-build SIMD",
            backend.as_str()
        );
    }
    Ok(())
}

#[test]
fn required_simd_and_failure_atomicity() -> Result<(), Box<dyn std::error::Error>> {
    let executor = Executor::for_compiled_target(Mode::Require);
    let Ok(executor) = executor else {
        assert!(std::env::var_os("BRYNJA_REQUIRE_MD5_EXECUTION").is_none());
        return Ok(());
    };
    let mut output = [[0xa5; 16]; 8];
    let mut control = Md5BatchControl::new(128);
    assert_eq!(
        executor.digest(
            &[None; 8],
            &mut output,
            &mut control,
            PublicData::acknowledge()
        ),
        Err(Error::IneligibleWorkload)
    );
    assert_eq!(output, [[0xa5; 16]; 8]);
    assert_eq!(control.remaining(), 128);
    let data = [0u8; 128];
    let inputs = [Some(BitString::new(&data, 8).map_err(|_| "invalid test bits")?); 8];
    let expected = [brynja_legacy_md5::md5(&data)?; 8];
    for budget in 0..24 {
        let mut control = Md5BatchControl::new(budget);
        assert_eq!(
            executor.digest(
                &inputs,
                &mut output,
                &mut control,
                PublicData::acknowledge()
            ),
            Err(Error::Batch(Md5BatchError::WorkLimit))
        );
        assert_eq!(output, [[0xa5; 16]; 8]);
    }
    let report = executor.digest(
        &inputs,
        &mut output,
        &mut Md5BatchControl::new(24),
        PublicData::acknowledge(),
    )?;
    assert_eq!(output, expected);
    assert_eq!(report.work.vector_blocks, 16);
    assert_eq!(report.work.scalar_blocks, 8);
    assert!(!executor.backend().is_some_and(|b| b.is_admitted()));
    executor.quarantine();
    output = [[0xa5; 16]; 8];
    assert_eq!(
        executor.digest(
            &inputs,
            &mut output,
            &mut control,
            PublicData::acknowledge()
        ),
        Err(Error::Quarantined)
    );
    assert_eq!(output, [[0xa5; 16]; 8]);
    Ok(())
}

#[test]
fn callback_unwind_is_terminal_and_transactional() {
    let executor = Executor::portable();
    let mut output = [[0xa5; 16]; 8];
    let mut callback =
        || std::panic::resume_unwind(Box::new("synthetic cancellation callback unwind"));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor.digest(
            &[None; 8],
            &mut output,
            &mut Md5BatchControl::with_cancellation(0, &mut callback),
            PublicData::acknowledge(),
        )
    }));
    assert!(result.is_err());
    assert_eq!(output, [[0xa5; 16]; 8]);
    assert_eq!(
        executor.health(),
        brynja_legacy_md5::Md5BackendHealth::Quarantined
    );
}
