use super::*;
use brynja_hash_sha2::Sha512TBits;

fn exercise(executor: &Executor<'_>) -> Result<u64, String> {
    let mut calls = 0_u64;
    for t in 1..512 {
        let Ok(parameter) = Sha512TBits::new(t) else {
            continue;
        };
        for tail in 1_u8..=8 {
            let storage = [[0xa0; 257], [0xc0; 257], [0x80; 257], [0; 257]];
            let algorithms = [
                Algorithm::Sha512T(parameter),
                Algorithm::Sha512_224,
                Algorithm::Sha512_256,
                Algorithm::Sha512T(parameter),
            ];
            let mut input = [None; 4];
            let mut expected = [None; 4];
            for (lane, ((bytes, slot), answer)) in storage
                .iter()
                .zip(&mut input)
                .zip(&mut expected)
                .enumerate()
            {
                // Rotate every identity/parameter through every physical lane.
                let algorithm = *algorithms
                    .get((lane.checked_add(usize::from(t)).ok_or("lane")?) % 4)
                    .ok_or("identity")?;
                let size: usize = if lane % 2 == 0 { 241 } else { 257 };
                let mut bytes = *bytes;
                *bytes
                    .get_mut(size.checked_sub(1).ok_or("size")?)
                    .ok_or("tail")? &= u8::MAX << (8_u8.checked_sub(tail).ok_or("tail width")?);
                // Borrow persistent storage below instead of the temporary.
                let bits = BitString::new(bytes.get(..size).ok_or("bytes")?, tail)
                    .map_err(|e| format!("{e:?}"))?;
                *answer = Some(oracle(algorithm, bits)?);
                *slot = Some((algorithm, size));
            }
            let mut owned = storage;
            let mut inputs = [None; 4];
            for ((bytes, descriptor), slot) in owned.iter_mut().zip(input).zip(&mut inputs) {
                let (algorithm, size) = descriptor.ok_or("descriptor")?;
                *bytes
                    .get_mut(size.checked_sub(1).ok_or("size")?)
                    .ok_or("tail")? &= u8::MAX << (8_u8.checked_sub(tail).ok_or("tail width")?);
                *slot = Some(Input::new(
                    algorithm,
                    BitString::new(bytes.get(..size).ok_or("bytes")?, tail)
                        .map_err(|e| format!("{e:?}"))?,
                ));
            }
            let mut output = [Some(Digest::Sha512(Sha512Digest::from_bytes([0x55; 64]))); 4];
            let mut cancel = || false;
            let mut control = Control::new(100, &mut cancel);
            let report = executor
                .digest(PublicData::new(&inputs), &mut output, &mut control)
                .map_err(|e| format!("{e:?}"))?;
            assert_eq!(output, expected, "t={t}, tail={tail}");
            assert_eq!(
                control.used(),
                report
                    .scalar_blocks
                    .checked_add(report.vector_blocks)
                    .ok_or("work")?
            );
            calls = calls.checked_add(report.vector_calls).ok_or("calls")?;
            for digest in output.into_iter().flatten() {
                if let Digest::Sha512T(value) = digest {
                    assert_eq!(value.parameter(), parameter);
                    assert_eq!(value.as_bytes().len(), parameter.output_bytes());
                    if t % 8 != 0 {
                        assert_eq!(value.as_bytes().last().ok_or("last")? & (255 >> (t % 8)), 0);
                    }
                }
            }
        }
    }
    Ok(calls)
}

#[test]
fn every_parameter_and_tail_portable() -> Result<(), String> {
    assert_eq!(exercise(&Executor::portable())?, 0);
    Ok(())
}

#[test]
fn every_parameter_and_tail_vector() -> Result<(), String> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let owner = Authority::for_compiled_target(kernel).map_err(|e| format!("{e:?}"))?;
        let executor = Executor::with_session(
            owner.session().map_err(|e| format!("{e:?}"))?,
            Mode::Require,
            1,
        )
        .map_err(|e| format!("{e:?}"))?;
        assert!(exercise(&executor)? >= 4080);
    }
    Ok(())
}

#[test]
fn derived_iv_work_is_bounded_and_named_identity_is_distinct() -> Result<(), String> {
    for t in [224, 256] {
        let parameter = Sha512TBits::new(t).map_err(|e| format!("{e:?}"))?;
        let bits = BitString::new(b"abc", 8).map_err(|e| format!("{e:?}"))?;
        let named = if t == 224 {
            Algorithm::Sha512_224
        } else {
            Algorithm::Sha512_256
        };
        let input = [
            Some(Input::new(Algorithm::Sha512T(parameter), bits)),
            Some(Input::new(named, bits)),
            None,
            None,
        ];
        let sentinel = [Some(Digest::Sha512(Sha512Digest::from_bytes([0x55; 64]))); 4];
        for maximum in 0..3 {
            let mut output = sentinel;
            let mut cancel = || false;
            let mut control = Control::new(maximum, &mut cancel);
            assert_eq!(
                Executor::portable().digest(PublicData::new(&input), &mut output, &mut control),
                Err(Error::WorkLimit)
            );
            assert_eq!(output, sentinel);
        }
        let mut output = sentinel;
        let mut cancel = || false;
        let mut control = Control::new(3, &mut cancel);
        let report = Executor::portable()
            .digest(PublicData::new(&input), &mut output, &mut control)
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(report.scalar_blocks, 3);
        let a = output[0].ok_or("general")?;
        let b = output[1].ok_or("named")?;
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.algorithm(), b.algorithm());
        assert_ne!(a, b);
    }
    Ok(())
}
