use super::*;

#[test]
fn commit_preflights_every_width_before_any_write() -> Result<(), Error> {
    let staging = core::array::from_fn(|lane| [u8::try_from(lane).unwrap_or(0); 32]);
    for bad_slot in 0..CAPACITY {
        for width in 0..=33 {
            let mut storage = [[0xa5; 33]; CAPACITY];
            let mut slot = 0;
            let mut dest = storage.each_mut().map(|out| {
                let len = if slot == bad_slot { width } else { 32 };
                slot += 1;
                out.get_mut(..len)
            });
            let result = super::super::output::commit(&staging, &mut dest);
            if matches!(width, 28 | 32) {
                result?;
                for (lane, out) in storage.iter().enumerate() {
                    let len = if lane == bad_slot { width } else { 32 };
                    assert_eq!(out.get(..len), staging.get(lane).and_then(|s| s.get(..len)));
                    assert!(
                        out.get(len..)
                            .ok_or(Error::Invariant)?
                            .iter()
                            .all(|b| *b == 0xa5)
                    );
                }
            } else {
                assert_eq!(result, Err(Error::Invariant));
                assert_eq!(storage, [[0xa5; 33]; CAPACITY]);
            }
        }
    }
    Ok(())
}

#[test]
fn mixed_declassification_preflights_all_slots_and_clears_secrets() -> Result<(), Error> {
    let b = bits(b"abc", 8)?;
    let inputs = core::array::from_fn(|slot| {
        Some(Input::new(
            if slot % 2 == 0 {
                Algorithm::Sha224
            } else {
                Algorithm::Sha256
            },
            b,
        ))
    });
    let mut expected = [[0; 32]; CAPACITY];
    for (out, input) in expected.iter_mut().zip(inputs.iter().flatten()) {
        *out = oracle(input)?;
    }
    // All valid widths, wrong widths, and missing slots, including late errors.
    // Exercise the output owner directly: the existing lifecycle/differential
    // tests cover the hashing-to-output handoff. Do not rehash every shape under
    // Miri when the operation under test is only transfer and consuming Drop.
    for bad_slot in 0..CAPACITY {
        for width in 0..=34 {
            let mut secret = [[0xa5; 32]; CAPACITY];
            let mut public = [[0x69; 33]; CAPACITY];
            for ((out, source), input) in secret
                .iter_mut()
                .zip(&expected)
                .zip(inputs.iter().flatten())
            {
                let len = input.algorithm.output_bytes();
                out.get_mut(..len)
                    .ok_or(Error::Invariant)?
                    .copy_from_slice(source.get(..len).ok_or(Error::Invariant)?);
            }
            let owner = SecretBatchOutput::new(destinations(&mut secret, &inputs));
            let mut slot = 0;
            let dest = public.each_mut().map(|out| {
                let normal = if slot % 2 == 0 { 28 } else { 32 };
                let len = if slot == bad_slot { width } else { normal };
                slot += 1;
                out.get_mut(..len)
            });
            let result = owner.declassify(dest, PublicDeclassification::acknowledge());
            let expected_width = if bad_slot % 2 == 0 { 28 } else { 32 };
            if width == expected_width {
                result?;
                for ((out, source), input) in
                    public.iter().zip(&expected).zip(inputs.iter().flatten())
                {
                    let len = input.algorithm.output_bytes();
                    assert_eq!(out.get(..len), source.get(..len));
                    assert!(
                        out.get(len..)
                            .ok_or(Error::Invariant)?
                            .iter()
                            .all(|b| *b == 0x69)
                    );
                }
            } else {
                assert_eq!(result, Err(Error::OutputShape));
                assert_eq!(public, [[0x69; 33]; CAPACITY]);
            }
            for (out, input) in secret.iter().zip(inputs.iter().flatten()) {
                let len = input.algorithm.output_bytes();
                assert!(
                    out.get(..len)
                        .ok_or(Error::Invariant)?
                        .iter()
                        .all(|b| *b == 0)
                );
                assert!(
                    out.get(len..)
                        .ok_or(Error::Invariant)?
                        .iter()
                        .all(|b| *b == 0xa5)
                );
            }
        }
    }
    Ok(())
}
