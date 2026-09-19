use super::*;

#[test]
fn commit_preflights_every_width_before_any_write() -> Result<(), Error> {
    let staging = [[0x11; 64], [0x22; 64], [0x33; 64], [0x44; 64]];
    for slot in 0..CAPACITY {
        for width in 0..=65 {
            let mut storage = [[0xa5; 65]; CAPACITY];
            let mut index = 0;
            let mut destinations = storage.each_mut().map(|out| {
                let len = if index == slot { width } else { 64 };
                index += 1;
                out.get_mut(..len)
            });
            let result = super::super::output::commit(&staging, &mut destinations);
            if (1..=64).contains(&width) {
                result?;
                for (index, (out, source)) in storage.iter().zip(&staging).enumerate() {
                    let len = if index == slot { width } else { 64 };
                    assert_eq!(out.get(..len), source.get(..len));
                    assert!(
                        out.get(len..)
                            .ok_or(Error::Invariant)?
                            .iter()
                            .all(|b| *b == 0xa5)
                    );
                }
            } else {
                assert_eq!(result, Err(Error::Invariant));
                assert_eq!(storage, [[0xa5; 65]; CAPACITY]);
            }
        }
    }
    Ok(())
}

#[test]
fn declassification_all_widths_is_atomic_and_clears_secrets() -> Result<(), Error> {
    // Test output ownership directly, not repeated hashing under Miri. Existing
    // all-t/oracle tests cover digest identity, masking and the engine handoff.
    for width in 1..=64 {
        for slot in 0..CAPACITY {
            for shape in 0..3 {
                let mut secret = [[0x63; 64]; CAPACITY];
                let mut public = [[0xa5; 65]; CAPACITY];
                let owner =
                    SecretBatchOutput::new(secret.each_mut().map(|out| out.get_mut(..width)));
                let mut index = 0;
                let destinations = public.each_mut().map(|out| {
                    let selected = index == slot;
                    index += 1;
                    if selected && shape == 2 {
                        None
                    } else {
                        let len = if selected && shape == 1 {
                            width - 1
                        } else {
                            width
                        };
                        out.get_mut(..len)
                    }
                });
                let result = owner.declassify(destinations, PublicDeclassification::acknowledge());
                if shape == 0 {
                    result?;
                    for out in &public {
                        assert!(
                            out.get(..width)
                                .ok_or(Error::Invariant)?
                                .iter()
                                .all(|b| *b == 0x63)
                        );
                        assert!(
                            out.get(width..)
                                .ok_or(Error::Invariant)?
                                .iter()
                                .all(|b| *b == 0xa5)
                        );
                    }
                } else {
                    assert_eq!(result, Err(Error::OutputShape));
                    assert_eq!(public, [[0xa5; 65]; CAPACITY]);
                }
                for out in &secret {
                    assert!(
                        out.get(..width)
                            .ok_or(Error::Invariant)?
                            .iter()
                            .all(|b| *b == 0)
                    );
                    assert!(
                        out.get(width..)
                            .ok_or(Error::Invariant)?
                            .iter()
                            .all(|b| *b == 0x63)
                    );
                }
            }
        }
    }
    Ok(())
}
