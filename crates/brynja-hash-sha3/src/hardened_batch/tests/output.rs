use super::*;

#[test]
fn commit_preflights_all_slices_and_preserves_sparse_slots() -> Result<(), Error> {
    let staging: [u8; 680] = core::array::from_fn(|i| u8::try_from(i % 251).unwrap_or(0));
    for active in 0_u8..16 {
        for width in [0, 1, 28, 32, 48, 64, 135, 136, 137, 167, 168, 169] {
            let total = active.count_ones() as usize * width;
            for available in [total.saturating_sub(1), total, staging.len()] {
                let mut storage = [[0xa5; 170]; CAPACITY];
                let mut slot = 0;
                let mut dest = storage.each_mut().map(|out| {
                    let present = active & (1 << slot) != 0;
                    slot += 1;
                    if present { out.get_mut(..width) } else { None }
                });
                let result = super::super::output::commit(
                    staging.get(..available).ok_or(Error::Invariant)?,
                    &mut dest,
                );
                if available < total {
                    assert_eq!(result, Err(Error::Invariant));
                    assert_eq!(storage, [[0xa5; 170]; CAPACITY]);
                } else {
                    result?;
                    let mut offset = 0;
                    for (slot, out) in storage.iter().enumerate() {
                        let len = if active & (1 << slot) != 0 { width } else { 0 };
                        assert_eq!(out.get(..len), staging.get(offset..offset + len));
                        assert!(
                            out.get(len..)
                                .ok_or(Error::Invariant)?
                                .iter()
                                .all(|b| *b == 0xa5)
                        );
                        offset += len;
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn declassification_is_atomic_and_clears_secret_slots() -> Result<(), Error> {
    // Exercise ownership/transfer directly; differential tests cover hashing.
    for width in [0, 1, 28, 32, 48, 64, 135, 136, 137, 167, 168, 169, 337] {
        for bad_slot in 0..CAPACITY {
            for shape in 0..3 {
                let mut secret = [[0x3c; 337]; CAPACITY];
                let owner =
                    SecretBatchOutput::new(secret.each_mut().map(|out| out.get_mut(..width)));
                let mut public = [[0xa5; 338]; CAPACITY];
                let mut slot = 0;
                let dest = public.each_mut().map(|out| {
                    let bad = slot == bad_slot;
                    slot += 1;
                    if bad && shape == 2 {
                        None
                    } else {
                        out.get_mut(..width + usize::from(bad && shape == 1))
                    }
                });
                let result = owner.declassify(dest, Sha3PublicDeclassification::acknowledge());
                if shape == 0 {
                    result?;
                    for out in &public {
                        assert!(
                            out.get(..width)
                                .ok_or(Error::Invariant)?
                                .iter()
                                .all(|b| *b == 0x3c)
                        );
                        assert!(
                            out.get(width..)
                                .ok_or(Error::Invariant)?
                                .iter()
                                .all(|b| *b == 0xa5)
                        );
                    }
                } else {
                    assert_eq!(result, Err(Error::InvalidDestination));
                    assert_eq!(public, [[0xa5; 338]; CAPACITY]);
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
                            .all(|b| *b == 0x3c)
                    );
                }
            }
        }
    }
    Ok(())
}
