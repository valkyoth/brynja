use super::*;

#[test]
fn unqualified_import_rejects_before_touching_key_or_storage() -> Result<(), Error> {
    for width in [16, 24, 32] {
        let key = [0x37; 32];
        let mut primary = [0x91; 32];
        let mut complemented = [0x92; 32];
        assert!(matches!(
            Keys::new_with_fixture_profile(
                key.get(..width).ok_or(Error::SecretMemory)?,
                primary.get_mut(..width).ok_or(Error::SecretMemory)?,
                complemented.get_mut(..width).ok_or(Error::SecretMemory)?,
                false,
            ),
            Err(ProfileFailure::UnsupportedBuild)
        ));
        assert_eq!(key, [0x37; 32]);
        assert_eq!(primary, [0x91; 32]);
        assert_eq!(complemented, [0x92; 32]);
    }
    Ok(())
}

#[test]
fn classified_import_rejection_clears_admitted_storage() -> Result<(), Error> {
    let key = [0x37; 17]; // Not an admitted AES key width.
    let mut primary = [0x91; 32];
    let mut complemented = [0x92; 32];
    assert!(matches!(
        Keys::new_with_fixture_profile(
            &key,
            primary.get_mut(..17).ok_or(Error::SecretMemory)?,
            complemented.get_mut(..17).ok_or(Error::SecretMemory)?,
            true,
        ),
        Err(ProfileFailure::ImportRejected)
    ));
    assert_eq!(key, [0x37; 17]);
    assert!(
        primary
            .get(..17)
            .ok_or(Error::SecretMemory)?
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(
        complemented
            .get(..17)
            .ok_or(Error::SecretMemory)?
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(
        primary
            .get(17..)
            .ok_or(Error::SecretMemory)?
            .iter()
            .all(|byte| *byte == 0x91)
    );
    assert!(
        complemented
            .get(17..)
            .ok_or(Error::SecretMemory)?
            .iter()
            .all(|byte| *byte == 0x92)
    );

    let key = [0x37; 16];
    let mut primary = [0x91; 32];
    let mut complemented = [0x92; 32];
    assert!(matches!(
        Keys::new_with_fixture_profile(
            &key,
            primary.get_mut(..16).ok_or(Error::SecretMemory)?,
            complemented.get_mut(..15).ok_or(Error::SecretMemory)?,
            true,
        ),
        Err(ProfileFailure::ImportRejected)
    ));
    assert_eq!(primary.get(..16).ok_or(Error::SecretMemory)?, &[0; 16]);
    assert_eq!(complemented.get(..15).ok_or(Error::SecretMemory)?, &[0; 15]);
    assert_eq!(primary.get(16..).ok_or(Error::SecretMemory)?, &[0x91; 16]);
    assert_eq!(
        complemented.get(15..).ok_or(Error::SecretMemory)?,
        &[0x92; 17]
    );
    Ok(())
}

#[test]
fn cached_and_operation_local_imports_preserve_rejection_classification() -> Result<(), Error> {
    for width in [16, 24, 32] {
        let key = [0x37; 32];
        let mut primary = [0x91; 32];
        let mut secondary = [0x92; 32];
        assert!(matches!(
            Cached::new_profile(
                key.get(..width).ok_or(Error::SecretMemory)?,
                primary.get_mut(..width).ok_or(Error::SecretMemory)?,
                secondary.get_mut(..width - 1).ok_or(Error::SecretMemory)?,
            ),
            Err(ProfileFailure::ImportRejected)
        ));
        assert!(
            primary
                .get(..width)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            secondary
                .get(..width - 1)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            primary
                .get(width..)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0x91)
        );
        assert!(
            secondary
                .get(width - 1..)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0x92)
        );

        let mut primary = [0x91; 32];
        let mut secondary = [0x92; 32];
        assert!(matches!(
            ephemeral::Ephemeral::new_profile(
                key.get(..width).ok_or(Error::SecretMemory)?,
                primary.get_mut(..width).ok_or(Error::SecretMemory)?,
                secondary.get_mut(..width - 1).ok_or(Error::SecretMemory)?,
            ),
            Err(ProfileFailure::ImportRejected)
        ));
        assert!(
            primary
                .get(..width)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            secondary
                .get(..width - 1)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            primary
                .get(width..)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0x91)
        );
        assert!(
            secondary
                .get(width - 1..)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0x92)
        );
    }
    Ok(())
}

pub(super) fn answer(text: &str) -> Result<[u8; 16], Error> {
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::SecretMemory);
    }
    let mut output = [0; 16];
    for (byte, pair) in output.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(
            core::str::from_utf8(pair).map_err(|_| Error::SecretMemory)?,
            16,
        )
        .map_err(|_| Error::SecretMemory)?;
    }
    Ok(output)
}

#[test]
fn cached_fips_answers_all_widths_directions_and_reuse() -> Result<(), Error> {
    let input = answer("00112233445566778899aabbccddeeff")?;
    for (width, text) in [
        (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (32, "8ea2b7ca516745bfeafc49904b496089"),
    ] {
        let expected = answer(text)?;
        let mut key = [0; 32];
        for (byte, value) in key.iter_mut().zip(0u8..32) {
            *byte = value;
        }
        let key = key.get(..width).ok_or(Error::SecretMemory)?;
        let mut a = [0x91; 32];
        let mut b = [0x92; 32];
        let mut output = [0x93; 16];
        let secret = {
            let mut owner = Cached::new(
                key,
                a.get_mut(..width).ok_or(Error::SecretMemory)?,
                b.get_mut(..width).ok_or(Error::SecretMemory)?,
            )?;
            for _ in 0..3 {
                owner.encrypt_public(&input, &mut output, PublicCiphertext::acknowledge())?;
                assert_eq!(output, expected);
                let block = owner.secret(&input, &mut output, false)?;
                assert_eq!(block.expose(), &expected);
                drop(block);
                let block = owner.secret(&expected, &mut output, true)?;
                assert_eq!(block.expose(), &input);
                drop(block);
            }
            owner.secret(&expected, &mut output, true)?
        };
        assert_eq!(secret.expose(), &input); // Outlives both retained key borrows.
        drop(secret);
        assert_eq!(output, [0; 16]);
        assert!(
            a.get(..width)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|v| *v == 0)
        );
        assert!(
            b.get(..width)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|v| *v == 0)
        );
        assert!(
            a.get(width..)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|v| *v == 0x91)
        );
        assert!(
            b.get(width..)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|v| *v == 0x92)
        );
    }
    Ok(())
}

#[test]
fn bad_import_widths_clear_both_admitted_borrows() -> Result<(), Error> {
    for width in [0, 1, 15, 17, 23, 25, 31, 33] {
        let key = [0x42; 33];
        let mut a = [0x91; 32];
        let mut b = [0x92; 32];
        assert!(Cached::new(key.get(..width).ok_or(Error::SecretMemory)?, &mut a, &mut b).is_err());
        assert_eq!(a, [0; 32]);
        assert_eq!(b, [0; 32]);
    }
    for width in [16usize, 24, 32] {
        for primary_short in [false, true] {
            let key = [0x42; 32];
            let mut a = [0x91; 32];
            let mut b = [0x92; 32];
            let first = if primary_short {
                width.wrapping_sub(1)
            } else {
                width
            };
            let second = if primary_short {
                width
            } else {
                width.wrapping_sub(1)
            };
            assert!(
                Cached::new(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    a.get_mut(..first).ok_or(Error::SecretMemory)?,
                    b.get_mut(..second).ok_or(Error::SecretMemory)?
                )
                .is_err()
            );
            assert!(
                a.get(..first)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|v| *v == 0)
            );
            assert!(
                b.get(..second)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|v| *v == 0)
            );
        }
    }
    Ok(())
}

#[test]
fn separate_key_borrows_are_complemented_and_schedules_unchanged_on_use() -> Result<(), Error> {
    for width in [16, 24, 32] {
        let key = [0x42; 32];
        let mut a = [0; 32];
        let mut b = [0; 32];
        let mut owner = Cached::new(
            key.get(..width).ok_or(Error::SecretMemory)?,
            a.get_mut(..width).ok_or(Error::SecretMemory)?,
            b.get_mut(..width).ok_or(Error::SecretMemory)?,
        )?;
        assert!(owner.retained.keys.primary.iter().all(|v| *v == 0x42));
        assert!(owner.retained.keys.complemented.iter().all(|v| *v == !0x42));
        let mut output = [0; 16];
        let mut before = Scratch::<240>::new();
        let before = before
            .0
            .get_mut(..owner.retained.primary.as_bytes().len())
            .ok_or(Error::SecretMemory)?;
        before.copy_from_slice(owner.retained.primary.as_bytes());
        owner.encrypt_public(&[0x24; 16], &mut output, PublicCiphertext::acknowledge())?;
        assert_eq!(owner.retained.primary.as_bytes(), before);
        owner.retained.validate()?;
    }
    Ok(())
}
