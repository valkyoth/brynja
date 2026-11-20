use super::*;
use crate::aes::tests::take_cleared_regions;

#[test]
fn all_widths_directions_reuse_and_per_call_schedule_clearing() -> Result<(), Error> {
    let plain = super::super::tests::answer("00112233445566778899aabbccddeeff")?;
    for (width, text, schedule_bit) in [
        (16, "69c4e0d86a7b0430d8cdb78070b4c55a", 1),
        (24, "dda97ca4864cdfe06eaf70a0ec0d7191", 8),
        (32, "8ea2b7ca516745bfeafc49904b496089", 16),
    ] {
        let cipher = super::super::tests::answer(text)?;
        let mut key = [0; 32];
        for (byte, value) in key.iter_mut().zip(0u8..32) {
            *byte = value;
        }
        let key = key.get(..width).ok_or(Error::SecretMemory)?;
        let mut a = [0x91; 32];
        let mut b = [0x92; 32];
        let mut output = [0x93; 16];
        let block = {
            let mut owner = Ephemeral::new(
                key,
                a.get_mut(..width).ok_or(Error::SecretMemory)?,
                b.get_mut(..width).ok_or(Error::SecretMemory)?,
            )?;
            for _ in 0..3 {
                take_cleared_regions();
                owner.encrypt_public(&plain, &mut output, PublicCiphertext::acknowledge())?;
                assert_eq!(output, cipher);
                assert_ne!(take_cleared_regions() & schedule_bit, 0);
                for (input, expected, inverse) in
                    [(&plain, &cipher, false), (&cipher, &plain, true)]
                {
                    let secret = owner.secret(input, &mut output, inverse)?;
                    // The local primary schedule has already cleared while the
                    // returned block and persistent key owner are still alive.
                    assert_ne!(take_cleared_regions() & schedule_bit, 0);
                    assert_eq!(secret.expose(), expected);
                    drop(secret);
                    assert_eq!(output, [0; 16]);
                }
                assert_eq!(owner.keys.primary, key);
                assert!(
                    owner
                        .keys
                        .complemented
                        .iter()
                        .zip(key)
                        .all(|(a, b)| *a == !*b)
                );
            }
            owner.secret(&cipher, &mut output, true)?
        };
        // Returned secret storage does not borrow the key owner.
        assert_eq!(block.expose(), &plain);
        drop(block);
        assert_eq!(output, [0; 16]);
        for (storage, suffix) in [(&a, 0x91), (&b, 0x92)] {
            assert!(
                storage
                    .get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|v| *v == 0)
            );
            assert!(
                storage
                    .get(width..)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|v| *v == suffix)
            );
        }
    }
    Ok(())
}

#[test]
fn invalid_imports_clear_both_borrows_without_schedule_expansion() -> Result<(), Error> {
    let key = [0x42; 33];
    for width in [0, 1, 15, 17, 23, 25, 31, 33] {
        let mut a = [0x91; 32];
        let mut b = [0x92; 32];
        take_cleared_regions();
        assert!(
            Ephemeral::new(key.get(..width).ok_or(Error::SecretMemory)?, &mut a, &mut b).is_err()
        );
        assert_eq!(a, [0; 32]);
        assert_eq!(b, [0; 32]);
        assert_eq!(take_cleared_regions() & (1 | 8 | 16), 0);
    }
    for width in [16usize, 24, 32] {
        for short_primary in [true, false] {
            let mut a = [0x91; 32];
            let mut b = [0x92; 32];
            let first = if short_primary {
                width.wrapping_sub(1)
            } else {
                width
            };
            let second = if short_primary {
                width
            } else {
                width.wrapping_sub(1)
            };
            assert!(
                Ephemeral::new(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    a.get_mut(..first).ok_or(Error::SecretMemory)?,
                    b.get_mut(..second).ok_or(Error::SecretMemory)?
                )
                .is_err()
            );
            for (storage, admitted, suffix) in [(&a, first, 0x91), (&b, second, 0x92)] {
                assert!(
                    storage
                        .get(..admitted)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|v| *v == 0)
                );
                assert!(
                    storage
                        .get(admitted..)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|v| *v == suffix)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn persistent_key_corruption_retires_both_routes_without_repair() -> Result<(), Error> {
    for width in [16usize, 24, 32] {
        for secondary in [false, true] {
            for position in 0..width {
                let key = [0x42; 32];
                let mut a = [0; 32];
                let mut b = [0; 32];
                let mut owner = Ephemeral::new(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    a.get_mut(..width).ok_or(Error::SecretMemory)?,
                    b.get_mut(..width).ok_or(Error::SecretMemory)?,
                )?;
                let stored = if secondary {
                    &mut owner.keys.complemented
                } else {
                    &mut owner.keys.primary
                };
                *stored.get_mut(position).ok_or(Error::SecretMemory)? ^= 1;
                let mut output = [0x91; 16];
                take_cleared_regions();
                assert!(
                    owner
                        .encrypt_public(&[0x24; 16], &mut output, PublicCiphertext::acknowledge())
                        .is_err()
                );
                assert_eq!(output, [0x91; 16]);
                assert!(owner.secret(&[0x24; 16], &mut output, false).is_err());
                assert_eq!(output, [0; 16]);
                assert_eq!(take_cleared_regions() & (1 | 8 | 16), 0);
                // Even repairing the test bytes cannot revive a retired owner.
                let stored = if secondary {
                    &mut owner.keys.complemented
                } else {
                    &mut owner.keys.primary
                };
                *stored.get_mut(position).ok_or(Error::SecretMemory)? ^= 1;
                owner.keys.validate()?;
                assert!(
                    owner
                        .encrypt_public(&[0x24; 16], &mut output, PublicCiphertext::acknowledge())
                        .is_err()
                );
                assert!(owner.secret(&[0x24; 16], &mut output, true).is_err());
            }
        }
    }
    Ok(())
}
