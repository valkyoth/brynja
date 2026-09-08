use super::*;

fn state(p: Sha512TBits) -> Result<HardenedSha512T, Sha512TError> {
    let mut value = HardenedSha512T::new(p);
    value.update(b"confidential")?;
    Ok(value)
}

fn tail() -> Result<BitString<'static>, Sha512TError> {
    BitString::new(&[0xa0], 3).map_err(|_| Sha512TError::MessageTooLong)
}

#[test]
fn every_parameter_and_destination_width_obeys_secret_ownership() -> Result<(), Sha512TError> {
    for t in 1..512 {
        if t == 384 {
            continue;
        }
        let p = Sha512TBits::new(t)?;
        for length in 0..=65 {
            let mut output = [0xa5; 65];
            let (destination, redzone) = output
                .split_at_mut_checked(length)
                .ok_or(Sha512TError::OutputLength)?;
            if length == p.output_bytes() {
                let secret = state(p)?.finalize_secret(destination)?;
                assert_eq!(secret.parameter(), p);
                assert_eq!(secret.as_bytes(), sha512_t(p, b"confidential")?.as_bytes());
                drop(secret);
            } else {
                assert!(matches!(
                    state(p)?.finalize_secret(destination),
                    Err(Sha512TError::OutputLength)
                ));
            }
            assert!(destination.iter().all(|b| *b == 0));
            assert!(redzone.iter().all(|b| *b == 0xa5));
        }
    }
    Ok(())
}

#[test]
fn dynamic_lifecycle_all_secret_routes_clear_and_preserve_borrowed_inputs()
-> Result<(), Sha512TError> {
    for t in [1, 9, 224, 256, 511] {
        let p = Sha512TBits::new(t)?;
        let input = [0xa0];
        let bits = BitString::new(&input, 3).map_err(|_| Sha512TError::MessageTooLong)?;
        let expected = sha512_t_bits(p, bits)?;
        for route in 0..4 {
            for width in [p.output_bytes(), 0, 65] {
                let mut output = [0xa5; 65];
                let (destination, redzone) = output
                    .split_at_mut_checked(width)
                    .ok_or(Sha512TError::OutputLength)?;
                {
                    let result = match route {
                        0 => state(p)?.finalize_secret(destination),
                        1 => state(p)?.finalize_bits_secret(bits, destination),
                        2 => hardened_sha512_t_secret(p, &input, destination),
                        _ => hardened_sha512_t_bits_secret(p, bits, destination),
                    };
                    if width == p.output_bytes() {
                        let secret = result?;
                        assert_eq!(secret.parameter(), p);
                        if route == 3 {
                            assert_eq!(secret.as_bytes(), expected.as_bytes());
                        }
                        let public = secret.declassify(auth())?;
                        assert_eq!(public.parameter(), p);
                    } else {
                        assert!(matches!(result, Err(Sha512TError::OutputLength)));
                    }
                }
                assert!(destination.iter().all(|b| *b == 0));
                assert!(redzone.iter().all(|b| *b == 0xa5));
                assert_eq!(input, [0xa0]);
            }
        }
        let mut live = state(p)?;
        assert!(live.check_additional_bits(u128::MAX).is_err());
        assert!(live.check_additional_bytes(u128::MAX).is_err());
        live.update(b" data")?;
        assert_eq!(
            live.finalize_public(auth())?,
            sha512_t(p, b"confidential data")?
        );
        state(p)?.cancel();
        drop(state(p)?);
    }
    Ok(())
}

#[test]
fn dynamic_lifecycle_unwind_clears_each_secret_route() -> Result<(), Sha512TError> {
    let p = Sha512TBits::new(9)?;
    for route in 0..4 {
        let mut output = [0xa5; 2];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let secret = match route {
                0 => state(p)?.finalize_secret(&mut output),
                1 => state(p)?.finalize_bits_secret(tail()?, &mut output),
                2 => hardened_sha512_t_secret(p, b"secret", &mut output),
                _ => hardened_sha512_t_bits_secret(p, tail()?, &mut output),
            }?;
            assert_eq!(secret.parameter(), p);
            std::panic::resume_unwind(Box::new(()));
            #[allow(unreachable_code)]
            Ok::<(), Sha512TError>(())
        }));
        assert!(result.is_err());
        assert_eq!(output, [0; 2]);
        // No failing destructor poisons a fresh, independently owned operation.
        let secret = hardened_sha512_t_secret(p, b"next", &mut output)?;
        assert_eq!(secret.as_bytes(), sha512_t(p, b"next")?.as_bytes());
        drop(secret);
        assert_eq!(output, [0; 2]);
    }
    Ok(())
}
