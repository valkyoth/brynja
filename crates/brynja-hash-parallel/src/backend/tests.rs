use super::*;
extern crate std;

#[test]
fn scoped_leaf_clears_completed_secret_destination() -> Result<(), HardenedSha3Error> {
    let mut output = [0xa5; 32];
    let input = Fips202BitString::new(&[5], 3).map_err(|_| HardenedSha3Error::MessageTooLong)?;
    let secret = leaf128(input, &mut output)?;
    assert_ne!(secret.expose(), &[0xa5; 32]);
    drop(secret);
    assert_eq!(output, [0; 32]);
    Ok(())
}

#[test]
fn scoped_leaf_matches_shake_for_every_tail_and_rate_boundary() -> Result<(), HardenedSha3Error> {
    let selected = if cfg!(miri) {
        std::env::var("BRYNJA_MIRI_CASE").ok().map(|value| {
            let parsed = value.parse::<usize>();
            assert!(parsed.is_ok());
            parsed.unwrap_or(usize::MAX)
        })
    } else {
        None
    };
    assert!(selected.is_none_or(|case| case < 65));
    let mut visited = 0;
    let mut executed = 0;
    let mut input = [0_u8; 337];
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = u8::try_from(i % 251).map_err(|_| HardenedSha3Error::MessageTooLong)?;
    }
    for width in [0, 1, 135, 136, 137, 167, 168, 169, 337] {
        for valid in if width == 0 { 0..=0 } else { 1..=8 } {
            let index = visited;
            visited += 1;
            if selected.is_some_and(|case| case != index) {
                continue;
            }
            executed += 1;
            // Canonical FIPS bit strings store the valid low bits of the last byte.
            let mut bytes = input;
            if width != 0 && valid < 8 {
                *bytes
                    .get_mut(width - 1)
                    .ok_or(HardenedSha3Error::MessageTooLong)? &= (1_u8 << valid) - 1;
            }
            let bits = Fips202BitString::new(
                bytes
                    .get(..width)
                    .ok_or(HardenedSha3Error::MessageTooLong)?,
                valid,
            )
            .map_err(|_| HardenedSha3Error::MessageTooLong)?;
            macro_rules! check {
                ($leaf:ident, $reference:ident, $n:expr) => {{
                    let mut expected = [0; $n];
                    let reference = brynja_hash_sha3::$reference::new();
                    reference
                        .finalize_bits_xof(bits)
                        .map_err(|_| HardenedSha3Error::MessageTooLong)?
                        .squeeze(&mut expected)
                        .map_err(|_| HardenedSha3Error::MessageTooLong)?;
                    let mut actual = [0xa5; $n];
                    let secret = $leaf(bits, &mut actual)?;
                    assert_eq!(secret.expose(), expected);
                    drop(secret);
                    assert_eq!(actual, [0; $n]);
                }};
            }
            check!(leaf128, Shake128, 32);
            check!(leaf256, Shake256, 64);
        }
    }
    assert_eq!(visited, 65);
    assert_eq!(executed, if selected.is_some() { 1 } else { 65 });
    #[cfg(miri)]
    if let Some(case) = selected {
        std::println!("\nMIRI_CASE_PASS: parallelhash-leaf:{case}");
    }
    Ok(())
}
