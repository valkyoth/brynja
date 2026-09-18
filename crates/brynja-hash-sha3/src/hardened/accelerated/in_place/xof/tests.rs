extern crate std;
use super::super::tests::{authority, public, session};
mod lifecycle;
use super::*;

macro_rules! campaign {
    ($workspace:ident, $reader:ident, $rate:literal, $reference:ident, $n:expr, $s:expr, $owner:ident) => {{
        let mut workspace = $workspace::new(session(&$owner)?)?;
        for length in [0, 1, $rate - 1, $rate, $rate + 1, 2 * $rate + 1] {
            let input = std::vec![0xa6; length];
            for valid in 1..=8 {
                let tail = Fips202BitString::new(&[1], valid).map_err(|_| Error::Terminal)?;
                let mut ordinary = crate::$reference::new_bits($n, $s).map_err(|_| Error::Terminal)?;
                ordinary.update(&input).map_err(|_| Error::Terminal)?;
                let mut ordinary = ordinary.finalize_bits_xof(tail).map_err(|_| Error::Terminal)?;
                let mut expected = [0; 510];
                ordinary.squeeze(&mut expected).map_err(|_| Error::Terminal)?;
                let address = ::core::ptr::from_ref(&workspace.storage.inner.engine);
                let stage = ::core::ptr::from_ref(&workspace.storage.inner.stage);
                workspace.with_bits($n, $s, |mut state| {
                    for part in input.chunks(17) { state.update(&[])?; state.update(part)?; }
                    let mut reader: $reader<'_, '_> = state.finalize_bits_xof(tail)?;
                    assert_eq!(::core::ptr::from_ref(&reader.inner.storage.inner.engine), address);
                    assert_eq!(::core::ptr::from_ref(&reader.inner.storage.inner.stage), stage);
                    let empty = reader.squeeze_secret(&mut [])?; drop(empty);
                    reader.squeeze_public(&mut [], public())?;
                    let mut first = [0xa5; 169];
                    let secret = reader.squeeze_secret(&mut first)?;
                    assert_eq!(secret.expose(), &expected[..169]); drop(secret); assert_eq!(first, [0; 169]);
                    assert!(reader.inner.storage.inner.stage.0.iter().all(|b| *b == 0));
                    let mut second = [0xa5; 168];
                    reader.squeeze_public(&mut second, public())?;
                    assert_eq!(second, expected[169..337]);
                    let mut third = [0xa5; 173]; let mut scratch = [0x9b; 200];
                    reader.squeeze_public_with_scratch(&mut third, &mut scratch, public())?;
                    assert_eq!(third, expected[337..]); assert_eq!(scratch, [0; 200]);
                    Ok::<(), Error>(())
                })??;
                assert!(workspace.storage.cleared_for_test());
                for output_valid in 1..=8 {
                    let mut expected = [0; 169];
                    let mut ordinary = crate::$reference::new_bits($n, $s).map_err(|_| Error::Terminal)?;
                    ordinary.update(&input).map_err(|_| Error::Terminal)?;
                    ordinary.finalize_bits_xof(tail).map_err(|_| Error::Terminal)?.squeeze(&mut expected).map_err(|_| Error::Terminal)?;
                    expected[168] &= 255 >> 8_u8.saturating_sub(output_valid);
                    let mut output = [0xa5; 169];
                    let secret = workspace.with_bits($n, $s, |mut state| {
                        state.update(&input)?; state.finalize_bits_xof(tail)?.squeeze_final_bits_secret(&mut output, output_valid)
                    })??;
                    assert_eq!(secret.expose(), expected); drop(secret); assert_eq!(output, [0; 169]);
                    let mut scratch = [0xa5; 180];
                    workspace.with_bits($n, $s, |mut state| {
                        state.update(&input)?; state.finalize_bits_xof(tail)?.squeeze_final_bits_public(Fips202Output::new(&mut output, output_valid).map_err(|_| Error::OutputLength)?, &mut scratch, public())
                    })??;
                    assert_eq!(output, expected); assert_eq!(scratch, [0; 180]);
                    assert!(workspace.storage.cleared_for_test());
                }
            }
        }
    }};
}

#[test]
fn scoped_execution_cshake_bits_reading_and_storage() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    let empty = Fips202BitString::new(&[], 0).map_err(|_| Error::PrefixEncoding)?;
    let n = Fips202BitString::new(&[5], 3).map_err(|_| Error::PrefixEncoding)?;
    let s = Fips202BitString::new(&[17], 5).map_err(|_| Error::PrefixEncoding)?;
    for (n, s) in [(empty, empty), (empty, s), (n, empty), (n, s)] {
        campaign!(
            Cshake128Workspace,
            Cshake128Reader,
            168,
            Cshake128,
            n,
            s,
            owner
        );
        campaign!(
            Cshake256Workspace,
            Cshake256Reader,
            136,
            Cshake256,
            n,
            s,
            owner
        );
    }
    Ok(())
}

#[test]
fn scoped_execution_shake_matches_portable_and_cshake_empty() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    macro_rules! check {
        ($workspace:ident, $ordinary:ident, $custom:ident) => {{
            let mut workspace = $workspace::new(session(&owner)?)?;
            let mut custom = $custom::new(session(&owner)?)?;
            for valid in 1..=8 {
                let input = Fips202BitString::new(&[1; 169], valid).map_err(|_| Error::Terminal)?;
                let mut expected = [0; 400];
                crate::$ordinary::new()
                    .finalize_bits_xof(input)
                    .map_err(|_| Error::Terminal)?
                    .squeeze(&mut expected)
                    .map_err(|_| Error::Terminal)?;
                let mut output = [0xa5; 400];
                let secret = workspace
                    .with(|state| state.finalize_bits_xof(input)?.squeeze_secret(&mut output))??;
                assert_eq!(secret.expose(), expected);
                drop(secret);
                assert_eq!(output, [0; 400]);
                let secret = custom.with(b"", b"", |state| {
                    state.finalize_bits_xof(input)?.squeeze_secret(&mut output)
                })??;
                assert_eq!(secret.expose(), expected);
                drop(secret);
                assert_eq!(output, [0; 400]);
            }
        }};
    }
    check!(Shake128Workspace, Shake128, Cshake128Workspace);
    check!(Shake256Workspace, Shake256, Cshake256Workspace);
    Ok(())
}
