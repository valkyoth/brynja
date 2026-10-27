//! Authentication is a successful Result only for an exact, valid tag.
use brynja_mac_kmac::{Fips202BitString, Kmac128, Kmac256, KmacError};

fn bits(bytes: &[u8], last: u8) -> Result<Fips202BitString<'_>, KmacError> {
    Fips202BitString::new(bytes, last).map_err(|_| KmacError::InvalidBitString)
}

macro_rules! portable {
    ($name:ident, $state:ident, $width:literal) => {
        #[test]
        fn $name() -> Result<(), KmacError> {
            let key = [0x42; $width];
            let mut expected = [0; $width];
            let tag = $state::new(&key, b"protocol")?.finalize_tag(&mut expected)?;
            assert_eq!(tag.verify_candidate(tag.as_bytes()), Ok(()));
            assert_eq!(tag.verify_candidate(&[]), Err(KmacError::Mismatch));
            for position in [0, $width / 2, $width - 1] {
                let mut forged = expected;
                *forged
                    .get_mut(position)
                    .ok_or(KmacError::InvalidBitString)? ^= 1;
                let mut authorized = false;
                let result = (|| {
                    $state::new(&key, b"protocol")?.verify(&forged)?;
                    authorized = true;
                    Ok::<(), KmacError>(())
                })();
                assert_eq!(result, Err(KmacError::Mismatch));
                assert!(!authorized);
                assert!(!$state::new(&key, b"protocol")?.verify(&forged).is_ok());
                assert_eq!(
                    $state::new(&key, b"protocol")?.verify_exact(&forged, $width * 8),
                    Err(KmacError::Mismatch)
                );
            }
            assert_eq!($state::new(&key, b"protocol")?.verify(&expected), Ok(()));
            assert_eq!(
                $state::new(&key, b"protocol")?.verify_exact(&expected, $width * 8),
                Ok(())
            );
            for width in [0, $width * 8 - 1, $width * 8 + 1, u128::MAX] {
                assert_eq!(
                    $state::new(&key, b"protocol")?.verify_exact(&expected, width),
                    Err(KmacError::InvalidBitString)
                );
            }
            // An otherwise valid longer tag cannot select a different protocol width.
            let mut longer = [0; $width + 1];
            let _ = $state::new(&key, b"protocol")?.finalize_tag(&mut longer)?;
            assert_eq!($state::new(&key, b"protocol")?.verify(&longer), Ok(()));
            assert_eq!(
                $state::new(&key, b"protocol")?.verify_exact(&longer, $width * 8),
                Err(KmacError::InvalidBitString)
            );
            // Width rejection precedes tag generation, even below the strength minimum.
            assert_eq!(
                $state::new(&key, b"protocol")?.verify_exact(&[0], $width * 8),
                Err(KmacError::InvalidBitString)
            );
            assert_eq!(
                $state::new(&key, b"protocol")?.verify_exact(&[0], 8),
                Err(KmacError::TagTooShort)
            );
            let message = bits(&[5], 3)?;
            for last in 1..=8 {
                let mut tag = [0; $width + 1];
                let _ = $state::new(&key, b"bits")?.finalize_tag_bits(message, &mut tag, last)?;
                let width = ($width * 8) + u128::from(last);
                assert_eq!(
                    $state::new(&key, b"bits")?.verify_bits_exact(
                        message,
                        bits(&tag, last)?,
                        width
                    ),
                    Ok(())
                );
                assert_eq!(
                    $state::new(&key, b"bits")?.verify_bits_exact(
                        message,
                        bits(&tag, last)?,
                        width.checked_add(1).ok_or(KmacError::OutputTooLong)?
                    ),
                    Err(KmacError::InvalidBitString)
                );
                tag[0] ^= 1;
                assert_eq!(
                    $state::new(&key, b"bits")?.verify_bits_exact(
                        message,
                        bits(&tag, last)?,
                        width
                    ),
                    Err(KmacError::Mismatch)
                );
                assert_eq!(
                    $state::new(&key, b"bits")?.verify_bits(message, bits(&tag, last)?),
                    Err(KmacError::Mismatch)
                );
            }
            Ok(())
        }
    };
}
portable!(kmac128_mismatch_and_exact_width, Kmac128, 16);
portable!(kmac256_mismatch_and_exact_width, Kmac256, 32);

#[test]
fn scoped_mismatch_propagates_and_workspace_can_be_reused() -> Result<(), KmacError> {
    macro_rules! check {
        ($workspace:ident, $state:ident) => {{
            let mut workspace = brynja_mac_kmac::hardened_in_place::$workspace::new();
            let key = [7; 32];
            let mut tag = [0; 32];
            let _ = $state::new(&key, b"")?.finalize_tag(&mut tag)?;
            for _ in 0..2 {
                let mut bad = tag;
                bad[31] ^= 1;
                let mut authorized = false;
                assert_eq!(
                    workspace.with(&key, b"", |state| {
                        state.verify(&bad)?;
                        authorized = true;
                        Ok::<(), KmacError>(())
                    })?,
                    Err(KmacError::Mismatch)
                );
                assert!(!authorized);
                assert_eq!(
                    workspace.with(&key, b"", |state| state.verify(&tag))?,
                    Ok(())
                );
            }
        }};
    }
    check!(Kmac128Workspace, Kmac128);
    check!(Kmac256Workspace, Kmac256);
    Ok(())
}

#[cfg(feature = "hardened-execution")]
#[test]
fn selectable_verification_propagates_mismatch() -> Result<(), KmacError> {
    use brynja_mac_kmac::execution as cpu;
    macro_rules! check {
        ($state:ident) => {{
            let key = [7; 32];
            let mut tag = [0; 32];
            let _ = $state::new(&key, b"")?.finalize_tag(&mut tag)?;
            assert_eq!(
                cpu::$state::new(cpu::Mode::Portable, &key, b"")?.verify(&tag),
                Ok(())
            );
            tag[0] ^= 1;
            let mut authorized = false;
            let result = (|| {
                cpu::$state::new(cpu::Mode::Portable, &key, b"")?.verify(&tag)?;
                authorized = true;
                Ok::<(), KmacError>(())
            })();
            assert_eq!(result, Err(KmacError::Mismatch));
            assert!(!authorized);
        }};
    }
    check!(Kmac128);
    check!(Kmac256);
    Ok(())
}
