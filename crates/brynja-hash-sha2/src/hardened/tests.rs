//! Synthetic private-state injection, never a public state-import API.
//! Valid-boundary controls are framing consistency checks, not claims that a
//! maximum-length message was actually hashed. Ordinary KATs cover real inputs.
use super::*;

fn set32(owner: &mut HardenedSha2Owner, bytes: u64) {
    // The SHA-224/256 counter occupies the first eight bytes of the owner.
    if let Some(destination) = owner.message_length.get_mut(..8) {
        destination.copy_from_slice(&bytes.to_be_bytes());
    }
    assert_eq!(
        owner.set_buffer_len(usize::try_from(bytes % 64).unwrap_or(0)),
        Ok(())
    );
}

fn set64(owner: &mut HardenedSha2Owner, bytes: u128) {
    owner.message_length = bytes.to_be_bytes();
    assert_eq!(
        owner.set_buffer_len(usize::try_from(bytes % 128).unwrap_or(0)),
        Ok(())
    );
}

macro_rules! finalization_case {
    ($test:ident, $state:ident, $word:ty, $set:ident, $width:literal) => {
        #[test]
        fn $test() -> Result<(), HardenedSha2Error> {
            let make = |bytes| {
                let mut state = $state::new();
                $set(&mut state.owner, bytes);
                assert_eq!(state.message_bytes(), bytes);
                state
            };
            let max_bytes = <$word>::MAX / 8;
            for bytes in [max_bytes + 1, <$word>::MAX] {
                // Exact and invalid widths: preserve public size-error
                // precedence; secret arithmetic rejection always clears.
                for width in [0, $width - 1, $width, $width + 1] {
                    let mut public = [0xa5; 66];
                    let output = public
                        .get_mut(1..1 + width)
                        .ok_or(HardenedSha2Error::OutputLength)?;
                    let expected = if width == $width {
                        HardenedSha2Error::MessageTooLong
                    } else {
                        HardenedSha2Error::OutputLength
                    };
                    assert_eq!(
                        make(bytes).finalize_public(output, PublicDeclassification::acknowledge()),
                        Err(expected)
                    );
                    assert_eq!(public, [0xa5; 66]);
                    let mut secret = [0xa5; 66];
                    let output = secret
                        .get_mut(1..1 + width)
                        .ok_or(HardenedSha2Error::OutputLength)?;
                    assert!(matches!(
                        make(bytes).finalize_secret(output),
                        Err(HardenedSha2Error::MessageTooLong)
                    ));
                    assert!(output.iter().all(|byte| *byte == 0));
                    assert_eq!(secret.first(), Some(&0xa5));
                    assert!(
                        secret
                            .get(1 + width..)
                            .is_some_and(|s| s.iter().all(|b| *b == 0xa5))
                    );
                }
            }
            // Largest accepted byte count and its neighbor still finalize.
            // Compare with the existing independently checked bit-tail route.
            for bytes in [0, max_bytes - 1, max_bytes] {
                let mut public = [0xa5; $width];
                let mut bit_public = [0x5a; $width];
                make(bytes).finalize_public(&mut public, PublicDeclassification::acknowledge())?;
                make(bytes).finalize_bits_public(
                    BitString::new(&[], 0).map_err(|_| HardenedSha2Error::MessageTooLong)?,
                    &mut bit_public,
                    PublicDeclassification::acknowledge(),
                )?;
                assert_eq!(public, bit_public);
                let mut storage = [0xa5; $width];
                {
                    let secret = make(bytes).finalize_secret(&mut storage)?;
                    assert_eq!(secret.expose(), public);
                }
                assert_eq!(storage, [0; $width]);
            }
            Ok(())
        }
    };
}

finalization_case!(checked_length_sha224, HardenedSha224, u64, set32, 28);
finalization_case!(checked_length_sha256, HardenedSha256, u64, set32, 32);
finalization_case!(checked_length_sha384, HardenedSha384, u128, set64, 48);
finalization_case!(checked_length_sha512, HardenedSha512, u128, set64, 64);
finalization_case!(
    checked_length_sha512_224,
    HardenedSha512_224,
    u128,
    set64,
    28
);
finalization_case!(
    checked_length_sha512_256,
    HardenedSha512_256,
    u128,
    set64,
    32
);
