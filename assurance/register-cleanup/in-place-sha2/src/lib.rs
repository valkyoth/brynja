//! Development caller probes: scoped storage, not whole-register qualification.
#![no_std]
#![forbid(unsafe_code)]

use brynja_hash_sha2::{HardenedSha2Error, hardened_in_place::*};

macro_rules! probe {
    ($name:ident, $workspace:ident, $width:literal) => {
        /// Borrows a workspace through secret input and consuming finalization.
        #[inline(never)]
        pub extern "C" fn $name(
            workspace: &mut $workspace,
            input: &[u8; 256],
            output: &mut [u8; $width],
            length: usize,
        ) -> u8 {
            let Some(input) = input.get(..length) else {
                return 2;
            };
            let result = workspace.with(|mut state| {
                state.update(input)?;
                drop(state.finalize_secret(output)?);
                Ok::<(), HardenedSha2Error>(())
            });
            u8::from(result.is_err())
        }
    };
}
probe!(scoped224, Sha224Workspace, 28);
probe!(scoped256, Sha256Workspace, 32);
probe!(scoped384, Sha384Workspace, 48);
probe!(scoped512, Sha512Workspace, 64);
probe!(scoped512_224, Sha512_224Workspace, 28);
probe!(scoped512_256, Sha512_256Workspace, 32);

#[cfg(test)]
mod tests {
    use super::*;
    macro_rules! smoke {
        ($name:ident, $workspace:ident, $width:literal, $probe:ident, $reference:ident) => {
            #[test]
            fn $name() -> Result<(), HardenedSha2Error> {
                let mut workspace = $workspace::default();
                let mut output = [0xa5; $width];
                assert_eq!($probe(&mut workspace, &[0x5a; 256], &mut output, 256), 0);
                assert_eq!(output, [0; $width]);
                let secret = workspace.with(|mut state| {
                    state.update(b"abc")?;
                    state.finalize_secret(&mut output)
                })?;
                assert_eq!(
                    secret.expose(),
                    brynja_hash_sha2::$reference(b"abc")
                        .map_err(|_| HardenedSha2Error::MessageTooLong)?
                        .as_ref()
                );
                drop(secret);
                assert_eq!(output, [0; $width]);
                Ok(())
            }
        };
    }
    smoke!(sha224, Sha224Workspace, 28, scoped224, sha224);
    smoke!(sha256, Sha256Workspace, 32, scoped256, sha256);
    smoke!(sha384, Sha384Workspace, 48, scoped384, sha384);
    smoke!(sha512, Sha512Workspace, 64, scoped512, sha512);
    smoke!(
        sha512_224,
        Sha512_224Workspace,
        28,
        scoped512_224,
        sha512_224
    );
    smoke!(
        sha512_256,
        Sha512_256Workspace,
        32,
        scoped512_256,
        sha512_256
    );

    #[test]
    fn sha256_known_answer() -> Result<(), HardenedSha2Error> {
        let mut workspace = Sha256Workspace::new();
        let mut output = [0; 32];
        let secret = workspace.with(|mut state| {
            state.update(b"abc")?;
            state.finalize_secret(&mut output)
        })?;
        assert_eq!(
            secret.expose(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        drop(secret);
        assert_eq!(output, [0; 32]);
        Ok(())
    }
}
