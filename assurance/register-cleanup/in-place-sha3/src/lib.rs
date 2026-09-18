//! Development caller probes: borrowed storage, not a whole-register claim.
#![no_std]
#![forbid(unsafe_code)]

use brynja_hash_sha3::{HardenedSha3Error, hardened_in_place::*};

macro_rules! probe {
    ($name:ident, $workspace:ident, $width:expr) => {
        /// Initializes/finalizes a scoped state in caller-provided storage.
        /// Only the borrowed handle moves; output clears before return.
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
                let digest = state.finalize_secret(output)?;
                drop(digest);
                Ok::<(), HardenedSha3Error>(())
            });
            u8::from(result.is_err())
        }
    };
}

probe!(scoped224, Sha3_224Workspace, 28);
probe!(scoped256, Sha3_256Workspace, 32);
probe!(scoped384, Sha3_384Workspace, 48);
probe!(scoped512, Sha3_512Workspace, 64);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scoped_downstream_smoke() -> Result<(), HardenedSha3Error> {
        let input = [0x5a; 256];
        assert_eq!(
            scoped224(&mut Sha3_224Workspace::new(), &input, &mut [1; 28], 256),
            0
        );
        assert_eq!(
            scoped256(&mut Sha3_256Workspace::new(), &input, &mut [1; 32], 256),
            0
        );
        assert_eq!(
            scoped384(&mut Sha3_384Workspace::new(), &input, &mut [1; 48], 256),
            0
        );
        let mut output = [1; 64];
        assert_eq!(
            scoped512(&mut Sha3_512Workspace::new(), &input, &mut output, 256),
            0
        );
        assert_eq!(output, [0; 64]);
        let mut workspace = Sha3_256Workspace::new();
        let mut bytes = [0; 32];
        let digest = workspace.with(|mut state| {
            state.update(b"abc")?;
            state.finalize_secret(&mut bytes)
        })?;
        assert_eq!(
            digest.expose(),
            &[
                0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3,
                0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45,
                0x11, 0x43, 0x15, 0x32,
            ]
        );
        drop(digest);
        assert_eq!(bytes, [0; 32]);
        Ok(())
    }
}
