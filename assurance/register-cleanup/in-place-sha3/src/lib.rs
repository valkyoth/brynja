//! Development caller probes: borrowed storage, not a whole-register claim.
#![no_std]
#![forbid(unsafe_code)]

use brynja_hash_sha3::{HardenedSha3Error, hardened_in_place::*};

#[cfg(feature = "execution")]
pub mod execution;

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

macro_rules! xof_probe {
    ($name:ident, $workspace:ident, $kind:ident) => {
        /// Borrows one owner through absorption and reader transfer, then clears output.
        #[inline(never)]
        pub extern "C" fn $name(
            workspace: &mut $workspace,
            input: &[u8; 256],
            output: &mut [u8; 337],
        ) -> u8 {
            let operation = |mut state: $kind<'_>| {
                state.update(input)?;
                let mut reader = state.finalize_xof()?;
                let secret = reader.squeeze_secret(output)?;
                drop(secret);
                Ok::<(), HardenedSha3Error>(())
            };
            u8::from(workspace.with(operation).is_err())
        }
    };
}
xof_probe!(scoped_shake128, Shake128Workspace, Shake128);
xof_probe!(scoped_shake256, Shake256Workspace, Shake256);

macro_rules! cshake_probe {
    ($name:ident, $workspace:ident) => {
        /// Initializes customization only after the workspace is borrowed.
        #[inline(never)]
        pub extern "C" fn $name(
            workspace: &mut $workspace,
            input: &[u8; 256],
            output: &mut [u8; 337],
        ) -> u8 {
            let result = workspace.with(b"", b"custom", |mut state| {
                state.update(input)?;
                let mut reader = state.finalize_xof()?;
                drop(reader.squeeze_secret(output)?);
                Ok::<(), HardenedSha3Error>(())
            });
            u8::from(!matches!(result, Ok(Ok(()))))
        }
    };
}
cshake_probe!(scoped_cshake128, Cshake128Workspace);
cshake_probe!(scoped_cshake256, Cshake256Workspace);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xof_downstream_smoke() -> Result<(), HardenedSha3Error> {
        let input = [0x5a; 256];
        let mut output = [0xa5; 337];
        assert_eq!(
            scoped_shake128(&mut Shake128Workspace::new(), &input, &mut output),
            0
        );
        assert_eq!(output, [0; 337]);
        output.fill(0xa5);
        assert_eq!(
            scoped_shake256(&mut Shake256Workspace::new(), &input, &mut output),
            0
        );
        assert_eq!(output, [0; 337]);
        output.fill(0xa5);
        assert_eq!(
            scoped_cshake128(&mut Cshake128Workspace::new(), &input, &mut output),
            0
        );
        assert_eq!(output, [0; 337]);
        output.fill(0xa5);
        assert_eq!(
            scoped_cshake256(&mut Cshake256Workspace::new(), &input, &mut output),
            0
        );
        assert_eq!(output, [0; 337]);
        // SHAKE128 empty message, first 32 output bytes (FIPS 202 example).
        let mut workspace = Shake128Workspace::new();
        let mut output = [0; 32];
        let secret = workspace.with(|state| state.finalize_xof()?.squeeze_secret(&mut output))?;
        assert_eq!(
            secret.expose(),
            [
                0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05,
                0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac,
                0xfa, 0x66, 0xef, 0x26
            ]
        );
        drop(secret);
        assert_eq!(output, [0; 32]);
        Ok(())
    }
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
