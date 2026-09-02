//! Downstream-style `no_std` consumer for every hardened FIPS 202 identity.

#![no_std]

use brynja_hash_sha3::{
    HardenedSha3Error, HardenedSha3_224, HardenedSha3_256, HardenedSha3_384,
    HardenedSha3_512, HardenedShake128, HardenedShake256, Sha3PublicDeclassification,
};

macro_rules! exercise_fixed {
    ($state:ty, $input:expr, $public:expr, $secret:expr) => {{
        let mut public_state = <$state>::new();
        public_state.update($input)?;
        public_state.finalize_public($public, Sha3PublicDeclassification::acknowledge())?;

        let mut secret_state = <$state>::new();
        secret_state.update($input)?;
        let owner = secret_state.finalize_secret($secret)?;
        if owner.expose() != $public {
            return Err(HardenedSha3Error::OutputLength);
        }
        drop(owner);
    }};
}

/// Exercises every fixed state and both incremental readers through public and
/// typed-secret output.
pub fn exercise_all(input: &[u8]) -> Result<(), HardenedSha3Error> {
    let mut public224 = [0_u8; 28];
    let mut public256 = [0_u8; 32];
    let mut public384 = [0_u8; 48];
    let mut public512 = [0_u8; 64];
    let mut secret224 = [0_u8; 28];
    let mut secret256 = [0_u8; 32];
    let mut secret384 = [0_u8; 48];
    let mut secret512 = [0_u8; 64];
    exercise_fixed!(HardenedSha3_224, input, &mut public224, &mut secret224);
    exercise_fixed!(HardenedSha3_256, input, &mut public256, &mut secret256);
    exercise_fixed!(HardenedSha3_384, input, &mut public384, &mut secret384);
    exercise_fixed!(HardenedSha3_512, input, &mut public512, &mut secret512);

    let mut public128 = [0_u8; 193];
    let mut secret128 = [0_u8; 193];
    let mut state128 = HardenedShake128::new();
    state128.update(input)?;
    let mut reader128 = state128.finalize_xof();
    reader128.squeeze_public(&mut public128, Sha3PublicDeclassification::acknowledge())?;
    let mut state128 = HardenedShake128::new();
    state128.update(input)?;
    let output128 = state128.finalize_xof().squeeze_secret(&mut secret128)?;
    if output128.expose() != public128 {
        return Err(HardenedSha3Error::OutputLength);
    }
    drop(output128);

    let mut public256 = [0_u8; 137];
    let mut secret256 = [0_u8; 137];
    let mut state256 = HardenedShake256::new();
    state256.update(input)?;
    let mut reader256 = state256.finalize_xof();
    reader256.squeeze_public(&mut public256, Sha3PublicDeclassification::acknowledge())?;
    let mut state256 = HardenedShake256::new();
    state256.update(input)?;
    let output256 = state256.finalize_xof().squeeze_secret(&mut secret256)?;
    if output256.expose() != public256 {
        return Err(HardenedSha3Error::OutputLength);
    }
    drop(output256);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn downstream_hardened_apis_are_usable() {
        assert_eq!(super::exercise_all(b"secret-derived input"), Ok(()));
    }
}
