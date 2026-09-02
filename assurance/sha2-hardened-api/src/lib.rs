//! Downstream-style `no_std` consumer for every hardened SHA-2 identity.

#![no_std]

use brynja_hash_sha2::{
    HardenedSha2Error, HardenedSha224, HardenedSha256, HardenedSha384, HardenedSha512,
    HardenedSha512_224, HardenedSha512_256, PublicDeclassification,
};

macro_rules! exercise {
    ($state:ty, $input:expr, $public:expr, $secret:expr) => {{
        let mut public_state = <$state>::new();
        public_state.update($input)?;
        public_state.finalize_public($public, PublicDeclassification::acknowledge())?;

        let mut secret_state = <$state>::new();
        secret_state.update($input)?;
        let owner = secret_state.finalize_secret($secret)?;
        if owner.expose() != $public {
            return Err(HardenedSha2Error::OutputLength);
        }
        drop(owner);
    }};
}

/// Exercises every hardened state through public and typed-secret output.
pub fn exercise_all(input: &[u8]) -> Result<(), HardenedSha2Error> {
    let mut public224 = [0_u8; 28];
    let mut public256 = [0_u8; 32];
    let mut public384 = [0_u8; 48];
    let mut public512 = [0_u8; 64];
    let mut public512_224 = [0_u8; 28];
    let mut public512_256 = [0_u8; 32];
    let mut secret224 = [0_u8; 28];
    let mut secret256 = [0_u8; 32];
    let mut secret384 = [0_u8; 48];
    let mut secret512 = [0_u8; 64];
    let mut secret512_224 = [0_u8; 28];
    let mut secret512_256 = [0_u8; 32];

    exercise!(HardenedSha224, input, &mut public224, &mut secret224);
    exercise!(HardenedSha256, input, &mut public256, &mut secret256);
    exercise!(HardenedSha384, input, &mut public384, &mut secret384);
    exercise!(HardenedSha512, input, &mut public512, &mut secret512);
    exercise!(HardenedSha512_224, input, &mut public512_224, &mut secret512_224);
    exercise!(HardenedSha512_256, input, &mut public512_256, &mut secret512_256);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn downstream_hardened_apis_are_usable() {
        assert_eq!(super::exercise_all(b"secret-derived input"), Ok(()));
    }
}
