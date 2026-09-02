use brynja_hash_sha2 as leaf;

use crate::AcceptanceError;

macro_rules! check_identity {
    ($state:ty, $ordinary:expr, $width:expr) => {{
        let expected = $ordinary.map_err(|_| AcceptanceError::HardenedMismatch)?;
        let mut public = [0_u8; $width];
        let mut public_state = <$state>::new();
        public_state
            .update(b"secret-bearing acceptance")
            .map_err(|_| AcceptanceError::HardenedMismatch)?;
        public_state
            .finalize_public(
                &mut public,
                leaf::PublicDeclassification::acknowledge(),
            )
            .map_err(|_| AcceptanceError::HardenedMismatch)?;
        if public.as_slice() != expected.as_bytes() {
            return Err(AcceptanceError::HardenedMismatch);
        }

        let mut secret = [0xa5_u8; $width];
        let mut secret_state = <$state>::new();
        secret_state
            .update(b"secret-bearing acceptance")
            .map_err(|_| AcceptanceError::HardenedMismatch)?;
        let owner = secret_state
            .finalize_secret(&mut secret)
            .map_err(|_| AcceptanceError::HardenedMismatch)?;
        if owner.expose() != expected.as_bytes() {
            return Err(AcceptanceError::HardenedMismatch);
        }
        drop(owner);
        if secret.iter().any(|byte| *byte != 0) {
            return Err(AcceptanceError::HardenedMismatch);
        }
    }};
}

pub(crate) fn check() -> Result<usize, AcceptanceError> {
    let input = b"secret-bearing acceptance";
    check_identity!(leaf::HardenedSha224, leaf::sha224(input), 28);
    check_identity!(leaf::HardenedSha256, leaf::sha256(input), 32);
    check_identity!(leaf::HardenedSha384, leaf::sha384(input), 48);
    check_identity!(leaf::HardenedSha512, leaf::sha512(input), 64);
    check_identity!(leaf::HardenedSha512_224, leaf::sha512_224(input), 28);
    check_identity!(leaf::HardenedSha512_256, leaf::sha512_256(input), 32);
    Ok(12)
}
