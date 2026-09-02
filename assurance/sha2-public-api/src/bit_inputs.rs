//! Package-external arbitrary-bit checks through leaf and facade APIs.

use brynja::crypto as facade;
use brynja_hash_sha2 as leaf;

use crate::{AcceptanceError, algorithms::matches_hex};

pub(crate) fn check() -> Result<usize, AcceptanceError> {
    check_sha224()?;
    check_sha256()?;
    check_sha384()?;
    check_sha512()?;
    check_sha512_224()?;
    check_sha512_256()?;
    Ok(18)
}

macro_rules! check_algorithm {
    ($check:ident, $function:ident, $state:ident, $message:expr, $expected:literal) => {
        fn $check() -> Result<(), AcceptanceError> {
            let message = $message;
            let complete = leaf::BitString::new(&message, 1)
                .map_err(|_| AcceptanceError::BitInputMismatch)?;
            let direct = leaf::$function(complete)
                .map_err(|_| AcceptanceError::BitInputMismatch)?;
            if !matches_hex(direct.as_bytes(), $expected.as_bytes()) {
                return Err(AcceptanceError::BitInputMismatch);
            }
            if facade::$function(complete)
                .map_err(|_| AcceptanceError::FacadeMismatch)?
                != direct
            {
                return Err(AcceptanceError::FacadeMismatch);
            }
            let mut state = leaf::$state::new();
            state
                .update(&message[..1])
                .map_err(|_| AcceptanceError::BitInputMismatch)?;
            let tail = leaf::BitString::new(&message[1..], 1)
                .map_err(|_| AcceptanceError::BitInputMismatch)?;
            if state
                .finalize_bits(tail)
                .map_err(|_| AcceptanceError::BitInputMismatch)?
                != direct
            {
                return Err(AcceptanceError::BitInputMismatch);
            }
            Ok(())
        }
    };
}

check_algorithm!(
    check_sha224,
    sha224_bits,
    Sha224,
    [0xd7, 0x00],
    "1a09e06ecff27f53f8f58b0ac36bff4acb0596da7dae9804e20487d7"
);
check_algorithm!(
    check_sha256,
    sha256_bits,
    Sha256,
    [0x43, 0x00],
    "b0f025fe6e4ac8fddd6e0fb2bf37b3c5773c9d3311d1aa2ce860d0fbef842f7f"
);
check_algorithm!(
    check_sha384,
    sha384_bits,
    Sha384,
    [0x9e, 0x00],
    "4b177bfba93d477107e249377a6bdb9f0151eff08757e1b4c5fb0f070f6552d691f4ccd9ba5ba36b9bd77424ad90ba35"
);
check_algorithm!(
    check_sha512,
    sha512_bits,
    Sha512,
    [0x9a, 0x80],
    "a6018b4deab5e0178df977b56a25ef75548c9c39a2a8c685f94b030a2d8efbce71a492cdc151a364a11022b0f70d87b83f5639a57a8da2b281282dbbf25acc8d"
);
check_algorithm!(
    check_sha512_224,
    sha512_224_bits,
    Sha512_224,
    [0xba, 0x80],
    "cf0cea456fc101d31ee24dcd9434acecd00a522726b7b6dc83035829"
);
check_algorithm!(
    check_sha512_256,
    sha512_256_bits,
    Sha512_256,
    [0x2c, 0x80],
    "a20a7144d71135218ec42502e2830a64a987d76513f255f5216c1304d722dac6"
);
