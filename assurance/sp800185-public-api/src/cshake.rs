use brynja_hash_sha3::{
    Cshake128, Cshake256, Fips202BitString, Fips202Output, HardenedCshake128,
    HardenedCshake256, cshake128, cshake128_bits, cshake256,
};

use crate::{AcceptanceError, hex_eq, vectors};

pub(crate) fn run() -> Result<(), AcceptanceError> {
    official_examples()?;
    streaming_and_bits()?;
    hardened_profiles()?;
    Ok(())
}

fn official_examples() -> Result<(), AcceptanceError> {
    let input = [0_u8, 1, 2, 3];
    let mut output128 = [0_u8; 32];
    let mut output256 = [0_u8; 64];
    cshake128(&input, b"", b"Email Signature", &mut output128)
        .map_err(|_| AcceptanceError::Cshake)?;
    cshake256(&input, b"", b"Email Signature", &mut output256)
        .map_err(|_| AcceptanceError::Cshake)?;
    if !hex_eq(&output128, vectors::CSHAKE128) || !hex_eq(&output256, vectors::CSHAKE256) {
        return Err(AcceptanceError::Cshake);
    }
    Ok(())
}

fn streaming_and_bits() -> Result<(), AcceptanceError> {
    let message = vectors::REAL_DATA;
    let mut expected128 = [0_u8; 337];
    let mut expected256 = [0_u8; 281];
    cshake128(message, b"Function", b"Context", &mut expected128)
        .map_err(|_| AcceptanceError::Cshake)?;
    cshake256(message, b"Function", b"Context", &mut expected256)
        .map_err(|_| AcceptanceError::Cshake)?;

    let mut state128 = Cshake128::new(b"Function", b"Context")
        .map_err(|_| AcceptanceError::Cshake)?;
    state128
        .update(&message[..7])
        .and_then(|()| state128.update(&message[7..]))
        .map_err(|_| AcceptanceError::Cshake)?;
    let mut reader128 = state128.finalize_xof();
    let mut actual128 = [0_u8; 337];
    let (first, rest) = actual128.split_at_mut(17);
    let (second, third) = rest.split_at_mut(151);
    reader128.squeeze(first).map_err(|_| AcceptanceError::Cshake)?;
    reader128.squeeze(second).map_err(|_| AcceptanceError::Cshake)?;
    reader128.squeeze(third).map_err(|_| AcceptanceError::Cshake)?;

    let mut state256 = Cshake256::new(b"Function", b"Context")
        .map_err(|_| AcceptanceError::Cshake)?;
    state256.update(message).map_err(|_| AcceptanceError::Cshake)?;
    let mut reader256 = state256.finalize_xof();
    let mut actual256 = [0_u8; 281];
    let (first, second) = actual256.split_at_mut(136);
    reader256.squeeze(first).map_err(|_| AcceptanceError::Cshake)?;
    reader256.squeeze(second).map_err(|_| AcceptanceError::Cshake)?;
    if actual128 != expected128 || actual256 != expected256 {
        return Err(AcceptanceError::Cshake);
    }

    let bits = Fips202BitString::new(&[0xa5, 0x03], 2)
        .map_err(|_| AcceptanceError::Cshake)?;
    let name = Fips202BitString::new(&[0x05], 3).map_err(|_| AcceptanceError::Cshake)?;
    let custom = Fips202BitString::new(&[0x02], 2).map_err(|_| AcceptanceError::Cshake)?;
    let mut direct = [0_u8; 34];
    let output = Fips202Output::new(&mut direct, 5).map_err(|_| AcceptanceError::Cshake)?;
    cshake128_bits(bits, name, custom, output).map_err(|_| AcceptanceError::Cshake)?;
    if direct[33] & 0xe0 != 0 {
        return Err(AcceptanceError::Cshake);
    }
    cshake256(b"", b"", b"", &mut []).map_err(|_| AcceptanceError::Cshake)
}

fn hardened_profiles() -> Result<(), AcceptanceError> {
    // These are public test messages, not application secrets. The ordinary
    // APIs are checked against official examples above; check the distinct
    // secret-output paths against the same inputs before checking erasure.
    let mut expected128 = [0_u8; 32];
    let mut expected256 = [0_u8; 67];
    cshake128(b"secret input", b"", b"portable acceptance", &mut expected128)
        .map_err(|_| AcceptanceError::Cshake)?;
    cshake256(b"secret input", b"KDF", b"portable acceptance", &mut expected256)
        .map_err(|_| AcceptanceError::Cshake)?;
    let mut output128 = [0xa5_u8; 32];
    {
        let mut state = HardenedCshake128::new(b"", b"portable acceptance")
            .map_err(|_| AcceptanceError::Cshake)?;
        state.update(b"secret input").map_err(|_| AcceptanceError::Cshake)?;
        let secret = state
            .finalize_secret(&mut output128)
            .map_err(|_| AcceptanceError::Cshake)?;
        if secret.expose() != expected128 {
            return Err(AcceptanceError::Cshake);
        }
    }
    let mut output256 = [0xa5_u8; 67];
    {
        let mut state = HardenedCshake256::new(b"KDF", b"portable acceptance")
            .map_err(|_| AcceptanceError::Cshake)?;
        state.update(b"secret input").map_err(|_| AcceptanceError::Cshake)?;
        let mut reader = state.finalize_xof().map_err(|_| AcceptanceError::Cshake)?;
        let secret = reader
            .squeeze_secret(&mut output256)
            .map_err(|_| AcceptanceError::Cshake)?;
        if secret.expose() != expected256 {
            return Err(AcceptanceError::Cshake);
        }
    }
    if output128 != [0; 32] || output256 != [0; 67] {
        return Err(AcceptanceError::Cshake);
    }
    Ok(())
}
