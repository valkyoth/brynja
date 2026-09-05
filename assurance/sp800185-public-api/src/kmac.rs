use brynja_hash_sha3::Fips202BitString;
use brynja_mac_kmac::{
    Kmac128, Kmac256, KmacPublicDeclassification, KmacXof128, KmacXof256, kmac128, kmac256,
    kmacxof128_public, kmacxof256_public,
};

use crate::{AcceptanceError, hex_eq, sequence, vectors};

pub(crate) fn run() -> Result<(), AcceptanceError> {
    official_examples()?;
    streaming_bits_and_conformance()?;
    hardened_outputs()?;
    Ok(())
}

fn official_examples() -> Result<(), AcceptanceError> {
    let key = sequence::<32>(0x40);
    let message = sequence::<4>(0x00);
    let mut fixed128 = [0_u8; 32];
    let mut fixed256 = [0_u8; 64];
    let mut xof128 = [0_u8; 32];
    let mut xof256 = [0_u8; 64];
    let _tag128 =
        kmac128(&key, &message, b"", &mut fixed128).map_err(|_| AcceptanceError::Kmac)?;
    let _tag256 = kmac256(&key, &message, b"My Tagged Application", &mut fixed256)
        .map_err(|_| AcceptanceError::Kmac)?;
    kmacxof128_public(
        &key,
        &message,
        b"",
        &mut xof128,
        KmacPublicDeclassification::acknowledge(),
    )
    .map_err(|_| AcceptanceError::Kmac)?;
    kmacxof256_public(
        &key,
        &message,
        b"My Tagged Application",
        &mut xof256,
        KmacPublicDeclassification::acknowledge(),
    )
    .map_err(|_| AcceptanceError::Kmac)?;
    if !hex_eq(&fixed128, vectors::KMAC128)
        || !hex_eq(&fixed256, vectors::KMAC256)
        || !hex_eq(&xof128, vectors::KMACXOF128)
        || !hex_eq(&xof256, vectors::KMACXOF256)
    {
        return Err(AcceptanceError::Kmac);
    }
    Ok(())
}

fn streaming_bits_and_conformance() -> Result<(), AcceptanceError> {
    let key = sequence::<32>(0x40);
    let message = sequence::<4>(0x00);
    let mut reader128 = KmacXof128::new(&key, b"")
        .map_err(|_| AcceptanceError::Kmac)?;
    reader128.update(&message[..1]).map_err(|_| AcceptanceError::Kmac)?;
    reader128.update(&message[1..]).map_err(|_| AcceptanceError::Kmac)?;
    let mut reader128 = reader128.finalize_xof().map_err(|_| AcceptanceError::Kmac)?;
    let mut output128 = [0_u8; 32];
    let (first, second) = output128.split_at_mut(7);
    reader128
        .squeeze_public(first, KmacPublicDeclassification::acknowledge())
        .and_then(|()| {
            reader128.squeeze_public(second, KmacPublicDeclassification::acknowledge())
        })
        .map_err(|_| AcceptanceError::Kmac)?;
    if !hex_eq(&output128, vectors::KMACXOF128) {
        return Err(AcceptanceError::Kmac);
    }

    let bits = Fips202BitString::new(&[0x05], 3).map_err(|_| AcceptanceError::Kmac)?;
    let custom = Fips202BitString::new(&[], 0).map_err(|_| AcceptanceError::Kmac)?;
    let key_bits = Fips202BitString::new(&key, 8).map_err(|_| AcceptanceError::Kmac)?;
    let mut output = [0_u8; 33];
    let _bit_tag = Kmac256::new_bits(key_bits, custom)
        .map_err(|_| AcceptanceError::Kmac)?
        .finalize_tag_bits(bits, &mut output, 5)
        .map_err(|_| AcceptanceError::Kmac)?;
    if output[32] & 0xe0 != 0 {
        return Err(AcceptanceError::Kmac);
    }

    if Kmac128::new(b"", b"").is_ok() || KmacXof256::new(b"", b"").is_ok() {
        return Err(AcceptanceError::Kmac);
    }
    let mut conformance = Kmac128::new_conformance(b"", b"")
        .map_err(|_| AcceptanceError::Kmac)?;
    conformance.update(b"").map_err(|_| AcceptanceError::Kmac)?;
    let mut one_byte = [0_u8; 1];
    let _conformance_tag = conformance
        .finalize_tag_conformance(&mut one_byte)
        .map_err(|_| AcceptanceError::Kmac)?;
    Ok(())
}

fn hardened_outputs() -> Result<(), AcceptanceError> {
    let key128 = [0x42_u8; 16];
    let key256 = [0x24_u8; 32];
    // Public fixture keys/messages: declassification is only for this oracle.
    let mut expected_fixed128 = [0_u8; 32];
    let mut expected_fixed256 = [0_u8; 64];
    let mut expected_xof128 = [0_u8; 37];
    let mut expected_xof256 = [0_u8; 73];
    let _expected_tag128 = kmac128(&key128, b"message", b"secret", &mut expected_fixed128)
        .map_err(|_| AcceptanceError::Kmac)?;
    let _expected_tag256 = kmac256(&key256, b"message", b"secret", &mut expected_fixed256)
        .map_err(|_| AcceptanceError::Kmac)?;
    kmacxof128_public(
        &key128, b"", b"secret", &mut expected_xof128,
        KmacPublicDeclassification::acknowledge(),
    ).map_err(|_| AcceptanceError::Kmac)?;
    kmacxof256_public(
        &key256, b"", b"secret", &mut expected_xof256,
        KmacPublicDeclassification::acknowledge(),
    ).map_err(|_| AcceptanceError::Kmac)?;
    let mut fixed128 = [0xa5_u8; 32];
    let mut fixed256 = [0xa5_u8; 64];
    let mut xof128 = [0xa5_u8; 37];
    let mut xof256 = [0xa5_u8; 73];
    {
        let mut state = Kmac128::new(&key128, b"secret").map_err(|_| AcceptanceError::Kmac)?;
        state.update(b"message").map_err(|_| AcceptanceError::Kmac)?;
        let secret = state
            .finalize_secret(&mut fixed128)
            .map_err(|_| AcceptanceError::Kmac)?;
        if secret.expose() != expected_fixed128 {
            return Err(AcceptanceError::Kmac);
        }
    }
    {
        let mut state = Kmac256::new(&key256, b"secret").map_err(|_| AcceptanceError::Kmac)?;
        state.update(b"message").map_err(|_| AcceptanceError::Kmac)?;
        let secret = state
            .finalize_secret(&mut fixed256)
            .map_err(|_| AcceptanceError::Kmac)?;
        if secret.expose() != expected_fixed256 {
            return Err(AcceptanceError::Kmac);
        }
    }
    {
        let state = KmacXof128::new(&key128, b"secret").map_err(|_| AcceptanceError::Kmac)?;
        let mut reader = state.finalize_xof().map_err(|_| AcceptanceError::Kmac)?;
        let secret = reader
            .squeeze_secret(&mut xof128)
            .map_err(|_| AcceptanceError::Kmac)?;
        if secret.expose() != expected_xof128 {
            return Err(AcceptanceError::Kmac);
        }
    }
    {
        let state = KmacXof256::new(&key256, b"secret").map_err(|_| AcceptanceError::Kmac)?;
        let mut reader = state.finalize_xof().map_err(|_| AcceptanceError::Kmac)?;
        let secret = reader
            .squeeze_secret(&mut xof256)
            .map_err(|_| AcceptanceError::Kmac)?;
        if secret.expose() != expected_xof256 {
            return Err(AcceptanceError::Kmac);
        }
    }
    if fixed128 != [0; 32] || fixed256 != [0; 64] || xof128 != [0; 37] || xof256 != [0; 73] {
        return Err(AcceptanceError::Kmac);
    }
    Ok(())
}
