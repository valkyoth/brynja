#![no_std]

use brynja_mac_kmac::{Kmac128, KmacError, KmacPublicDeclassification, KmacXof256};

pub fn scoped_secret<'out>(
    workspace: &mut brynja_mac_kmac::hardened_in_place::Kmac128Workspace,
    key: &[u8; 16],
    message: &[u8],
    output: &'out mut [u8; 32],
) -> Result<brynja_mac_kmac::KmacSecretOutput<'out>, KmacError> {
    workspace.with(key, b"package-external", |mut state| {
        state.update(message)?;
        state.finalize_secret(output)
    })?
}

pub fn leaf_mac(key: &[u8; 16], message: &[u8], output: &mut [u8; 16]) -> Result<(), KmacError> {
    let mut state = Kmac128::new(key, b"package-external")?;
    state.update(message)?;
    state.finalize_tag(output).map(|_| ())
}

pub fn leaf_prf(key: &[u8; 32], message: &[u8], output: &mut [u8]) -> Result<(), KmacError> {
    let mut state = KmacXof256::new(key, b"package-external")?;
    state.update(message)?;
    state
        .finalize_xof()?
        .squeeze_public(output, KmacPublicDeclassification::acknowledge())
}

pub fn crypto_facade(key: &[u8; 16], output: &mut [u8; 16]) -> Result<(), KmacError> {
    brynja_crypto::kmac128(key, b"facade", b"", output).map(|_| ())
}

pub fn main_facade(key: &[u8; 16], output: &mut [u8; 16]) -> Result<(), KmacError> {
    brynja::crypto::kmac128(key, b"main facade", b"", output).map(|_| ())
}

#[cfg(test)]
mod tests {
    #[test]
    fn scoped_output_outlives_scope_and_clears_on_drop() -> Result<(), super::KmacError> {
        let mut workspace = brynja_mac_kmac::hardened_in_place::Kmac128Workspace::new();
        let mut destination = [0xa5; 32];
        let mut expected = [0; 32];
        let expected =
            brynja_mac_kmac::kmac128(&[0x42; 16], b"message", b"package-external", &mut expected)?;
        let secret =
            super::scoped_secret(&mut workspace, &[0x42; 16], b"message", &mut destination)?;
        assert_eq!(secret.expose(), expected.as_bytes());
        drop(secret);
        assert_eq!(destination, [0; 32]);
        Ok(())
    }
    #[test]
    fn all_three_package_layers_are_operational() {
        let key128 = [0x42; 16];
        let key256 = [0x24; 32];
        let mut leaf = [0; 16];
        let mut facade = [0; 16];
        let mut main = [0; 16];
        let mut prf = [0; 33];
        assert_eq!(super::leaf_mac(&key128, b"message", &mut leaf), Ok(()));
        assert_eq!(super::crypto_facade(&key128, &mut facade), Ok(()));
        assert_eq!(super::main_facade(&key128, &mut main), Ok(()));
        assert_eq!(super::leaf_prf(&key256, b"message", &mut prf), Ok(()));
        assert!(leaf.iter().any(|byte| *byte != 0));
        assert!(facade.iter().any(|byte| *byte != 0));
        assert!(main.iter().any(|byte| *byte != 0));
        assert!(prf.iter().any(|byte| *byte != 0));
    }
}
