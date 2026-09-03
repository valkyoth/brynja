#![no_std]

use brynja_mac_kmac::{Kmac128, KmacError, KmacPublicDeclassification, KmacXof256};

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
