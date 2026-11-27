use brynja::crypto::aes as facade;
use brynja_cipher_aes::{aes as leaf, provider::ProviderFailureKind};
use brynja_crypto::aes as compat;

struct ShortWrite;

macro_rules! provider {
    ($check:ident, $backend:ident, $owner:ident) => {
        impl leaf::provider::$backend for ShortWrite {
            fn permissions(&self) -> leaf::provider::Permissions {
                leaf::provider::Permissions::Encrypt
            }
            fn encrypt_block(
                &mut self,
                _: &[u8; 16],
                out: &mut [u8; 16],
            ) -> Result<usize, ProviderFailureKind> {
                out[0] = 1;
                Ok(1)
            }
            fn decrypt_block(
                &mut self,
                _: &[u8; 16],
                _: &mut [u8; 16],
            ) -> Result<usize, ProviderFailureKind> {
                unreachable!("binding never permits decryption")
            }
        }
        fn $check() {
            let mut owner: facade::provider::$owner<_> = compat::provider::$owner::new(ShortWrite);
            let mut destination = [0xa5; 16];
            let mut call = || {
                owner.encrypt_block_public(
                    &[0; 16],
                    &mut destination,
                    leaf::PublicCiphertext::acknowledge(),
                )
            };
            assert_eq!(
                call(),
                Err(brynja_crypto::provider::Error::Provider(
                    ProviderFailureKind::InvalidOutput
                ))
            );
            assert_eq!(call(), Err(brynja_cipher_aes::provider::Error::Quarantined));
            assert_eq!(destination, [0xa5; 16]);
        }
    };
}

provider!(bits128, Aes128Backend, Aes128ProviderKey);
provider!(bits192, Aes192Backend, Aes192ProviderKey);
provider!(bits256, Aes256Backend, Aes256ProviderKey);

pub fn check() {
    bits128();
    bits192();
    bits256();
    // Non-native kernel selection must not yield a portable fallback.
    let unavailable = if cfg!(target_arch = "x86_64") {
        leaf::execution::Kernel::ArmAes
    } else {
        leaf::execution::Kernel::X86AesNi
    };
    assert!(facade::execution::Authority::new(unavailable).is_err());
}
