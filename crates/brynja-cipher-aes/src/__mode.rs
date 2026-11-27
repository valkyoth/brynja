//! Cross-crate implementation bridge for AES-GCM and GMAC, not an access
//! control boundary. Exposes cached forward transforms into clearing storage
//! only. No decryption, public-output operation, or inner owner accessor.
use crate::aes;
pub use aes::{Error, SecretBlock};

macro_rules! forward {
    ($name:ident, $key:literal, $schedule:literal, $implementation:ty,
     [$($life:lifetime),+], [$($arg:ident : $ty:ty),*]) => {
        pub struct $name<$($life),+>($implementation);
        impl<$($life),+> $name<$($life),+> {
            #[inline]
            pub fn new($($arg: $ty,)* key: &[u8; $key], storage: &'s mut [u8; $schedule])
                -> Result<Self, Error> {
                <$implementation>::new($($arg,)* key, storage).map(Self)
            }
            #[inline]
            pub fn encrypt_block<'o>(&self, input: &[u8; 16], out: &'o mut [u8; 16])
                -> Result<SecretBlock<'o>, Error> {
                self.0.encrypt_block(input, out)
            }
        }
    };
}
macro_rules! widths {
    ($module:ident, [$($life:lifetime),+], [$($arg:ident : $ty:ty),*]) => {
        forward!(Aes128ExpandedKey, 16, 176, $module::Aes128ExpandedKey<$($life),+>, [$($life),+], [$($arg:$ty),*]);
        forward!(Aes192ExpandedKey, 24, 208, $module::Aes192ExpandedKey<$($life),+>, [$($life),+], [$($arg:$ty),*]);
        forward!(Aes256ExpandedKey, 32, 240, $module::Aes256ExpandedKey<$($life),+>, [$($life),+], [$($arg:$ty),*]);
    };
}
widths!(aes, ['s], []);

#[cfg(feature = "__mode-execution")]
pub mod execution {
    use crate::aes::{SecretBlock, execution as hw};
    use hw::{Authority, Error};
    widths!(hw, ['s, 'a], [authority: &'a Authority]);
}
