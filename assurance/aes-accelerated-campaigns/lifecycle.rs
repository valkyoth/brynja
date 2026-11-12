//! Package-external lifecycle boundaries, not production inlining annotations.
use brynja_aes_accelerated_fixture::aes::*;

#[inline(never)]
pub fn destroy_block(block: SecretBlock<'_>, explicit: bool) {
    if explicit {
        block.clear();
    } else {
        drop(block);
    }
}

macro_rules! width {
    ($module:ident, $key:ident, $cached:ident, $k:literal, $s:literal) => {
        pub mod $module {
            use super::*;

            #[inline(never)]
            pub fn new_key<'s, 'a>(
                authority: &'a Authority,
                raw: &[u8; $k],
                storage: &'s mut [u8; $k],
            ) -> Result<$key<'s, 'a>, Error> {
                $key::new(authority, raw, storage)
            }

            #[inline(never)]
            pub fn new_cached<'s, 'a>(
                authority: &'a Authority,
                raw: &[u8; $k],
                storage: &'s mut [u8; $s],
            ) -> Result<$cached<'s, 'a>, Error> {
                $cached::new(authority, raw, storage)
            }

            #[inline(never)]
            pub fn destroy_key(key: $key<'_, '_>, explicit: bool) {
                if explicit {
                    key.clear();
                } else {
                    drop(key);
                }
            }

            #[inline(never)]
            pub fn destroy_cached(key: $cached<'_, '_>, explicit: bool) {
                if explicit {
                    key.clear();
                } else {
                    drop(key);
                }
            }
        }
    };
}

width!(aes128, Aes128Key, Aes128ExpandedKey, 16, 176);
width!(aes192, Aes192Key, Aes192ExpandedKey, 24, 208);
width!(aes256, Aes256Key, Aes256ExpandedKey, 32, 240);
