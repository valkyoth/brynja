//! Dynamic-input instantiations of production HKDF, without test instrumentation.
#![no_std]
#![forbid(unsafe_code)]

macro_rules! operations {
    ($module:ident, $algorithm:ident) => {
        pub mod $module {
            use brynja_crypto::hkdf::{DerivedKey, Error, Prk, $algorithm};

            #[inline(never)]
            pub fn extract<'a>(
                salt: Option<&[u8]>,
                ikm: &[u8],
                output: &'a mut [u8],
            ) -> Result<Prk<'a, $algorithm>, Error> {
                Prk::extract(salt, ikm, output)
            }

            #[inline(never)]
            pub fn expand<'a>(
                prk: &Prk<'_, $algorithm>,
                info: &[u8],
                output: &'a mut [u8],
            ) -> Result<DerivedKey<'a, $algorithm>, Error> {
                prk.expand(info, output)
            }

            #[inline(never)]
            pub fn expand_parts<'a>(
                prk: &Prk<'_, $algorithm>,
                info: &[&[u8]],
                output: &'a mut [u8],
            ) -> Result<DerivedKey<'a, $algorithm>, Error> {
                prk.expand_parts(info, output)
            }

            #[inline(never)]
            pub fn label<'a>(
                prk: &Prk<'_, $algorithm>,
                label: &[u8],
                context: &[u8],
                output: &'a mut [u8],
            ) -> Result<DerivedKey<'a, $algorithm>, Error> {
                prk.expand_label(label, context, output)
            }
        }
    };
}

operations!(sha224, Sha224);
operations!(sha256, Sha256);
operations!(sha384, Sha384);
operations!(sha512, Sha512);
operations!(sha512_224, Sha512_224);
operations!(sha512_256, Sha512_256);
