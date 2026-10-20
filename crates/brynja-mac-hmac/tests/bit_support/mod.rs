use brynja_mac_hmac::*;

pub trait BitCase: Algorithm {
    const LOW_BITS: bool;
    fn input(bytes: &[u8], valid: u8) -> Option<Self::FinalInput<'_>>;
}

macro_rules! cases {
    ($input:ident, $low:literal, $($algorithm:ty),*) => {$(
        impl BitCase for $algorithm {
            const LOW_BITS: bool = $low;
            fn input(bytes: &[u8], valid: u8) -> Option<Self::FinalInput<'_>> {
                $input::new(bytes, valid).ok()
            }
        }
    )*};
}

cases!(
    Sha2BitString,
    false,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256
);
cases!(
    Fips202BitString,
    true,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512
);
