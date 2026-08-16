macro_rules! error_type {
    ($name:ident, $algorithm:literal, $length_bits:literal) => {
        #[doc = concat!("A closed ", $algorithm, " input failure.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub enum $name {
            #[doc = concat!("Accepting the update would reach or exceed 2^", $length_bits, " message bits.")]
            MessageTooLong,
        }
    };
}

error_type!(Sha224Error, "SHA-224", "64");
error_type!(Sha256Error, "SHA-256", "64");
error_type!(Sha384Error, "SHA-384", "128");
error_type!(Sha512Error, "SHA-512", "128");
error_type!(Sha512_224Error, "SHA-512/224", "128");
error_type!(Sha512_256Error, "SHA-512/256", "128");
