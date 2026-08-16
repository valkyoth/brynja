macro_rules! error_type {
    ($name:ident, $algorithm:literal) => {
        #[doc = concat!("A closed ", $algorithm, " input failure.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub enum $name {
            /// Accepting the update would reach or exceed 2^64 message bits.
            MessageTooLong,
        }
    };
}

error_type!(Sha224Error, "SHA-224");
error_type!(Sha256Error, "SHA-256");
