macro_rules! error_type {
    ($name:ident, $algorithm:literal) => {
        #[doc = concat!("A closed ", $algorithm, " input failure.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub enum $name {
            /// The implementation's exact byte counter would overflow.
            MessageTooLong,
        }
    };
}

error_type!(Sha3_224Error, "SHA3-224");
error_type!(Sha3_256Error, "SHA3-256");
