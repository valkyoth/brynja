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
error_type!(Sha3_384Error, "SHA3-384");
error_type!(Sha3_512Error, "SHA3-512");

macro_rules! xof_error_type {
    ($name:ident, $algorithm:literal) => {
        #[doc = concat!("A closed ", $algorithm, " input or output failure.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub enum $name {
            /// The implementation's exact input byte counter would overflow.
            MessageTooLong,
            /// The implementation's exact output byte counter would overflow.
            OutputTooLong,
        }
    };
}

xof_error_type!(Shake128Error, "SHAKE128");
xof_error_type!(Shake256Error, "SHAKE256");
