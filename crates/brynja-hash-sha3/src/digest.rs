macro_rules! digest_type {
    ($name:ident, $length:expr, $algorithm:literal, $bits:literal) => {
        #[doc = concat!("One complete ", $bits, "-bit ", $algorithm, " digest.")]
        ///
        /// A digest is public, non-secret output. Equality is ordinary value
        /// equality; it is not a MAC verification or authentication operation.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[repr(transparent)]
        pub struct $name([u8; Self::LENGTH]);

        impl $name {
            #[doc = concat!($algorithm, " digest size in bytes.")]
            pub const LENGTH: usize = $length;

            /// Creates a digest value from exact bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
                Self(bytes)
            }

            /// Borrows the exact digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
                &self.0
            }

            /// Returns the exact digest bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
                self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

digest_type!(Sha3_224Digest, 28, "SHA3-224", "224");
digest_type!(Sha3_256Digest, 32, "SHA3-256", "256");
digest_type!(Sha3_384Digest, 48, "SHA3-384", "384");
digest_type!(Sha3_512Digest, 64, "SHA3-512", "512");
