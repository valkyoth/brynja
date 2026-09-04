use brynja_hash_sha3::{Fips202BitString, Fips202Output};

use crate::{
    ParallelHashError, ParallelHashPublicDeclassification, ParallelHashSecretOutput,
    backend::{BackendReader, Strength},
    core_state::{ParallelCore, byte_string},
};

macro_rules! common {
    ($state:ident, $reader:ident, $strength:expr) => {
        impl<'workspace> $state<'workspace> {
            /// Creates a byte-oriented XOF state. Workspace length is `B`.
            pub fn new(
                workspace: &'workspace mut [u8],
                customization: &[u8],
            ) -> Result<Self, ParallelHashError> {
                Self::new_bits(workspace, byte_string(customization)?)
            }

            /// Creates an XOF state with arbitrary-bit customization.
            pub fn new_bits(
                workspace: &'workspace mut [u8],
                customization: Fips202BitString<'_>,
            ) -> Result<Self, ParallelHashError> {
                ParallelCore::new(workspace, $strength, customization).map(|core| Self { core })
            }

            /// Absorbs every complete input byte.
            pub fn update(&mut self, input: &[u8]) -> Result<(), ParallelHashError> {
                self.core.update(input)
            }

            /// Enters XOF output after complete-byte input.
            pub fn finalize_xof(&mut self) -> Result<$reader<'_>, ParallelHashError> {
                self.core.finalize_input(None)?;
                self.core.finish(None, 0).map(|reader| $reader { reader })
            }

            /// Enters XOF output after one canonical arbitrary-bit suffix.
            pub fn finalize_bits_xof(
                &mut self,
                tail: Fips202BitString<'_>,
            ) -> Result<$reader<'_>, ParallelHashError> {
                self.core.finalize_input(Some(tail))?;
                self.core.finish(None, 0).map(|reader| $reader { reader })
            }

            /// Clears the construction and its complete workspace.
            pub fn cancel(&mut self) {
                self.core.cancel();
            }
        }
    };
}

macro_rules! ordinary {
    ($state:ident, $reader:ident, $strength:expr, $label:literal) => {
        #[doc = concat!("Allocation-free streaming ", $label, " state for public input.")]
        pub struct $state<'workspace> {
            core: ParallelCore<'workspace>,
        }
        #[doc = concat!("Incremental public ", $label, " reader.")]
        pub struct $reader<'state> {
            reader: BackendReader<'state>,
        }
        common!($state, $reader, $strength);

        impl $reader<'_> {
            /// Fills one complete public output fragment transactionally.
            pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), ParallelHashError> {
                self.reader
                    .squeeze_public(output)
                    .map_err(ParallelHashError::from)
            }

            /// Consumes the reader after a final arbitrary-bit fragment.
            pub fn squeeze_final_bits(
                self,
                output: Fips202Output<'_>,
            ) -> Result<(), ParallelHashError> {
                self.reader
                    .squeeze_final_public(output)
                    .map_err(ParallelHashError::from)
            }
        }
    };
}

macro_rules! hardened {
    ($state:ident, $reader:ident, $strength:expr, $label:literal) => {
        #[doc = concat!("Allocation-free secret-bearing ", $label, " state.")]
        pub struct $state<'workspace> {
            core: ParallelCore<'workspace>,
        }
        #[doc = concat!("Incremental secret-bearing ", $label, " reader.")]
        pub struct $reader<'state> {
            reader: BackendReader<'state>,
        }
        common!($state, $reader, $strength);

        impl $reader<'_> {
            /// Writes one fragment with typed secret ownership.
            pub fn squeeze_secret<'a>(
                &mut self,
                output: &'a mut [u8],
            ) -> Result<ParallelHashSecretOutput<'a>, ParallelHashError> {
                self.reader
                    .squeeze_secret(output)
                    .map(ParallelHashSecretOutput::new)
                    .map_err(ParallelHashError::from)
            }

            /// Writes one final arbitrary-bit secret fragment.
            pub fn squeeze_final_bits_secret<'a>(
                self,
                output: Fips202Output<'a>,
            ) -> Result<ParallelHashSecretOutput<'a>, ParallelHashError> {
                self.reader
                    .squeeze_final_secret(output)
                    .map(ParallelHashSecretOutput::new)
                    .map_err(ParallelHashError::from)
            }

            /// Explicitly declassifies one complete public fragment.
            pub fn squeeze_public(
                &mut self,
                output: &mut [u8],
                _authority: ParallelHashPublicDeclassification,
            ) -> Result<(), ParallelHashError> {
                self.reader
                    .squeeze_public(output)
                    .map_err(ParallelHashError::from)
            }
        }
    };
}

ordinary!(
    ParallelHashXof128,
    ParallelHashXof128Reader,
    Strength::Bits128,
    "ParallelHashXOF128"
);
ordinary!(
    ParallelHashXof256,
    ParallelHashXof256Reader,
    Strength::Bits256,
    "ParallelHashXOF256"
);
hardened!(
    HardenedParallelHashXof128,
    HardenedParallelHashXof128Reader,
    Strength::Bits128,
    "ParallelHashXOF128"
);
hardened!(
    HardenedParallelHashXof256,
    HardenedParallelHashXof256Reader,
    Strength::Bits256,
    "ParallelHashXOF256"
);
