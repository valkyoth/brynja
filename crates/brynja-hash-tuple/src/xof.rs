use brynja_hash_sha3::{Fips202BitString, Fips202Output};

use crate::{
    TupleHashError, TupleHashPublicDeclassification, TupleHashSecretOutput,
    backend::BackendReader,
    core_state::{TupleCore, byte_string},
    item::TupleItemWriter,
};

macro_rules! xof_state_common {
    ($state:ident, $reader:ident, $strength:literal) => {
        impl $state {
            /// Creates a byte-oriented state with the supplied customization.
            pub fn new(customization: &[u8]) -> Result<Self, TupleHashError> {
                Self::new_bits(byte_string(customization)?)
            }

            /// Creates a state with canonical arbitrary-bit customization.
            pub fn new_bits(customization: Fips202BitString<'_>) -> Result<Self, TupleHashError> {
                TupleCore::new($strength, customization).map(|core| Self { core })
            }

            /// Returns the number of complete tuple items accepted.
            #[must_use]
            pub fn item_count(&self) -> u128 {
                self.core.item_count()
            }

            /// Appends one complete byte-oriented item.
            pub fn push_item(&mut self, item: &[u8]) -> Result<(), TupleHashError> {
                self.push_item_bits(byte_string(item)?)
            }

            /// Appends one complete canonical arbitrary-bit item.
            pub fn push_item_bits(
                &mut self,
                item: Fips202BitString<'_>,
            ) -> Result<(), TupleHashError> {
                self.core.push_item(item)
            }

            /// Begins one item whose declared bit length must be consumed exactly.
            pub fn begin_item(
                &mut self,
                bit_length: u128,
            ) -> Result<TupleItemWriter<'_>, TupleHashError> {
                self.core.begin_item(bit_length)?;
                Ok(TupleItemWriter::new(&mut self.core, bit_length))
            }

            /// Finalizes the tuple with `right_encode(0)`.
            pub fn finalize_xof(mut self) -> Result<$reader, TupleHashError> {
                self.core.finish(0).map(|reader| $reader { reader })
            }

            /// Consumes and clears this state without output.
            pub fn cancel(self) {}
        }
    };
}

macro_rules! ordinary_xof {
    ($state:ident, $reader:ident, $strength:literal, $label:literal) => {
        #[doc = concat!("Streaming ", $label, " state for public/unkeyed tuples.")]
        pub struct $state {
            core: TupleCore,
        }
        #[doc = concat!("Incremental public ", $label, " reader.")]
        pub struct $reader {
            reader: BackendReader,
        }
        xof_state_common!($state, $reader, $strength);

        impl $reader {
            /// Fills one complete public output fragment transactionally.
            pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), TupleHashError> {
                self.reader
                    .squeeze_public(output)
                    .map_err(TupleHashError::from)
            }

            /// Consumes the reader after a final arbitrary-bit fragment.
            pub fn squeeze_final_bits(
                self,
                output: Fips202Output<'_>,
            ) -> Result<(), TupleHashError> {
                self.reader
                    .squeeze_final_public(output)
                    .map_err(TupleHashError::from)
            }
        }
    };
}

macro_rules! hardened_xof {
    ($state:ident, $reader:ident, $strength:literal, $label:literal) => {
        #[doc = concat!("Secret-bearing streaming ", $label, " state.")]
        pub struct $state {
            core: TupleCore,
        }
        #[doc = concat!("Secret-bearing incremental ", $label, " reader.")]
        pub struct $reader {
            reader: BackendReader,
        }
        xof_state_common!($state, $reader, $strength);

        impl $reader {
            /// Writes one fragment with typed secret ownership.
            pub fn squeeze_secret<'a>(
                &mut self,
                output: &'a mut [u8],
            ) -> Result<TupleHashSecretOutput<'a>, TupleHashError> {
                self.reader
                    .squeeze_secret(output)
                    .map(TupleHashSecretOutput::new)
                    .map_err(TupleHashError::from)
            }

            /// Writes a final arbitrary-bit fragment with typed secret ownership.
            pub fn squeeze_final_bits_secret<'a>(
                self,
                output: Fips202Output<'a>,
            ) -> Result<TupleHashSecretOutput<'a>, TupleHashError> {
                self.reader
                    .squeeze_final_secret(output)
                    .map(TupleHashSecretOutput::new)
                    .map_err(TupleHashError::from)
            }

            /// Explicitly declassifies one complete output fragment.
            pub fn squeeze_public(
                &mut self,
                output: &mut [u8],
                _authority: TupleHashPublicDeclassification,
            ) -> Result<(), TupleHashError> {
                self.reader
                    .squeeze_public(output)
                    .map_err(TupleHashError::from)
            }

            /// Explicitly declassifies one final arbitrary-bit fragment.
            pub fn squeeze_final_bits_public(
                self,
                output: Fips202Output<'_>,
                _authority: TupleHashPublicDeclassification,
            ) -> Result<(), TupleHashError> {
                self.reader
                    .squeeze_final_public(output)
                    .map_err(TupleHashError::from)
            }
        }
    };
}

ordinary_xof!(
    TupleHashXof128,
    TupleHashXof128Reader,
    128,
    "TupleHashXOF128"
);
ordinary_xof!(
    TupleHashXof256,
    TupleHashXof256Reader,
    256,
    "TupleHashXOF256"
);
hardened_xof!(
    HardenedTupleHashXof128,
    HardenedTupleHashXof128Reader,
    128,
    "TupleHashXOF128"
);
hardened_xof!(
    HardenedTupleHashXof256,
    HardenedTupleHashXof256Reader,
    256,
    "TupleHashXOF256"
);
