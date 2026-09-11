use super::{
    Error,
    common::common,
    core_state::Core,
    output::{self, Stage},
};
use crate::{TupleHashPublicDeclassification, TupleHashSecretOutput};

macro_rules! ordinary {
    ($name:ident, $wide:literal) => {
        /// Public/unkeyed TupleHash. Fixed finalization consumes this owner.
        pub struct $name<'a> {
            core: Core<'a>,
        }
        common!($name, $wide);
        impl $name<'_> {
            /// Produces at most 168 public bytes transactionally.
            pub fn finalize(mut self, bytes: &mut [u8]) -> Result<(), Error> {
                let mut scratch = Stage([0; 168]);
                output::fixed_public(
                    &mut self.core,
                    bytes,
                    output::valid(bytes.len()),
                    &mut scratch.0,
                )
            }
            /// Arbitrary-length public output; the entire scratch is erased.
            pub fn finalize_with_scratch(
                mut self,
                bytes: &mut [u8],
                scratch: &mut [u8],
            ) -> Result<(), Error> {
                output::fixed_public(&mut self.core, bytes, output::valid(bytes.len()), scratch)
            }
            /// Canonical final output bits. Invalid widths preserve output and erase scratch.
            pub fn finalize_bits(
                mut self,
                bytes: &mut [u8],
                valid: u8,
                scratch: &mut [u8],
            ) -> Result<(), Error> {
                output::fixed_public(&mut self.core, bytes, valid, scratch)
            }
        }
    };
}
macro_rules! hardened {
    ($name:ident, $wide:literal) => {
        /// Secret-bearing TupleHash. Fixed finalization consumes this erasing owner.
        pub struct $name<'a> {
            core: Core<'a>,
        }
        common!($name, $wide);
        impl $name<'_> {
            /// Transfers typed secret output; every failure clears the destination.
            pub fn finalize_secret(
                mut self,
                bytes: &mut [u8],
            ) -> Result<TupleHashSecretOutput<'_>, Error> {
                output::fixed_secret(&mut self.core, bytes, output::valid(bytes.len()))
            }
            /// Transfers canonical secret output bits, clearing invalid destinations.
            pub fn finalize_secret_bits(
                mut self,
                bytes: &mut [u8],
                valid: u8,
            ) -> Result<TupleHashSecretOutput<'_>, Error> {
                output::fixed_secret(&mut self.core, bytes, valid)
            }
            /// Explicitly declassifies at most 168 bytes transactionally.
            pub fn finalize_public(
                mut self,
                bytes: &mut [u8],
                _authority: TupleHashPublicDeclassification,
            ) -> Result<(), Error> {
                let mut scratch = Stage([0; 168]);
                output::fixed_public(
                    &mut self.core,
                    bytes,
                    output::valid(bytes.len()),
                    &mut scratch.0,
                )
            }
            /// Arbitrary-length declassified output; the entire scratch is erased.
            pub fn finalize_public_with_scratch(
                mut self,
                bytes: &mut [u8],
                scratch: &mut [u8],
                _authority: TupleHashPublicDeclassification,
            ) -> Result<(), Error> {
                output::fixed_public(&mut self.core, bytes, output::valid(bytes.len()), scratch)
            }
            /// Explicitly declassifies canonical output bits transactionally.
            pub fn finalize_public_bits(
                mut self,
                bytes: &mut [u8],
                valid: u8,
                scratch: &mut [u8],
                _authority: TupleHashPublicDeclassification,
            ) -> Result<(), Error> {
                output::fixed_public(&mut self.core, bytes, valid, scratch)
            }
        }
    };
}
ordinary!(TupleHash128, false);
ordinary!(TupleHash256, true);
hardened!(HardenedTupleHash128, false);
hardened!(HardenedTupleHash256, true);
