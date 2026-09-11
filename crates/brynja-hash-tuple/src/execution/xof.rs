use super::{
    Error, Report,
    common::common,
    core_state::Core,
    output::{self, Stage},
};
use crate::{TupleHashPublicDeclassification, TupleHashSecretOutput};

/// Public output reader exclusively borrowing its original tuple owner.
pub struct Reader<'s, 'a> {
    core: &'s mut Core<'a>,
}
/// Secret-bearing output reader exclusively borrowing its original tuple owner.
pub struct HardenedReader<'s, 'a> {
    core: &'s mut Core<'a>,
}
macro_rules! reader_common {
    ($name:ident) => {
        impl $name<'_, '_> {
            /// Non-authorizing route/health observation.
            pub fn report(&self) -> Option<Report> {
                self.core.report()
            }
            /// Emitted output bits before terminal cancellation clears counters.
            pub fn output_bits(&self) -> u128 {
                self.core.output_bits()
            }
            /// Clears the exact borrowed source without further output.
            pub fn cancel(self) {}
        }
        impl Drop for $name<'_, '_> {
            fn drop(&mut self) {
                self.core.cancel();
            }
        }
    };
}
reader_common!(Reader);
reader_common!(HardenedReader);
impl Reader<'_, '_> {
    /// Emits at most 168 public bytes transactionally; failures close the source.
    pub fn squeeze(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        let mut scratch = Stage([0; 168]);
        self.squeeze_with_scratch(bytes, &mut scratch.0)
    }
    /// Emits arbitrary-length output using completely erased caller scratch.
    pub fn squeeze_with_scratch(
        &mut self,
        bytes: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        self.core
            .public(bytes, output::valid(bytes.len()), scratch, false)
    }
    /// Consumes the reader after canonical final public bits; errors preserve output.
    pub fn squeeze_final_bits(
        self,
        bytes: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        self.core.public(bytes, valid, scratch, true)
    }
}
impl HardenedReader<'_, '_> {
    /// Emits typed secret bytes; failures clear the entire destination.
    pub fn squeeze_secret<'out>(
        &mut self,
        bytes: &'out mut [u8],
    ) -> Result<TupleHashSecretOutput<'out>, Error> {
        self.core.secret(bytes, output::valid(bytes.len()), false)
    }
    /// Consumes the reader after canonical secret bits; invalid widths clear output.
    pub fn squeeze_final_bits_secret(
        self,
        bytes: &mut [u8],
        valid: u8,
    ) -> Result<TupleHashSecretOutput<'_>, Error> {
        self.core.secret(bytes, valid, true)
    }
    /// Explicitly declassifies at most 168 bytes transactionally.
    pub fn squeeze_public(
        &mut self,
        bytes: &mut [u8],
        authority: TupleHashPublicDeclassification,
    ) -> Result<(), Error> {
        let mut scratch = Stage([0; 168]);
        self.squeeze_public_with_scratch(bytes, &mut scratch.0, authority)
    }
    /// Explicitly declassifies arbitrary-length output with completely erased scratch.
    pub fn squeeze_public_with_scratch(
        &mut self,
        bytes: &mut [u8],
        scratch: &mut [u8],
        _authority: TupleHashPublicDeclassification,
    ) -> Result<(), Error> {
        self.core
            .public(bytes, output::valid(bytes.len()), scratch, false)
    }
    /// Consumes the reader after canonical declassified output bits.
    pub fn squeeze_final_bits_public(
        self,
        bytes: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        _authority: TupleHashPublicDeclassification,
    ) -> Result<(), Error> {
        self.core.public(bytes, valid, scratch, true)
    }
}
macro_rules! xof {
    ($name:ident, $reader:ident, $wide:literal, $label:literal) => {
        #[doc = $label]
        pub struct $name<'a> {
            core: Core<'a>,
        }
        common!($name, $wide);
        impl<'a> $name<'a> {
            /// Writes right_encode(0) and exclusively borrows the exact source.
            /// A forgotten reader cannot reopen absorption or finalization.
            pub fn finalize_xof(&mut self) -> Result<$reader<'_, 'a>, Error> {
                self.core.finish(0)?;
                Ok($reader {
                    core: &mut self.core,
                })
            }
        }
    };
}
xof!(
    TupleHashXof128,
    Reader,
    false,
    "Public/unkeyed TupleHashXOF128 owner."
);
xof!(
    TupleHashXof256,
    Reader,
    true,
    "Public/unkeyed TupleHashXOF256 owner."
);
xof!(
    HardenedTupleHashXof128,
    HardenedReader,
    false,
    "Secret-bearing TupleHashXOF128 owner."
);
xof!(
    HardenedTupleHashXof256,
    HardenedReader,
    true,
    "Secret-bearing TupleHashXOF256 owner."
);
