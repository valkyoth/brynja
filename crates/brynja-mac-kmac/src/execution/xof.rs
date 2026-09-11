use super::{
    Error, Mode, Report,
    core_state::Core,
    output::{self, Stage},
};
use crate::{
    Fips202BitString, KmacKeyPolicy, KmacPublicDeclassification, KmacSecretOutput,
    KmacServiceStatus,
};

/// Exclusive reader borrowing the exact inline keyed state. Drop cancels it.
pub struct Reader<'s, 'a> {
    core: &'s mut Core<'a>,
}
impl Reader<'_, '_> {
    /// Public route/health observation; no key or secret state is exposed.
    pub fn report(&self) -> Option<Report> {
        self.core.report()
    }
    /// Total emitted output bits (before terminal cancellation clears counters).
    pub fn output_bits(&self) -> u128 {
        self.core.output_bits()
    }
    /// Complete bytes emitted through the reader.
    pub fn output_bytes(&self) -> u128 {
        self.output_bits() / 8
    }
    /// Every service remains non-approved regardless of selected instructions.
    pub const fn service_status(&self) -> KmacServiceStatus {
        KmacServiceStatus::NonApproved
    }
    /// Declassifies at most 168 bytes transactionally; errors terminate the owner.
    pub fn squeeze_public(
        &mut self,
        output: &mut [u8],
        authority: KmacPublicDeclassification,
    ) -> Result<(), Error> {
        let mut scratch = Stage([0; 168]);
        self.squeeze_public_with_scratch(output, &mut scratch.0, authority)
    }
    /// Arbitrary-length transactional output using completely erased scratch.
    pub fn squeeze_public_with_scratch(
        &mut self,
        output: &mut [u8],
        scratch: &mut [u8],
        _authority: KmacPublicDeclassification,
    ) -> Result<(), Error> {
        self.core
            .public(output, output::valid(output.len()), scratch, false)
    }
    /// Transfers typed secret ownership; errors clear every destination byte.
    pub fn squeeze_secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<KmacSecretOutput<'out>, Error> {
        self.core.secret(output, output::valid(output.len()), false)
    }
    /// Consumes the reader after canonical final public output bits.
    pub fn squeeze_final_bits_public(
        self,
        bytes: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        _authority: KmacPublicDeclassification,
    ) -> Result<(), Error> {
        self.core.public(bytes, valid, scratch, true)
    }
    /// Consumes the reader after canonical final typed-secret output bits.
    pub fn squeeze_final_bits_secret<'out>(
        self,
        bytes: &'out mut [u8],
        valid: u8,
    ) -> Result<KmacSecretOutput<'out>, Error> {
        self.core.secret(bytes, valid, true)
    }
    /// Consumes the reader and clears the borrowed keyed state.
    pub fn cancel(self) {}
}
impl Drop for Reader<'_, '_> {
    fn drop(&mut self) {
        self.core.cancel();
    }
}

macro_rules! xof {
    ($name:ident, $wide:literal) => {
        /// Thread-bound KMACXOF with an affine in-place reader transition.
        pub struct $name<'a> {
            core: Core<'a>,
        }
        impl<'a> $name<'a> {
            /// Selects a hardened route before full-strength keyed setup.
            pub fn new(mode: Mode<'a>, key: &[u8], customization: &[u8]) -> Result<Self, Error> {
                Self::new_bits(mode, super::bits(key)?, super::bits(customization)?)
            }
            /// Arbitrary-bit full-strength key and customization setup.
            pub fn new_bits(
                mode: Mode<'a>,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, Error> {
                Ok(Self {
                    core: Core::new(mode, $wide, key, customization, false)?,
                })
            }
            /// Exact conformance for short and empty keys; absent by default.
            #[cfg(feature = "conformance-testing")]
            pub fn new_conformance(
                mode: Mode<'a>,
                key: &[u8],
                customization: &[u8],
            ) -> Result<Self, Error> {
                Self::new_bits_conformance(mode, super::bits(key)?, super::bits(customization)?)
            }
            /// Exact arbitrary-bit conformance key/domain setup.
            #[cfg(feature = "conformance-testing")]
            pub fn new_bits_conformance(
                mode: Mode<'a>,
                key: Fips202BitString<'_>,
                customization: Fips202BitString<'_>,
            ) -> Result<Self, Error> {
                Ok(Self {
                    core: Core::new(mode, $wide, key, customization, true)?,
                })
            }
            /// Public route/health only; None means portable.
            pub fn report(&self) -> Option<Report> {
                self.core.report()
            }
            /// Explicit key strength, separate from execution selection.
            pub fn key_policy(&self) -> KmacKeyPolicy {
                self.core.key_policy()
            }
            /// No implementation route is a FIPS-approved service.
            pub const fn service_status(&self) -> KmacServiceStatus {
                KmacServiceStatus::NonApproved
            }
            /// Complete update bytes after keyed initialization.
            pub fn message_bytes(&self) -> u128 {
                self.core.message_bytes()
            }
            /// Absorbs bytes; wrong phase or errors irreversibly clear this owner.
            pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                self.core.update(input)
            }
            /// Borrows this exact source into a single reader; no state is exported.
            pub fn finalize_xof(&mut self) -> Result<Reader<'_, 'a>, Error> {
                self.core.finish(None, 0, true, false)?;
                Ok(Reader {
                    core: &mut self.core,
                })
            }
            /// One canonical arbitrary-bit final message before reader borrowing.
            pub fn finalize_bits_xof(
                &mut self,
                message: Fips202BitString<'_>,
            ) -> Result<Reader<'_, 'a>, Error> {
                self.core.finish(Some(message), 0, true, false)?;
                Ok(Reader {
                    core: &mut self.core,
                })
            }
            /// Exact-conformance reader transition.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_xof_conformance(&mut self) -> Result<Reader<'_, 'a>, Error> {
                self.core.finish(None, 0, true, true)?;
                Ok(Reader {
                    core: &mut self.core,
                })
            }
            /// Exact-conformance arbitrary-bit reader transition.
            #[cfg(feature = "conformance-testing")]
            pub fn finalize_bits_xof_conformance(
                &mut self,
                message: Fips202BitString<'_>,
            ) -> Result<Reader<'_, 'a>, Error> {
                self.core.finish(Some(message), 0, true, true)?;
                Ok(Reader {
                    core: &mut self.core,
                })
            }
            /// Clears the original source in place, including after a forgotten reader.
            pub fn cancel(&mut self) {
                self.core.cancel();
            }
        }
    };
}
xof!(KmacXof128, false);
xof!(KmacXof256, true);
