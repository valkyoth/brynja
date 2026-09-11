macro_rules! common {
    ($name:ident, $wide:literal) => {
        impl<'a> $name<'a> {
            /// Selects a route and absorbs byte-oriented customization.
            pub fn new(mode: super::Mode<'a>, customization: &[u8]) -> Result<Self, super::Error> {
                Self::new_bits(mode, super::bits(customization)?)
            }
            /// Selects a route and absorbs canonical arbitrary-bit customization.
            pub fn new_bits(
                mode: super::Mode<'a>,
                customization: crate::Fips202BitString<'_>,
            ) -> Result<Self, super::Error> {
                Ok(Self {
                    core: super::core_state::Core::new(mode, $wide, customization)?,
                })
            }
            /// Observes the selected route and health; None means portable.
            pub fn report(&self) -> Option<super::Report> {
                self.core.report()
            }
            /// Number of completed items; finalization/cancellation clear it.
            pub fn item_count(&self) -> u128 {
                self.core.item_count()
            }
            /// Appends one complete byte item. Errors close and clear this owner.
            pub fn push_item(&mut self, item: &[u8]) -> Result<(), super::Error> {
                match super::bits(item) {
                    Ok(bits) => self.push_item_bits(bits),
                    Err(error) => {
                        self.core.cancel();
                        Err(error)
                    }
                }
            }
            /// Appends one complete canonical arbitrary-bit item.
            pub fn push_item_bits(
                &mut self,
                item: crate::Fips202BitString<'_>,
            ) -> Result<(), super::Error> {
                let length = match u128::try_from(item.bit_len()) {
                    Ok(length) => length,
                    Err(_) => {
                        self.core.cancel();
                        return Err(super::Error::MessageTooLong);
                    }
                };
                self.core.begin(length)?;
                self.core.fragment(item)?;
                self.core.complete()
            }
            /// Borrows an affine writer for exactly the declared number of bits.
            /// Dropping or forgetting an unfinished writer cannot reopen the parent.
            pub fn begin_item(
                &mut self,
                bits: u128,
            ) -> Result<super::TupleItemWriter<'_, 'a>, super::Error> {
                self.core.begin(bits)?;
                Ok(super::TupleItemWriter::new(&mut self.core))
            }
            /// Irreversibly erases the source without output.
            pub fn cancel(&mut self) {
                self.core.cancel();
            }
        }
    };
}
pub(super) use common;
