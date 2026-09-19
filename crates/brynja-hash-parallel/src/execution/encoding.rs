use super::Error;
use brynja_core::clear_owned_region;

pub(super) struct Encoded {
    bytes: [u8; 17],
    length: [u8; 1],
}
impl Encoded {
    pub(super) const fn empty() -> Self {
        Self {
            bytes: [0; 17],
            length: [0],
        }
    }
    pub(super) fn left(&mut self, value: u128) -> Result<(), Error> {
        crate::secret_encoding::write(&mut self.bytes, &mut self.length, value, true)
            .map_err(Error::from)
    }
    pub(super) fn right(&mut self, value: u128) -> Result<(), Error> {
        crate::secret_encoding::write(&mut self.bytes, &mut self.length, value, false)
            .map_err(Error::from)
    }
    pub(super) fn bytes(&self) -> Result<&[u8], Error> {
        crate::secret_encoding::bytes(&self.bytes, &self.length).map_err(Error::from)
    }
}

impl Drop for Encoded {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.bytes);
        let _ = clear_owned_region(&mut self.length);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn execution_encoding_borrows_and_rejects_empty_storage() -> Result<(), Error> {
        let mut encoded = Encoded::empty();
        assert!(encoded.bytes().is_err());
        for value in [0, 1, 255, 256, u64::MAX.into(), u128::MAX] {
            encoded.left(value)?;
            assert_eq!(
                encoded.bytes()?,
                brynja_hash_sha3::left_encode_u128(value).as_bytes()
            );
            encoded.right(value)?;
            assert_eq!(
                encoded.bytes()?,
                brynja_hash_sha3::right_encode_u128(value).as_bytes()
            );
        }
        encoded.left(0)?;
        assert_eq!(&encoded.bytes[2..], &[0; 15]);
        Ok(())
    }
}
