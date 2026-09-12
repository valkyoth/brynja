use super::Error;
use brynja_core::clear_owned_region;

pub(super) struct Encoded {
    bytes: [u8; 17],
    length: [u8; 1],
}
impl Encoded {
    pub(super) fn new(value: u128, left: bool) -> Result<Self, Error> {
        let mut width = 1_usize;
        let mut remaining = value;
        while remaining > 255 {
            width = width.checked_add(1).ok_or(Error::State)?;
            remaining >>= 8;
        }
        let mut encoded = Self {
            bytes: [0; 17],
            length: [0],
        };
        encoded.length[0] =
            u8::try_from(width.checked_add(1).ok_or(Error::State)?).map_err(|_| Error::State)?;
        let marker = if left { 0 } else { width };
        *encoded.bytes.get_mut(marker).ok_or(Error::State)? =
            u8::try_from(width).map_err(|_| Error::State)?;
        for index in 0..width {
            let shift = width
                .checked_sub(index)
                .and_then(|v| v.checked_sub(1))
                .and_then(|v| v.checked_mul(8))
                .ok_or(Error::State)?;
            let position = index.checked_add(usize::from(left)).ok_or(Error::State)?;
            *encoded.bytes.get_mut(position).ok_or(Error::State)? =
                u8::try_from((value >> shift) & 255).map_err(|_| Error::State)?;
        }
        Ok(encoded)
    }
    pub(super) fn bytes(&self) -> Result<&[u8], Error> {
        self.bytes
            .get(..usize::from(self.length[0]))
            .ok_or(Error::State)
    }
}
impl Drop for Encoded {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.bytes);
        let _ = clear_owned_region(&mut self.length);
    }
}
