use crate::Error;

// Fresh zero storage may move; populated scratch is only borrowed, never copied.
pub(crate) struct Scratch<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> Scratch<N> {
    pub(crate) const fn new() -> Self {
        Self([0; N])
    }
    pub(crate) fn prefix(&mut self, length: usize) -> Result<&mut [u8], Error> {
        self.0.get_mut(..length).ok_or(Error::SecretMemory)
    }
}

impl<const N: usize> Drop for Scratch<N> {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(&mut self.0);
    }
}

pub(crate) fn mask(pad: &mut [u8], value: u8) -> Result<(), Error> {
    for byte in pad {
        brynja_core::xor_secret_byte_bits(byte, &value, 0, 8, 0)
            .map_err(|_| Error::SecretMemory)?;
    }
    Ok(())
}
