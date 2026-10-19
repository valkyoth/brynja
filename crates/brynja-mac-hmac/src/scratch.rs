use brynja_core::{clear_owned_region, xor_secret_byte_bits};

use crate::Error;

/// Never return a populated scratch buffer by value or derive Copy/Clone.
pub(crate) struct Scratch<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> Scratch<N> {
    pub(crate) const fn new() -> Self {
        Self([0; N])
    }

    pub(crate) fn prefix(&mut self, size: usize) -> Result<&mut [u8], Error> {
        self.0.get_mut(..size).ok_or(Error::SecretMemory)
    }
}

impl<const N: usize> Drop for Scratch<N> {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}

pub(crate) fn mask_pad(pad: &mut [u8], mask: u8) -> Result<(), Error> {
    for byte in pad {
        // Reuse the existing reference-based secret XOR boundary. No Rust
        // by-value load of a key byte is introduced by HMAC's framing layer.
        xor_secret_byte_bits(byte, &mask, 0, 8, 0).map_err(|_| Error::SecretMemory)?;
    }
    Ok(())
}
