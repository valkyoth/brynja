// Independent bit-plane linear layers. No primary byte-field/layout helpers.
use super::{Error, Planes, Scratch, read};

// Each nibble is one AES column, with its four row bits in order.
fn next_row(plane: u8) -> u8 {
    ((plane >> 1) & 0x77) | ((plane & 0x11) << 3)
}

fn opposite_row(plane: u8) -> u8 {
    ((plane >> 2) & 0x33) | ((plane & 0x33) << 2)
}

impl Planes {
    pub(super) fn xor(&mut self, other: &Self) {
        for (left, right) in self.0.0.iter_mut().zip(&other.0.0) {
            *left ^= right;
        }
    }

    // Multiply all lanes by x, as a fixed XOR network on polynomial bit planes.
    fn double(&mut self) -> Result<(), Error> {
        let mut old = Scratch::<16>::new();
        old.0.copy_from_slice(&self.0.0);
        for (position, plane) in self.0.0.iter_mut().enumerate() {
            let bit = position % 8;
            let base = (position / 8).wrapping_mul(8);
            *plane = if bit == 0 {
                0
            } else {
                read(&old.0, base.wrapping_add(bit.wrapping_sub(1)))?
            };
            if matches!(bit, 0 | 1 | 3 | 4) {
                *plane ^= read(&old.0, base.wrapping_add(7))?;
            }
        }
        Ok(())
    }

    pub(super) fn shift_rows(&mut self, inverse: bool) -> Result<(), Error> {
        let mut shifted = Scratch::<16>::new();
        for destination in 0usize..16 {
            let row = destination % 4;
            let column = destination / 4;
            let source_column = if inverse {
                column.wrapping_add(4).wrapping_sub(row) % 4
            } else {
                column.wrapping_add(row) % 4
            };
            let source = source_column.wrapping_mul(4).wrapping_add(row);
            for bit in 0usize..8 {
                let source_plane = (source / 8).wrapping_mul(8).wrapping_add(bit);
                let destination_plane = (destination / 8).wrapping_mul(8).wrapping_add(bit);
                *shifted
                    .0
                    .get_mut(destination_plane)
                    .ok_or(Error::SecretMemory)? |=
                    ((read(&self.0.0, source_plane)? >> (source % 8)) & 1) << (destination % 8);
            }
        }
        self.0.0.copy_from_slice(&shifted.0);
        Ok(())
    }

    pub(super) fn mix_columns(&mut self, inverse: bool) -> Result<(), Error> {
        let mut adjustment = Self::new();
        if inverse {
            // InvMixColumns = MixColumns after the opposite-row x^2 correction.
            for (out, input) in adjustment.0.0.iter_mut().zip(&self.0.0) {
                *out = input ^ opposite_row(*input);
            }
            adjustment.double()?;
            adjustment.double()?;
            self.xor(&adjustment);
        }
        for (out, input) in adjustment.0.0.iter_mut().zip(&self.0.0) {
            *out = input ^ next_row(*input);
        }
        adjustment.double()?;
        for (plane, correction) in self.0.0.iter_mut().zip(&adjustment.0.0) {
            *plane = next_row(*plane)
                ^ opposite_row(*plane)
                ^ next_row(opposite_row(*plane))
                ^ correction;
        }
        Ok(())
    }
}
