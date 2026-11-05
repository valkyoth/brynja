// FIPS 197 sections 4 and 5. State is column-major. Indexing and loops depend
// only on public fixed-size positions/direction, never keys or block contents.
use super::{Error, Scratch};

fn read(bytes: &[u8], index: usize) -> Result<u8, Error> {
    bytes.get(index).copied().ok_or(Error::SecretMemory)
}
fn write(bytes: &mut [u8], index: usize, value: u8) -> Result<(), Error> {
    *bytes.get_mut(index).ok_or(Error::SecretMemory)? = value;
    Ok(())
}

mod field;
mod layout;
pub(super) mod wide;
use field::{inv_sbox, multiply, sbox, xtime};

pub(super) fn expand(key: &[u8], schedule: &mut [u8; 176]) -> Result<(), Error> {
    if key.len() != 16 {
        return Err(Error::SecretMemory);
    }
    schedule
        .get_mut(..16)
        .ok_or(Error::SecretMemory)?
        .copy_from_slice(key);
    let mut word = Scratch::<4>::new();
    #[cfg(test)]
    super::tests::expansion_checkpoint()?;
    let mut rcon = 1;
    for offset in (16usize..176).step_by(4) {
        for (i, byte) in word.0.iter_mut().enumerate() {
            *byte = read(schedule, offset.wrapping_sub(4).wrapping_add(i))?;
        }
        if offset % 16 == 0 {
            word.0.rotate_left(1);
            for byte in &mut word.0 {
                *byte = sbox(*byte);
            }
            *word.0.first_mut().ok_or(Error::SecretMemory)? ^= rcon;
            rcon = xtime(rcon);
        }
        for (i, byte) in word.0.iter().enumerate() {
            let value = read(schedule, offset.wrapping_sub(16).wrapping_add(i))? ^ byte;
            write(schedule, offset.wrapping_add(i), value)?;
        }
        #[cfg(test)]
        super::tests::expansion_checkpoint()?;
    }
    Ok(())
}

fn add_key(state: &mut [u8; 16], schedule: &[u8; 176], round: usize) -> Result<(), Error> {
    for (i, byte) in state.iter_mut().enumerate() {
        *byte ^= read(schedule, layout::round_key_index(round, i))?;
    }
    #[cfg(test)]
    super::tests::checkpoint()?;
    Ok(())
}
fn substitute(state: &mut [u8; 16], inverse: bool) {
    for byte in state {
        *byte = if inverse {
            inv_sbox(*byte)
        } else {
            sbox(*byte)
        };
    }
}
fn shift(state: &mut [u8; 16], inverse: bool) -> Result<(), Error> {
    let mut previous = Scratch::<16>::new();
    previous.0.copy_from_slice(state);
    for (i, byte) in state.iter_mut().enumerate() {
        *byte = read(&previous.0, layout::shift_source(i, inverse))?;
    }
    Ok(())
}
fn mix(state: &mut [u8; 16], inverse: bool) {
    for [a, b, c, d] in state.as_chunks_mut::<4>().0 {
        // Scalar compiler/register copies are not covered by scratch Drop.
        let (x, y, z, w) = (*a, *b, *c, *d);
        if inverse {
            *a = multiply(x, 14) ^ multiply(y, 11) ^ multiply(z, 13) ^ multiply(w, 9);
            *b = multiply(x, 9) ^ multiply(y, 14) ^ multiply(z, 11) ^ multiply(w, 13);
            *c = multiply(x, 13) ^ multiply(y, 9) ^ multiply(z, 14) ^ multiply(w, 11);
            *d = multiply(x, 11) ^ multiply(y, 13) ^ multiply(z, 9) ^ multiply(w, 14);
        } else {
            *a = multiply(x, 2) ^ multiply(y, 3) ^ z ^ w;
            *b = x ^ multiply(y, 2) ^ multiply(z, 3) ^ w;
            *c = x ^ y ^ multiply(z, 2) ^ multiply(w, 3);
            *d = multiply(x, 3) ^ y ^ z ^ multiply(w, 2);
        }
    }
}

pub(super) fn transform(
    state: &mut [u8; 16],
    schedule: &[u8; 176],
    inverse: bool,
) -> Result<(), Error> {
    if inverse {
        add_key(state, schedule, 10)?;
        for round in (1..10).rev() {
            shift(state, true)?;
            substitute(state, true);
            add_key(state, schedule, round)?;
            mix(state, true);
        }
        shift(state, true)?;
        substitute(state, true);
        add_key(state, schedule, 0)
    } else {
        add_key(state, schedule, 0)?;
        for round in 1..10 {
            substitute(state, false);
            shift(state, false)?;
            mix(state, false);
            add_key(state, schedule, round)?;
        }
        substitute(state, false);
        shift(state, false)?;
        add_key(state, schedule, 10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn field_and_substitution_exhaustive() {
        assert_eq!(multiply(0x57, 0x13), 0xfe); // FIPS 197 section 4.2.
        assert_eq!(sbox(0), 0x63);
        assert_eq!(sbox(0x53), 0xed);
        for a in 0..=u8::MAX {
            assert_eq!(multiply(a, field::inverse(a)), u8::from(a != 0));
            assert_eq!(inv_sbox(sbox(a)), a);
            assert_eq!(sbox(inv_sbox(a)), a);
        }
    }
    #[test]
    fn linear_steps_are_inverse_on_every_single_byte() -> Result<(), Error> {
        for position in 0..16 {
            for byte in 0..=u8::MAX {
                let mut state = [0; 16];
                write(&mut state, position, byte)?;
                let original = state;
                shift(&mut state, false)?;
                shift(&mut state, true)?;
                assert_eq!(state, original);
                mix(&mut state, false);
                mix(&mut state, true);
                assert_eq!(state, original);
            }
        }
        Ok(())
    }
}
