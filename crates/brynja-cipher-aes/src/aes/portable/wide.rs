// FIPS 197-upd1 sections 5.1–5.3, Algorithms 1–3. These private
// instantiations admit only (24,208,12) and (32,240,14); no user-defined AES.
use super::{Error, Scratch, layout, mix, read, sbox, shift, substitute, write, xtime};

use layout::valid_wide_parameters as valid_parameters;

pub(in crate::aes) fn expand<const K: usize, const S: usize, const R: usize>(
    key: &[u8],
    schedule: &mut [u8; S],
) -> Result<(), Error> {
    const { assert!(valid_parameters(K, S, R)) };
    if key.len() != K {
        return Err(Error::SecretMemory);
    }
    schedule
        .get_mut(..K)
        .ok_or(Error::SecretMemory)?
        .copy_from_slice(key);
    let mut word = Scratch::<4>::new();
    #[cfg(test)]
    crate::aes::tests::expansion_checkpoint()?;
    let mut rcon = 1;
    for offset in (K..S).step_by(4) {
        for (i, byte) in word.0.iter_mut().enumerate() {
            *byte = read(schedule, layout::prior_word_index(offset, 4, i))?;
        }
        let position = offset.checked_rem(K).ok_or(Error::SecretMemory)?;
        if position == 0 {
            word.0.rotate_left(1);
            for byte in &mut word.0 {
                *byte = sbox(*byte);
            }
            *word.0.first_mut().ok_or(Error::SecretMemory)? ^= rcon;
            rcon = xtime(rcon);
        } else if K == 32 && position == 16 {
            // AES-256 only: SubWord without RotWord or Rcon at i mod Nk = 4.
            for byte in &mut word.0 {
                *byte = sbox(*byte);
            }
        }
        for (i, byte) in word.0.iter().enumerate() {
            let value = read(schedule, layout::prior_word_index(offset, K, i))? ^ byte;
            write(schedule, layout::word_byte_index(offset, i), value)?;
        }
        #[cfg(test)]
        crate::aes::tests::expansion_checkpoint()?;
    }
    Ok(())
}

fn add_key(state: &mut [u8; 16], schedule: &[u8], round: usize) -> Result<(), Error> {
    for (i, byte) in state.iter_mut().enumerate() {
        *byte ^= read(schedule, layout::round_key_index(round, i))?;
    }
    #[cfg(test)]
    crate::aes::tests::checkpoint()?;
    Ok(())
}

pub(in crate::aes) fn transform<const K: usize, const S: usize, const R: usize>(
    state: &mut [u8; 16],
    schedule: &[u8; S],
    inverse: bool,
) -> Result<(), Error> {
    const { assert!(valid_parameters(K, S, R)) };
    if inverse {
        add_key(state, schedule, R)?;
        for round in (1..R).rev() {
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
        for round in 1..R {
            substitute(state, false);
            shift(state, false)?;
            mix(state, false);
            add_key(state, schedule, round)?;
        }
        substitute(state, false);
        shift(state, false)?;
        add_key(state, schedule, R)
    }
}
