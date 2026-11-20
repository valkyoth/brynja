// Private functional workbench, not a fault-integrity owner. Raw fixture bytes
// are accepted here; future capture/retirement/release guards are not supplied.
use super::{Error, Planes, Scratch, read};

pub(super) struct Schedule {
    pub(super) keys: [Planes; 15],
    pub(super) rounds: usize,
}

impl Schedule {
    pub(super) fn new() -> Self {
        Self {
            keys: core::array::from_fn(|_| Planes::new()),
            rounds: 0,
        }
    }

    pub(super) fn expand(&mut self, key: &[u8]) -> Result<(), Error> {
        #[cfg(all(test, brynja_fault_evidence))]
        let _phase = super::corruption_tests::SubstitutionPhase::expansion();
        let words: usize = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            _ => return Err(Error::SecretMemory),
        };
        self.rounds = 0;
        for key in &mut self.keys {
            let _ = brynja_core::clear_owned_region(&mut key.0.0)?;
        }
        // Cyclic Nk-word history, not the primary's contiguous byte schedule.
        // Only round-key storage is retained, in bit-plane representation.
        let mut history = Scratch::<32>::new();
        history
            .0
            .get_mut(..key.len())
            .ok_or(Error::SecretMemory)?
            .copy_from_slice(key);
        let mut round = Scratch::<16>::new();
        let mut word = Scratch::<16>::new();
        let mut substituted = Planes::new();
        let rounds = words.wrapping_add(6);
        const RCON: [u8; 10] = [1, 2, 4, 8, 16, 32, 64, 128, 0x1b, 0x36];
        for index in 0..rounds.wrapping_add(1).wrapping_mul(4) {
            let position = index.checked_rem(words).ok_or(Error::SecretMemory)?;
            let slot = position.wrapping_mul(4);
            if index >= words {
                let prior = index
                    .wrapping_sub(1)
                    .checked_rem(words)
                    .ok_or(Error::SecretMemory)?
                    .wrapping_mul(4);
                word.0.fill(0);
                let rotated = position == 0;
                for byte in 0usize..4 {
                    let source = if rotated {
                        byte.wrapping_add(1) % 4
                    } else {
                        byte
                    };
                    *word.0.get_mut(byte).ok_or(Error::SecretMemory)? =
                        read(&history.0, prior.wrapping_add(source))?;
                }
                if rotated || (words == 8 && position == 4) {
                    substituted.load(&word.0)?;
                    substituted.substitute(false)?;
                    substituted.store(&mut word.0)?;
                }
                if rotated {
                    *word.0.first_mut().ok_or(Error::SecretMemory)? ^= read(
                        &RCON,
                        index
                            .checked_div(words)
                            .ok_or(Error::SecretMemory)?
                            .wrapping_sub(1),
                    )?;
                }
                for byte in 0usize..4 {
                    *history
                        .0
                        .get_mut(slot.wrapping_add(byte))
                        .ok_or(Error::SecretMemory)? ^= read(&word.0, byte)?;
                }
            }
            for byte in 0usize..4 {
                let position = (index % 4).wrapping_mul(4).wrapping_add(byte);
                *round.0.get_mut(position).ok_or(Error::SecretMemory)? =
                    read(&history.0, slot.wrapping_add(byte))?;
            }
            if index % 4 == 3 {
                self.keys
                    .get_mut(index / 4)
                    .ok_or(Error::SecretMemory)?
                    .load(&round.0)?;
            }
        }
        self.rounds = rounds;
        Ok(())
    }

    pub(super) fn transform(
        &self,
        input: &[u8; 16],
        output: &mut [u8; 16],
        inverse: bool,
    ) -> Result<(), Error> {
        #[cfg(all(test, brynja_fault_evidence))]
        let _phase = super::corruption_tests::SubstitutionPhase::transform();
        if !matches!(self.rounds, 10 | 12 | 14) {
            return Err(Error::SecretMemory);
        }
        let mut state = Planes::new();
        state.load(input)?;
        let first = if inverse { self.rounds } else { 0 };
        state.xor(self.keys.get(first).ok_or(Error::SecretMemory)?);
        for step in 1..=self.rounds {
            // Explicit source-evidence skip at one secondary substitution
            // call site. This changes test codegen and is NOT native S1 proof.
            #[cfg(all(test, brynja_fault_evidence))]
            let skip_substitution = evidence_tests::skip_substitution(step, inverse);
            #[cfg(not(all(test, brynja_fault_evidence)))]
            let skip_substitution = false;
            if inverse {
                state.shift_rows(true)?;
                if !skip_substitution {
                    state.substitute(true)?;
                }
                state.xor(
                    self.keys
                        .get(self.rounds.wrapping_sub(step))
                        .ok_or(Error::SecretMemory)?,
                );
                if step != self.rounds {
                    state.mix_columns(true)?;
                }
            } else {
                if !skip_substitution {
                    state.substitute(false)?;
                }
                state.shift_rows(false)?;
                if step != self.rounds {
                    state.mix_columns(false)?;
                }
                state.xor(self.keys.get(step).ok_or(Error::SecretMemory)?);
            }
        }
        state.store(output)
    }
}

#[cfg(all(test, brynja_fault_evidence))]
pub(super) mod evidence_tests;
