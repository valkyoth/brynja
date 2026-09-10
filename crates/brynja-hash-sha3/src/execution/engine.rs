use super::{Error, Execution, Report};
use crate::{
    Fips202BitString,
    keccak::{byte, xor_byte},
};

// Only public-data working state is cloned for transactional admission.
// No hardened owner or secret-bearing construction may enter this module.
#[derive(Clone)]
pub(super) struct State<const RATE: usize> {
    lanes: [u64; 25],
    position: usize,
    pub(super) message_bytes: u128,
    pub(super) output_bytes: u128,
    pub(super) report: Report,
}

impl<const RATE: usize> State<RATE> {
    pub(super) fn new(route: super::Route) -> Self {
        Self {
            lanes: [0; 25],
            position: 0,
            message_bytes: 0,
            output_bytes: 0,
            report: Report::new(route),
        }
    }

    pub(super) fn check_bytes(current: u128, additional: u128) -> Result<u128, Error> {
        current.checked_add(additional).ok_or(Error::LengthOverflow)
    }

    pub(super) fn check_bits(current: u128, bits: u128) -> Result<(), Error> {
        Self::check_bytes(current, bits / 8).map(|_| ())
    }

    pub(super) fn update(&mut self, execution: &Execution<'_>, input: &[u8]) -> Result<(), Error> {
        execution.check()?;
        let length = Self::check_bytes(self.message_bytes, input.len() as u128)?;
        let mut candidate = self.clone();
        for value in input {
            xor_byte(&mut candidate.lanes, candidate.position, *value);
            candidate.position = candidate
                .position
                .checked_add(1)
                .ok_or(Error::LengthOverflow)?;
            if candidate.position == RATE {
                candidate.permute(execution, 0)?;
                candidate.position = 0;
            }
        }
        candidate.message_bytes = length;
        *self = candidate;
        Ok(())
    }

    // phase 0 = absorb, 1 = padding, 2 = squeeze; private closed call sites.
    fn permute(&mut self, execution: &Execution<'_>, phase: u8) -> Result<(), Error> {
        let count = match phase {
            0 => &mut self.report.absorb_permutations,
            1 => &mut self.report.padding_permutations,
            _ => &mut self.report.squeeze_permutations,
        };
        let next = count.checked_add(1).ok_or(Error::LengthOverflow)?;
        execution.permute(&mut self.lanes)?;
        *count = next;
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        execution: &Execution<'_>,
        input: Fips202BitString<'_>,
        suffix: u8,
        width: u8,
    ) -> Result<(), Error> {
        execution.check()?;
        Self::check_bits(self.message_bytes, input.bit_len() as u128)?;
        let (complete, partial) = input.split();
        self.update(execution, complete)?;
        let mut bit_position = self.position.checked_mul(8).ok_or(Error::LengthOverflow)?;
        let rate_bits = RATE.checked_mul(8).ok_or(Error::LengthOverflow)?;
        if let Some((value, bits)) = partial {
            xor_byte(&mut self.lanes, self.position, value);
            bit_position = bit_position
                .checked_add(usize::from(bits))
                .ok_or(Error::LengthOverflow)?;
        }
        for offset in 0..width {
            if bit_position == rate_bits {
                self.permute(execution, 1)?;
                bit_position = 0;
            }
            if suffix & (1_u8 << offset) != 0 {
                xor_byte(
                    &mut self.lanes,
                    bit_position / 8,
                    1_u8 << (bit_position % 8),
                );
            }
            bit_position = bit_position.checked_add(1).ok_or(Error::LengthOverflow)?;
        }
        if bit_position == rate_bits {
            self.permute(execution, 1)?;
        }
        xor_byte(&mut self.lanes, RATE.saturating_sub(1), 0x80);
        self.permute(execution, 1)?;
        self.position = 0;
        Ok(())
    }

    pub(super) fn digest<const N: usize>(&self) -> [u8; N] {
        let mut output = [0; N];
        for (position, target) in output.iter_mut().enumerate() {
            *target = byte(&self.lanes, position);
        }
        output
    }

    pub(super) fn squeeze(
        &mut self,
        execution: &Execution<'_>,
        output: &mut [u8],
        scratch: &mut [u8],
        valid: u8,
    ) -> Result<(), Error> {
        execution.check()?;
        let scratch = scratch
            .get_mut(..output.len())
            .ok_or(Error::ScratchTooSmall)?;
        let partial = !output.is_empty() && valid < 8;
        let complete = if partial {
            output.len().saturating_sub(1)
        } else {
            output.len()
        };
        let length = Self::check_bytes(self.output_bytes, complete as u128)?;
        let mut candidate = self.clone();
        for target in scratch.iter_mut() {
            if candidate.position == RATE {
                candidate.permute(execution, 2)?;
                candidate.position = 0;
            }
            *target = byte(&candidate.lanes, candidate.position);
            candidate.position = candidate
                .position
                .checked_add(1)
                .ok_or(Error::LengthOverflow)?;
        }
        if partial && let Some(last) = scratch.last_mut() {
            *last &= u8::MAX >> 8_u8.saturating_sub(valid);
        }
        candidate.output_bytes = length;
        // No fallible operations remain after this public-output commit point.
        output.copy_from_slice(scratch);
        *self = candidate;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_permutation_failure_does_not_commit_absorb_or_output() {
        let mut state = State::<136>::new(super::super::Route::Portable);
        assert!(state.update(&Execution::fault_after(1), &[7; 400]).is_err());
        assert_eq!(state.lanes, [0; 25]);
        assert_eq!(state.message_bytes, 0);
        assert_eq!(state.report.absorb_permutations, 0);
        let mut destination = [0xa5; 500];
        let mut scratch = [0xa5; 500];
        assert!(
            state
                .squeeze(
                    &Execution::fault_after(1),
                    &mut destination,
                    &mut scratch,
                    8
                )
                .is_err()
        );
        assert_eq!(destination, [0xa5; 500]);
        assert_eq!(state.lanes, [0; 25]);
        assert_eq!(state.output_bytes, 0);
        assert_eq!(state.report.squeeze_permutations, 0);
        assert_ne!(scratch, [0xa5; 500]);
    }

    #[test]
    fn overflow_preserves_state_output_and_accounting() {
        let execution = Execution::portable();
        let mut state = State::<136>::new(execution.route());
        state.message_bytes = u128::MAX;
        assert_eq!(state.update(&execution, b"x"), Err(Error::LengthOverflow));
        assert_eq!(state.message_bytes, u128::MAX);
        assert_eq!(state.lanes, [0; 25]);
        state.output_bytes = u128::MAX;
        let mut output = [0xa5; 1];
        assert_eq!(
            state.squeeze(&execution, &mut output, &mut [0; 1], 8),
            Err(Error::LengthOverflow)
        );
        assert_eq!(output, [0xa5]);
        state.report.absorb_permutations = u128::MAX;
        state.message_bytes = 0;
        assert_eq!(
            state.update(&execution, &[1; 136]),
            Err(Error::LengthOverflow)
        );
        assert_eq!(state.lanes, [0; 25]);
        assert_eq!(state.message_bytes, 0);
    }
}
