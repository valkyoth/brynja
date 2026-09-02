use brynja_core::clear_owned_region;

pub(crate) const ABSORBING: u8 = 0;
pub(crate) const FINALIZING: u8 = 1;

/// Complete crate-owned storage for every hardened SHA-2 identity.
pub(crate) struct HardenedSha2Owner {
    pub(crate) chaining_state: [u8; 64],
    pub(crate) partial_input: [u8; 128],
    pub(crate) message_length: [u8; 16],
    pub(crate) phase: [u8; 2],
    pub(crate) message_schedule: [u8; 640],
    pub(crate) block_copy: [u8; 128],
    pub(crate) padding_block: [u8; 128],
    pub(crate) output_staging: [u8; 64],
}

impl HardenedSha2Owner {
    pub(crate) fn new32(initial: [u32; 8]) -> Self {
        let mut owner = Self::empty();
        for (destination, word) in owner.chaining_state.chunks_exact_mut(4).zip(initial) {
            destination.copy_from_slice(&word.to_be_bytes());
        }
        owner
    }

    pub(crate) fn new64(initial: [u64; 8]) -> Self {
        let mut owner = Self::empty();
        for (destination, word) in owner.chaining_state.chunks_exact_mut(8).zip(initial) {
            destination.copy_from_slice(&word.to_be_bytes());
        }
        owner
    }

    fn empty() -> Self {
        Self {
            chaining_state: [0; 64],
            partial_input: [0; 128],
            message_length: [0; 16],
            phase: [ABSORBING, 0],
            message_schedule: [0; 640],
            block_copy: [0; 128],
            padding_block: [0; 128],
            output_staging: [0; 64],
        }
    }

    pub(crate) fn buffer_len(&self) -> usize {
        usize::from(self.phase[1])
    }

    pub(crate) fn set_buffer_len(&mut self, length: usize) {
        self.phase[1] = u8::try_from(length).unwrap_or(0);
    }

    pub(crate) fn staged(&self, length: usize) -> Option<&[u8]> {
        self.output_staging.get(..length)
    }

    pub(crate) fn wipe_compression_scratch(&mut self) {
        let _ = clear_owned_region(&mut self.message_schedule);
        let _ = clear_owned_region(&mut self.block_copy);
    }

    #[inline(never)]
    pub(crate) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.chaining_state);
        let _ = clear_owned_region(&mut self.partial_input);
        let _ = clear_owned_region(&mut self.message_length);
        let _ = clear_owned_region(&mut self.phase);
        let _ = clear_owned_region(&mut self.message_schedule);
        let _ = clear_owned_region(&mut self.block_copy);
        let _ = clear_owned_region(&mut self.padding_block);
        let _ = clear_owned_region(&mut self.output_staging);
    }
}

impl Drop for HardenedSha2Owner {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
pub(crate) mod assurance_contract {
    use super::HardenedSha2Owner;

    #[test]
    fn registered_algorithm_sha2_owner_contract_is_compiler_checked() {
        let mut owner = HardenedSha2Owner::new32([0x55aa_aa55; 8]);
        owner.partial_input.fill(0xa5);
        owner.message_schedule.fill(0x5a);
        owner.wipe();
        assert!(owner.chaining_state.iter().all(|byte| *byte == 0));
        assert!(owner.partial_input.iter().all(|byte| *byte == 0));
        assert!(owner.message_schedule.iter().all(|byte| *byte == 0));
    }
}
