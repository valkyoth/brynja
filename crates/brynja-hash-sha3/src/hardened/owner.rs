use brynja_core::clear_owned_region;

pub(crate) const ABSORBING: u8 = 0;
pub(crate) const SQUEEZING: u8 = 1;
pub(crate) const MAX_RATE: usize = 168;

/// Complete crate-owned storage for hardened FIPS 202 operations.
pub(crate) struct HardenedFips202Owner<const RATE: usize> {
    pub(crate) sponge_lanes: [u8; 200],
    pub(crate) partial_input: [u8; MAX_RATE],
    pub(crate) message_length: [u8; 16],
    pub(crate) output_length: [u8; 16],
    pub(crate) cshake_setup_length: [u8; 16],
    pub(crate) cshake_domain: [u8; 1],
    pub(crate) phase: [u8; 3],
    pub(crate) suffix_staging: [u8; 4],
    pub(crate) padding_block: [u8; MAX_RATE],
    pub(crate) squeeze_staging: [u8; MAX_RATE],
    pub(crate) permutation_columns: [u8; 40],
    pub(crate) permutation_theta: [u8; 40],
    pub(crate) permutation_rearranged: [u8; 200],
}

impl<const RATE: usize> HardenedFips202Owner<RATE> {
    pub(crate) fn new() -> Self {
        Self {
            sponge_lanes: [0; 200],
            partial_input: [0; MAX_RATE],
            message_length: [0; 16],
            output_length: [0; 16],
            cshake_setup_length: [0; 16],
            cshake_domain: [0; 1],
            phase: [ABSORBING, 0, 0],
            suffix_staging: [0; 4],
            padding_block: [0; MAX_RATE],
            squeeze_staging: [0; MAX_RATE],
            permutation_columns: [0; 40],
            permutation_theta: [0; 40],
            permutation_rearranged: [0; 200],
        }
    }

    pub(crate) fn buffer_len(&self) -> usize {
        usize::from(self.phase[1])
    }

    pub(crate) fn set_buffer_len(&mut self, value: usize) {
        self.phase[1] = u8::try_from(value).unwrap_or(0);
    }

    pub(crate) fn squeeze_position(&self) -> usize {
        usize::from(self.phase[2])
    }

    pub(crate) fn set_squeeze_position(&mut self, value: usize) {
        self.phase[2] = u8::try_from(value).unwrap_or(0);
    }

    pub(crate) fn remember_cshake_setup(&mut self, customized: bool) {
        self.cshake_setup_length
            .copy_from_slice(&self.message_length);
        self.cshake_domain[0] = u8::from(customized);
    }

    pub(crate) fn cshake_is_customized(&self) -> bool {
        self.cshake_domain[0] == 1
    }

    pub(crate) fn wipe_cshake_metadata(&mut self) {
        let _ = clear_owned_region(&mut self.cshake_setup_length);
        let _ = clear_owned_region(&mut self.cshake_domain);
    }

    pub(crate) fn wipe_permutation_scratch(&mut self) {
        let _ = clear_owned_region(&mut self.permutation_columns);
        let _ = clear_owned_region(&mut self.permutation_theta);
        let _ = clear_owned_region(&mut self.permutation_rearranged);
    }

    pub(crate) fn wipe_staging(&mut self) {
        let _ = clear_owned_region(&mut self.padding_block);
        let _ = clear_owned_region(&mut self.squeeze_staging);
        let _ = clear_owned_region(&mut self.suffix_staging);
    }

    #[inline(never)]
    pub(crate) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.sponge_lanes);
        let _ = clear_owned_region(&mut self.partial_input);
        let _ = clear_owned_region(&mut self.message_length);
        let _ = clear_owned_region(&mut self.output_length);
        let _ = clear_owned_region(&mut self.cshake_setup_length);
        let _ = clear_owned_region(&mut self.cshake_domain);
        let _ = clear_owned_region(&mut self.phase);
        let _ = clear_owned_region(&mut self.suffix_staging);
        let _ = clear_owned_region(&mut self.padding_block);
        let _ = clear_owned_region(&mut self.squeeze_staging);
        let _ = clear_owned_region(&mut self.permutation_columns);
        let _ = clear_owned_region(&mut self.permutation_theta);
        let _ = clear_owned_region(&mut self.permutation_rearranged);
    }
}

impl<const RATE: usize> Drop for HardenedFips202Owner<RATE> {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
pub(crate) mod assurance_contract {
    use super::HardenedFips202Owner;

    #[test]
    fn registered_algorithm_sha3_shake_owner_contract_is_compiler_checked() {
        let mut owner = HardenedFips202Owner::<136>::new();
        owner.sponge_lanes.fill(0xa5);
        owner.partial_input.fill(0x5a);
        owner.message_length.fill(0x11);
        owner.output_length.fill(0x22);
        owner.cshake_setup_length.fill(0x2a);
        owner.cshake_domain.fill(0x2b);
        owner.phase.fill(0x33);
        owner.suffix_staging.fill(0x44);
        owner.padding_block.fill(0x55);
        owner.squeeze_staging.fill(0x66);
        owner.permutation_columns.fill(0x77);
        owner.permutation_theta.fill(0x88);
        owner.permutation_rearranged.fill(0x96);
        owner.wipe();
        assert!(owner.sponge_lanes.iter().all(|byte| *byte == 0));
        assert!(owner.partial_input.iter().all(|byte| *byte == 0));
        assert!(owner.message_length.iter().all(|byte| *byte == 0));
        assert!(owner.output_length.iter().all(|byte| *byte == 0));
        assert!(owner.cshake_setup_length.iter().all(|byte| *byte == 0));
        assert!(owner.cshake_domain.iter().all(|byte| *byte == 0));
        assert!(owner.phase.iter().all(|byte| *byte == 0));
        assert!(owner.suffix_staging.iter().all(|byte| *byte == 0));
        assert!(owner.padding_block.iter().all(|byte| *byte == 0));
        assert!(owner.squeeze_staging.iter().all(|byte| *byte == 0));
        assert!(owner.permutation_columns.iter().all(|byte| *byte == 0));
        assert!(owner.permutation_theta.iter().all(|byte| *byte == 0));
        assert!(owner.permutation_rearranged.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn exhausted_counters_reject_work_without_mutation() {
        let mut owner = HardenedFips202Owner::<136>::new();
        owner.message_length.fill(0xff);
        owner.output_length.fill(0xff);
        let message_before = owner.message_length;
        let output_before = owner.output_length;

        assert_eq!(owner.check_message_bytes(1), Err(()));
        assert_eq!(owner.check_message_bits(8), Err(()));
        assert_eq!(owner.check_output_bytes(1), Err(()));
        assert_eq!(owner.check_output_bits(8), Err(()));
        assert_eq!(owner.message_length, message_before);
        assert_eq!(owner.output_length, output_before);
    }

    #[test]
    fn cshake_metadata_is_owned_and_cleared_independently() {
        let mut owner = HardenedFips202Owner::<136>::new();
        owner.message_length[0] = 136;
        owner.remember_cshake_setup(true);
        assert!(owner.cshake_is_customized());
        assert_eq!(owner.cshake_setup_length[0], 136);

        owner.wipe_cshake_metadata();
        assert!(!owner.cshake_is_customized());
        assert!(owner.cshake_setup_length.iter().all(|byte| *byte == 0));
        assert!(owner.cshake_domain.iter().all(|byte| *byte == 0));
    }
}
