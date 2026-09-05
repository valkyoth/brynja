use brynja_core::clear_owned_region;

// All source-owned arrays containing input or derived material live here.
// Compression scalar temporaries retain the documented register/spill risk.
pub(crate) struct Sha1Owner {
    pub(crate) chaining_state: [u8; 20],
    pub(crate) block: [u8; 64],
    pub(crate) schedule: [u8; 320],
    pub(crate) message_length: [u8; 8],
    pub(crate) buffered: [u8; 1],
    pub(crate) output_staging: [u8; 20],
}

impl Sha1Owner {
    pub(crate) const fn new() -> Self {
        Self {
            chaining_state: [
                0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32,
                0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0,
            ],
            block: [0; 64],
            schedule: [0; 320],
            message_length: [0; 8],
            buffered: [0; 1],
            output_staging: [0; 20],
        }
    }

    pub(crate) fn bits(&self) -> u64 {
        u64::from_be_bytes(self.message_length)
    }

    pub(crate) fn buffered(&self) -> usize {
        let [count] = self.buffered;
        usize::from(count)
    }

    pub(crate) fn clear_block(&mut self) {
        let _ = clear_owned_region(&mut self.block);
        let _ = clear_owned_region(&mut self.schedule);
        let _ = clear_owned_region(&mut self.buffered);
    }

    #[inline(never)]
    pub(crate) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.chaining_state);
        let _ = clear_owned_region(&mut self.block);
        let _ = clear_owned_region(&mut self.schedule);
        let _ = clear_owned_region(&mut self.message_length);
        let _ = clear_owned_region(&mut self.buffered);
        let _ = clear_owned_region(&mut self.output_staging);
    }
}

impl Drop for Sha1Owner {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod assurance_contract {
    use super::Sha1Owner;

    #[test]
    fn registered_algorithm_sha1_owner_contract_is_compiler_checked() {
        let mut owner = Sha1Owner::new();
        owner.chaining_state.fill(0xa5);
        owner.block.fill(0xa5);
        owner.schedule.fill(0xa5);
        owner.message_length.fill(0xa5);
        owner.buffered.fill(0xa5);
        owner.output_staging.fill(0xa5);
        owner.wipe();
        assert_eq!(owner.chaining_state, [0; 20]);
        assert_eq!(owner.block, [0; 64]);
        assert_eq!(owner.schedule, [0; 320]);
        assert_eq!(owner.message_length, [0; 8]);
        assert_eq!(owner.buffered, [0; 1]);
        assert_eq!(owner.output_staging, [0; 20]);
    }
}
