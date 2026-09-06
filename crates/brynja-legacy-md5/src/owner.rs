use brynja_core::clear_owned_region;

// All source-owned arrays containing input or derived material live here.
// Compression scalar temporaries retain the documented register/spill risk.
pub(crate) struct Md5Owner {
    pub(crate) chaining_state: [u8; 16],
    pub(crate) block: [u8; 64],
    pub(crate) message_length: [u8; 16],
    pub(crate) buffered: [u8; 1],
    pub(crate) output_staging: [u8; 16],
}

impl Md5Owner {
    pub(crate) const fn new() -> Self {
        Self {
            chaining_state: [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10,
            ],
            block: [0; 64],
            message_length: [0; 16],
            buffered: [0; 1],
            output_staging: [0; 16],
        }
    }

    pub(crate) fn bits(&self) -> u128 {
        u128::from_be_bytes(self.message_length)
    }

    pub(crate) fn buffered(&self) -> usize {
        let [count] = self.buffered;
        usize::from(count)
    }

    pub(crate) fn clear_block(&mut self) {
        let _ = clear_owned_region(&mut self.block);
        let _ = clear_owned_region(&mut self.buffered);
    }

    #[inline(never)]
    pub(crate) fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.chaining_state);
        let _ = clear_owned_region(&mut self.block);
        let _ = clear_owned_region(&mut self.message_length);
        let _ = clear_owned_region(&mut self.buffered);
        let _ = clear_owned_region(&mut self.output_staging);
    }
}

impl Drop for Md5Owner {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod assurance_contract {
    use super::Md5Owner;

    #[test]
    fn registered_algorithm_md5_owner_contract_is_compiler_checked() {
        let mut owner = Md5Owner::new();
        owner.chaining_state.fill(0xa5);
        owner.block.fill(0xa5);
        owner.message_length.fill(0xa5);
        owner.buffered.fill(0xa5);
        owner.output_staging.fill(0xa5);
        owner.wipe();
        assert_eq!(owner.chaining_state, [0; 16]);
        assert_eq!(owner.block, [0; 64]);
        assert_eq!(owner.message_length, [0; 16]);
        assert_eq!(owner.buffered, [0; 1]);
        assert_eq!(owner.output_staging, [0; 16]);
    }
}
