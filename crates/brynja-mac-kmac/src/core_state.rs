use brynja_core::clear_owned_region;
use brynja_hash_sha3::Fips202BitString;

use crate::{
    backend::CshakeState,
    error::KmacError,
    packer::{absorb_key, append_right_encode},
    policy::{KmacKeyPolicy, key_policy},
};

const FULL_STRENGTH: u8 = 1;

pub(crate) struct KmacCore<S, const RATE: usize, const STRENGTH: u128> {
    state: Option<S>,
    metadata: KmacMetadata,
}

impl<S: CshakeState, const RATE: usize, const STRENGTH: u128> KmacCore<S, RATE, STRENGTH> {
    pub(crate) fn new_bits(
        key: Fips202BitString<'_>,
        customization: Fips202BitString<'_>,
        require_full_strength: bool,
    ) -> Result<Self, KmacError> {
        let key_bits = u128::try_from(key.bit_len()).map_err(|_| KmacError::MessageTooLong)?;
        let policy = key_policy(key_bits, STRENGTH);
        if require_full_strength && policy != KmacKeyPolicy::FullStrength {
            return Err(KmacError::KeyTooShort);
        }
        let mut state = S::new_kmac(customization).map_err(KmacError::from)?;
        absorb_key(&mut state, key, RATE)?;
        Ok(Self {
            state: Some(state),
            metadata: KmacMetadata::new(policy),
        })
    }

    pub(crate) fn key_policy(&self) -> KmacKeyPolicy {
        self.metadata.key_policy()
    }

    pub(crate) fn message_bytes(&self) -> u128 {
        self.metadata.message_bytes()
    }

    pub(crate) fn check_additional_bytes(&self, additional: u128) -> Result<(), KmacError> {
        self.message_bytes()
            .checked_add(additional)
            .ok_or(KmacError::MessageTooLong)?;
        self.state_ref()?
            .check_additional_bytes(additional)
            .map_err(KmacError::from)
    }

    pub(crate) fn update(&mut self, input: &[u8]) -> Result<(), KmacError> {
        let additional = u128::try_from(input.len()).map_err(|_| KmacError::MessageTooLong)?;
        let updated = self
            .message_bytes()
            .checked_add(additional)
            .ok_or(KmacError::MessageTooLong)?;
        self.state_ref()?
            .check_additional_bytes(additional)
            .map_err(KmacError::from)?;
        self.state_mut()?.update(input).map_err(KmacError::from)?;
        self.metadata.set_message_bytes(updated);
        Ok(())
    }

    pub(crate) fn finish_fixed(
        self,
        final_message: Option<Fips202BitString<'_>>,
        output_bits: u128,
        require_full_strength: bool,
    ) -> Result<S::Reader, KmacError> {
        if require_full_strength && self.key_policy() != KmacKeyPolicy::FullStrength {
            return Err(KmacError::KeyTooShort);
        }
        if require_full_strength && output_bits < STRENGTH {
            return Err(KmacError::TagTooShort);
        }
        let mut owner = self;
        append_right_encode(owner.take_state()?, final_message, output_bits)
    }

    pub(crate) fn finish_xof(
        self,
        final_message: Option<Fips202BitString<'_>>,
        require_full_strength: bool,
    ) -> Result<S::Reader, KmacError> {
        if require_full_strength && self.key_policy() != KmacKeyPolicy::FullStrength {
            return Err(KmacError::KeyTooShort);
        }
        let mut owner = self;
        append_right_encode(owner.take_state()?, final_message, 0)
    }

    fn state_ref(&self) -> Result<&S, KmacError> {
        self.state.as_ref().ok_or(KmacError::SecretMemory)
    }

    fn state_mut(&mut self) -> Result<&mut S, KmacError> {
        self.state.as_mut().ok_or(KmacError::SecretMemory)
    }

    fn take_state(&mut self) -> Result<S, KmacError> {
        self.state.take().ok_or(KmacError::SecretMemory)
    }
}

impl<S, const RATE: usize, const STRENGTH: u128> KmacCore<S, RATE, STRENGTH> {
    #[inline(never)]
    fn wipe(&mut self) {
        drop(self.state.take());
        self.metadata.wipe();
    }
}

impl<S, const RATE: usize, const STRENGTH: u128> Drop for KmacCore<S, RATE, STRENGTH> {
    fn drop(&mut self) {
        self.wipe();
    }
}

struct KmacMetadata {
    message_length: [u8; 16],
    key_class: [u8; 1],
}

impl KmacMetadata {
    fn new(policy: KmacKeyPolicy) -> Self {
        Self {
            message_length: [0; 16],
            key_class: [u8::from(policy == KmacKeyPolicy::FullStrength)],
        }
    }

    fn key_policy(&self) -> KmacKeyPolicy {
        if self.key_class.first().copied() == Some(FULL_STRENGTH) {
            KmacKeyPolicy::FullStrength
        } else {
            KmacKeyPolicy::ConformanceOnly
        }
    }

    fn message_bytes(&self) -> u128 {
        u128::from_le_bytes(self.message_length)
    }

    fn set_message_bytes(&mut self, value: u128) {
        self.message_length.copy_from_slice(&value.to_le_bytes());
    }

    fn wipe(&mut self) {
        let _ = clear_owned_region(&mut self.message_length);
        let _ = clear_owned_region(&mut self.key_class);
    }
}

impl Drop for KmacMetadata {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
pub(crate) mod assurance_contract {
    use super::{KmacCore, KmacKeyPolicy, KmacMetadata};

    #[test]
    fn registered_algorithm_kmac_owner_contract_is_compiler_checked() {
        let mut owner = KmacCore::<(), 168, 128> {
            state: Some(()),
            metadata: KmacMetadata::new(KmacKeyPolicy::FullStrength),
        };
        owner.metadata.message_length.fill(0xa5);
        owner.wipe();
        assert!(owner.state.is_none());
        assert!(owner.metadata.message_length.iter().all(|byte| *byte == 0));
        assert!(owner.metadata.key_class.iter().all(|byte| *byte == 0));
    }
}
