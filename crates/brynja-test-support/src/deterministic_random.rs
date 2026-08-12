//! Deterministic and fault-injecting secure-random engine for tests only.
//!
//! This module is not cryptographically secure. Its containing package is
//! permanently unpublished and mechanically prohibited from production
//! dependency graphs.

use brynja_core::{
    EntropyFailureKind, RandomStateDestruction, RawEntropy, SecretRegionInitialization,
    SecureRandomEngine, SecureRandomRequest, SecurityStrength, clear_owned_region,
};

/// One fault injected into the next matching operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DeterministicFault {
    /// Perform the next operation normally.
    None,
    /// Fail the next generate call before writing.
    RetryGenerate,
    /// Write one byte, then fail the next generate call retryably.
    PartialRetryGenerate,
    /// Fail the next generate call permanently.
    PermanentGenerate,
    /// Return success after deliberately underfilling the next output.
    UnderfillGenerate,
    /// Fail the next reseed call retryably.
    RetryReseed,
    /// Fail the next reseed call permanently.
    PermanentReseed,
    /// Report failed destruction.
    DestructionFailure,
}

/// Repository-only deterministic engine with explicit one-shot faults.
///
/// The engine is neither cloneable nor formattable. It is suitable only for
/// repeatable state-machine tests; it makes no entropy, security, or FIPS claim.
pub struct DeterministicRandom {
    state: [u8; 32],
    counter: u64,
    cursor: usize,
    fault: DeterministicFault,
    initialized: bool,
    drop_failure_observed: bool,
}

impl DeterministicRandom {
    /// Creates an uninitialized deterministic test engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: [0; 32],
            counter: 0,
            cursor: 0,
            fault: DeterministicFault::None,
            initialized: false,
            drop_failure_observed: false,
        }
    }

    /// Replaces the one-shot fault selected for the next matching operation.
    pub fn inject(&mut self, fault: DeterministicFault) {
        self.fault = fault;
    }

    /// Reports whether the mandatory drop-failure hook ran.
    #[must_use]
    pub const fn drop_failure_observed(&self) -> bool {
        self.drop_failure_observed
    }

    fn absorb(&mut self, entropy: &RawEntropy<'_>) {
        for (destination, source) in self.state.iter_mut().zip(entropy.expose().iter().cycle()) {
            *destination = *source;
        }
        self.counter = 0;
        self.cursor = 0;
        self.initialized = true;
    }

    fn next_byte(&mut self) -> Result<u8, EntropyFailureKind> {
        let counter_bytes = self.counter.to_le_bytes();
        let state_byte = match self.state.get_mut(self.cursor) {
            Some(value) => value,
            None => return Err(EntropyFailureKind::Permanent),
        };
        let counter_index = self.cursor & 7;
        let counter_byte = match counter_bytes.get(counter_index) {
            Some(value) => *value,
            None => return Err(EntropyFailureKind::Permanent),
        };
        let output = *state_byte ^ counter_byte;
        *state_byte = state_byte.rotate_left(1) ^ counter_byte ^ 0x5a;
        self.cursor = if self.cursor == 31 {
            self.counter = self.counter.wrapping_add(1);
            0
        } else {
            self.cursor.saturating_add(1)
        };
        Ok(output)
    }

    fn clear_state(&mut self) -> RandomStateDestruction {
        let result = clear_owned_region(&mut self.state);
        self.counter = 0;
        self.cursor = 0;
        self.initialized = false;
        if result.is_err() || self.fault == DeterministicFault::DestructionFailure {
            RandomStateDestruction::Failed
        } else {
            RandomStateDestruction::Complete
        }
    }
}

impl Default for DeterministicRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureRandomEngine for DeterministicRandom {
    fn maximum_strength(&self) -> SecurityStrength {
        SecurityStrength::Bits256
    }

    fn instantiate(&mut self, entropy: &RawEntropy<'_>) -> Result<(), EntropyFailureKind> {
        self.absorb(entropy);
        Ok(())
    }

    fn generate(
        &mut self,
        request: SecureRandomRequest,
        output: &mut SecretRegionInitialization<'_>,
    ) -> Result<(), EntropyFailureKind> {
        if !self.initialized {
            return Err(EntropyFailureKind::Permanent);
        }
        let fault = self.fault;
        self.fault = DeterministicFault::None;
        match fault {
            DeterministicFault::RetryGenerate => return Err(EntropyFailureKind::Retryable),
            DeterministicFault::PermanentGenerate => {
                return Err(EntropyFailureKind::Permanent);
            }
            DeterministicFault::PartialRetryGenerate => {
                let byte = self.next_byte()?;
                output
                    .write(&[byte])
                    .map_err(|_| EntropyFailureKind::Permanent)?;
                return Err(EntropyFailureKind::Retryable);
            }
            _ => {}
        }
        let count = if fault == DeterministicFault::UnderfillGenerate {
            request.bytes().saturating_sub(1)
        } else {
            request.bytes()
        };
        for _ in 0..count {
            let byte = self.next_byte()?;
            output
                .write(&[byte])
                .map_err(|_| EntropyFailureKind::Permanent)?;
        }
        Ok(())
    }

    fn reseed(&mut self, entropy: &RawEntropy<'_>) -> Result<(), EntropyFailureKind> {
        let fault = self.fault;
        self.fault = DeterministicFault::None;
        match fault {
            DeterministicFault::RetryReseed => Err(EntropyFailureKind::Retryable),
            DeterministicFault::PermanentReseed => Err(EntropyFailureKind::Permanent),
            _ => {
                self.absorb(entropy);
                Ok(())
            }
        }
    }

    fn uninstantiate(&mut self) -> RandomStateDestruction {
        self.clear_state()
    }

    fn handle_drop_failure(&mut self) {
        self.drop_failure_observed = true;
    }
}

impl Drop for DeterministicRandom {
    fn drop(&mut self) {
        let _completion = clear_owned_region(&mut self.state);
        self.counter = 0;
        self.cursor = 0;
        self.initialized = false;
    }
}
