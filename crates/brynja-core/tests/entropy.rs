//! Entropy and initialized secure-random state-machine tests.

use core::cell::Cell;

use brynja_core::{
    EntropyContractError, EntropyFailureKind, EntropyFailureStage, EntropyPurpose,
    MAX_RANDOM_REQUEST_BYTES, MAX_RESEED_INTERVAL, RandomPurpose, RandomRuntimeGeneration,
    RandomStateDestruction, RawEntropy, RawEntropyRequest, SecretRegionInitialization,
    SecureRandom, SecureRandomConfig, SecureRandomEngine, SecureRandomError, SecureRandomRequest,
    SecurityStrength,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Behavior {
    Success,
    RetryInstantiate,
    PermanentInstantiate,
    RetryGenerate,
    PermanentGenerate,
    Underfill,
    RetryReseed,
    PermanentReseed,
}

struct Metrics {
    instantiate: Cell<u32>,
    generate: Cell<u32>,
    reseed: Cell<u32>,
    destroy: Cell<u32>,
    destruction_failure: Cell<u32>,
}

impl Metrics {
    const fn new() -> Self {
        Self {
            instantiate: Cell::new(0),
            generate: Cell::new(0),
            reseed: Cell::new(0),
            destroy: Cell::new(0),
            destruction_failure: Cell::new(0),
        }
    }
}

struct Engine<'a> {
    metrics: &'a Metrics,
    behavior: Behavior,
    destruction: RandomStateDestruction,
}

impl Engine<'_> {
    fn increment(cell: &Cell<u32>) {
        cell.set(cell.get().saturating_add(1));
    }
}

impl SecureRandomEngine for Engine<'_> {
    fn maximum_strength(&self) -> SecurityStrength {
        SecurityStrength::Bits256
    }

    fn instantiate(&mut self, _: &RawEntropy<'_>) -> Result<(), EntropyFailureKind> {
        Self::increment(&self.metrics.instantiate);
        match self.behavior {
            Behavior::RetryInstantiate => Err(EntropyFailureKind::Retryable),
            Behavior::PermanentInstantiate => Err(EntropyFailureKind::Permanent),
            _ => Ok(()),
        }
    }

    fn generate(
        &mut self,
        request: SecureRandomRequest,
        output: &mut SecretRegionInitialization<'_>,
    ) -> Result<(), EntropyFailureKind> {
        Self::increment(&self.metrics.generate);
        if self.behavior == Behavior::RetryGenerate {
            output
                .write(&[0x55])
                .map_err(|_| EntropyFailureKind::Permanent)?;
            return Err(EntropyFailureKind::Retryable);
        }
        if self.behavior == Behavior::PermanentGenerate {
            return Err(EntropyFailureKind::Permanent);
        }
        let count = if self.behavior == Behavior::Underfill {
            request.bytes().saturating_sub(1)
        } else {
            request.bytes()
        };
        for _ in 0..count {
            output
                .write(&[0xa6])
                .map_err(|_| EntropyFailureKind::Permanent)?;
        }
        Ok(())
    }

    fn reseed(&mut self, _: &RawEntropy<'_>) -> Result<(), EntropyFailureKind> {
        Self::increment(&self.metrics.reseed);
        match self.behavior {
            Behavior::RetryReseed => Err(EntropyFailureKind::Retryable),
            Behavior::PermanentReseed => Err(EntropyFailureKind::Permanent),
            _ => Ok(()),
        }
    }

    fn uninstantiate(&mut self) -> RandomStateDestruction {
        Self::increment(&self.metrics.destroy);
        self.destruction
    }

    fn handle_destruction_failure(&mut self) {
        Self::increment(&self.metrics.destruction_failure);
    }
}

fn engine<'a>(metrics: &'a Metrics, behavior: Behavior) -> Engine<'a> {
    Engine {
        metrics,
        behavior,
        destruction: RandomStateDestruction::Complete,
    }
}

fn raw_entropy<'a>(
    bytes: &'a mut [u8],
    purpose: EntropyPurpose,
    strength: SecurityStrength,
) -> RawEntropy<'a> {
    let length = bytes.len();
    let mut initialization = match SecretRegionInitialization::begin(bytes) {
        Ok(value) => value,
        Err(_) => return unreachable_for_test(),
    };
    for _ in 0..length {
        assert_eq!(initialization.write(&[0x39]), Ok(()));
    }
    let owner = match initialization.finish() {
        Ok(value) => value,
        Err(_) => return unreachable_for_test(),
    };
    let request = match RawEntropyRequest::new(strength, purpose, length) {
        Ok(value) => value,
        Err(_) => return unreachable_for_test(),
    };
    match request.bind(owner) {
        Ok(value) => value,
        Err(_) => unreachable_for_test(),
    }
}

fn config(interval: u64) -> SecureRandomConfig {
    match SecureRandomConfig::new(SecurityStrength::Bits256, interval) {
        Ok(value) => value,
        Err(_) => unreachable_for_test(),
    }
}

fn request(bytes: usize) -> SecureRandomRequest {
    match SecureRandomRequest::new(
        SecurityStrength::Bits256,
        RandomPurpose::KeyGeneration,
        bytes,
    ) {
        Ok(value) => value,
        Err(_) => unreachable_for_test(),
    }
}

fn state<'a>(
    metrics: &'a Metrics,
    behavior: Behavior,
    interval: u64,
    seed: &mut [u8; 32],
) -> SecureRandom<Engine<'a>> {
    let entropy = raw_entropy(
        seed,
        EntropyPurpose::Instantiation,
        SecurityStrength::Bits256,
    );
    match SecureRandom::instantiate(
        engine(metrics, behavior),
        config(interval),
        RandomRuntimeGeneration::initial(),
        entropy,
    ) {
        Ok(value) => value,
        Err(_) => unreachable_for_test(),
    }
}

fn unreachable_for_test<T>() -> T {
    assert!(core::hint::black_box(false), "unreachable test state");
    loop {
        core::hint::spin_loop();
    }
}

#[test]
fn reject_invalid_and_exhausted() {
    assert_eq!(SecurityStrength::Bits128.minimum_bytes(), 16);
    assert_eq!(SecurityStrength::Bits192.minimum_bytes(), 24);
    assert_eq!(SecurityStrength::Bits256.minimum_bytes(), 32);
    assert!(matches!(
        RawEntropyRequest::new(SecurityStrength::Bits256, EntropyPurpose::Instantiation, 31),
        Err(EntropyContractError::InsufficientInputCapacity)
    ));
    assert!(matches!(
        RawEntropyRequest::new(SecurityStrength::Bits128, EntropyPurpose::Reseed, 0),
        Err(EntropyContractError::EmptyInput)
    ));
    assert!(matches!(
        SecureRandomRequest::new(
            SecurityStrength::Bits128,
            RandomPurpose::Nonce,
            MAX_RANDOM_REQUEST_BYTES.saturating_add(1)
        ),
        Err(EntropyContractError::RequestTooLarge)
    ));
    assert!(matches!(
        SecureRandomConfig::new(SecurityStrength::Bits128, 0),
        Err(EntropyContractError::InvalidReseedInterval)
    ));
    assert!(SecureRandomConfig::new(SecurityStrength::Bits128, MAX_RESEED_INTERVAL).is_ok());
}

#[test]
fn raw_binding_is_exact_and_failed_binding_clears() {
    let mut bytes = [0x55; 32];
    let owner = {
        let mut initialization = match SecretRegionInitialization::begin(&mut bytes) {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        };
        assert_eq!(initialization.write(&[0x22; 32]), Ok(()));
        match initialization.finish() {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        }
    };
    let wrong = match RawEntropyRequest::new(
        SecurityStrength::Bits128,
        EntropyPurpose::Instantiation,
        16,
    ) {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    assert!(matches!(
        wrong.bind(owner),
        Err(EntropyContractError::LengthMismatch)
    ));
    assert_eq!(bytes, [0_u8; 32]);
}

#[test]
fn rejected_and_failed_instantiation_destroy_engine_state() {
    for (behavior, expected) in [
        (
            Behavior::RetryInstantiate,
            SecureRandomError::Retryable(EntropyFailureStage::Instantiate),
        ),
        (
            Behavior::PermanentInstantiate,
            SecureRandomError::Permanent(EntropyFailureStage::Instantiate),
        ),
    ] {
        let metrics = Metrics::new();
        let mut seed = [9; 32];
        let result = SecureRandom::instantiate(
            engine(&metrics, behavior),
            config(1),
            RandomRuntimeGeneration::initial(),
            raw_entropy(
                &mut seed,
                EntropyPurpose::Instantiation,
                SecurityStrength::Bits256,
            ),
        );
        let error = match result {
            Err(value) => value,
            Ok(random) => {
                drop(random);
                return assert!(core::hint::black_box(false));
            }
        };
        assert_eq!(error, expected);
        assert_eq!(metrics.instantiate.get(), 1);
        assert_eq!(metrics.destroy.get(), 1);
        assert_eq!(seed, [0; 32]);
    }
}

#[test]
fn contract() {
    let metrics = Metrics::new();
    let mut seed = [9; 32];
    let mut random = state(&metrics, Behavior::Success, 1, &mut seed);
    assert_eq!(seed, [0; 32]);
    let mut output = [0x55; 4];
    {
        let owner =
            match random.generate(RandomRuntimeGeneration::initial(), request(4), &mut output) {
                Ok(value) => value,
                Err(_) => return assert!(core::hint::black_box(false)),
            };
        assert_eq!(owner.expose(), &[0xa6; 4]);
    }
    assert_eq!(output, [0; 4]);
    assert_eq!(random.requests_since_reseed(), 1);
    assert!(matches!(
        random.generate(RandomRuntimeGeneration::initial(), request(4), &mut output),
        Err(SecureRandomError::ReseedRequired)
    ));
    assert_eq!(metrics.generate.get(), 1);
}

#[test]
fn output_mismatch_and_retry_clear_without_advancing() {
    let metrics = Metrics::new();
    let mut seed = [9; 32];
    let mut random = state(&metrics, Behavior::RetryGenerate, 3, &mut seed);
    let mut output = [0x55; 4];
    assert!(matches!(
        random.generate(RandomRuntimeGeneration::initial(), request(3), &mut output),
        Err(SecureRandomError::Contract(
            EntropyContractError::LengthMismatch
        ))
    ));
    assert_eq!(metrics.generate.get(), 0);
    assert_eq!(output, [0; 4]);
    assert!(matches!(
        random.generate(RandomRuntimeGeneration::initial(), request(4), &mut output),
        Err(SecureRandomError::Retryable(EntropyFailureStage::Generate))
    ));
    assert_eq!(output, [0; 4]);
    assert_eq!(random.requests_since_reseed(), 0);
}

#[test]
fn underfill_and_permanent_fault_destroy_and_latch() {
    for behavior in [Behavior::Underfill, Behavior::PermanentGenerate] {
        let metrics = Metrics::new();
        let mut seed = [9; 32];
        let mut random = state(&metrics, behavior, 3, &mut seed);
        let mut output = [0x55; 4];
        assert!(matches!(
            random.generate(RandomRuntimeGeneration::initial(), request(4), &mut output),
            Err(SecureRandomError::Permanent(EntropyFailureStage::Generate))
        ));
        assert_eq!(output, [0; 4]);
        assert_eq!(metrics.destroy.get(), 1);
        assert!(matches!(
            random.generate(RandomRuntimeGeneration::initial(), request(4), &mut output),
            Err(SecureRandomError::Permanent(EntropyFailureStage::Generate))
        ));
        assert_eq!(metrics.generate.get(), 1);
    }
}

#[test]
fn fork_and_reseed_transitions_fail_closed() {
    let metrics = Metrics::new();
    let mut seed = [9; 32];
    let mut random = state(&metrics, Behavior::Success, 3, &mut seed);
    let next = match RandomRuntimeGeneration::initial().next() {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    assert_eq!(random.mark_fork(next), Ok(()));
    let mut output = [0x55; 4];
    assert!(matches!(
        random.generate(next, request(4), &mut output),
        Err(SecureRandomError::ForkReseedRequired)
    ));
    let mut reseed_bytes = [7; 32];
    let entropy = raw_entropy(
        &mut reseed_bytes,
        EntropyPurpose::Reseed,
        SecurityStrength::Bits256,
    );
    assert_eq!(random.reseed(next, entropy), Ok(()));
    assert_eq!(metrics.reseed.get(), 1);
    assert!(random.generate(next, request(4), &mut output).is_ok());
}

#[test]
fn wrong_entropy_never_reaches_engine_and_rollback_is_terminal() {
    let metrics = Metrics::new();
    let mut seed = [9; 32];
    let mut random = state(&metrics, Behavior::Success, 3, &mut seed);
    let mut wrong_bytes = [7; 32];
    let wrong = raw_entropy(
        &mut wrong_bytes,
        EntropyPurpose::Instantiation,
        SecurityStrength::Bits256,
    );
    assert!(matches!(
        random.reseed(RandomRuntimeGeneration::initial(), wrong),
        Err(SecureRandomError::Contract(
            EntropyContractError::PurposeMismatch
        ))
    ));
    assert_eq!(metrics.reseed.get(), 0);
    let next = match RandomRuntimeGeneration::initial().next() {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    assert_eq!(random.mark_fork(next), Ok(()));
    assert!(matches!(
        random.mark_fork(RandomRuntimeGeneration::initial()),
        Err(SecureRandomError::RuntimeRollback)
    ));
    assert_eq!(metrics.destroy.get(), 1);
}

#[test]
fn retryable_and_permanent_reseed_preserve_closed_semantics() {
    for (behavior, expected) in [
        (
            Behavior::RetryReseed,
            SecureRandomError::Retryable(EntropyFailureStage::Reseed),
        ),
        (
            Behavior::PermanentReseed,
            SecureRandomError::Permanent(EntropyFailureStage::Reseed),
        ),
    ] {
        let metrics = Metrics::new();
        let mut seed = [9; 32];
        let mut random = state(&metrics, behavior, 3, &mut seed);
        let mut reseed_bytes = [7; 32];
        let entropy = raw_entropy(
            &mut reseed_bytes,
            EntropyPurpose::Reseed,
            SecurityStrength::Bits256,
        );
        assert_eq!(
            random.reseed(RandomRuntimeGeneration::initial(), entropy),
            Err(expected)
        );
        let expected_destroy = u32::from(behavior == Behavior::PermanentReseed);
        assert_eq!(metrics.destroy.get(), expected_destroy);
    }
}

#[test]
fn explicit_and_drop_destruction_are_observable() {
    let metrics = Metrics::new();
    let mut seed = [9; 32];
    let random = state(&metrics, Behavior::Success, 3, &mut seed);
    assert_eq!(random.uninstantiate(), Ok(()));
    assert_eq!(metrics.destroy.get(), 1);

    for explicit in [true, false] {
        let failed_metrics = Metrics::new();
        let mut failed_seed = [9; 32];
        let failed_engine = Engine {
            metrics: &failed_metrics,
            behavior: Behavior::Success,
            destruction: RandomStateDestruction::Failed,
        };
        let entropy = raw_entropy(
            &mut failed_seed,
            EntropyPurpose::Instantiation,
            SecurityStrength::Bits256,
        );
        let random = match SecureRandom::instantiate(
            failed_engine,
            config(3),
            RandomRuntimeGeneration::initial(),
            entropy,
        ) {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        };
        if explicit {
            assert!(random.uninstantiate().is_err());
        } else {
            drop(random);
        }
        assert_eq!(failed_metrics.destroy.get(), 1);
        assert_eq!(failed_metrics.destruction_failure.get(), 1);
    }
}

#[test]
fn every_random_purpose_is_representable() {
    for purpose in [
        RandomPurpose::KeyGeneration,
        RandomPurpose::Nonce,
        RandomPurpose::ProtocolRandom,
        RandomPurpose::Blinding,
        RandomPurpose::Padding,
    ] {
        let value = SecureRandomRequest::new(SecurityStrength::Bits128, purpose, 1);
        assert!(value.is_ok());
    }
}
