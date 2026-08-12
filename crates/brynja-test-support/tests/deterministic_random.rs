//! Deterministic secure-random fixture and injected-failure tests.

use brynja_core::{
    EntropyFailureStage, EntropyPurpose, RandomPurpose, RandomRuntimeGeneration, RawEntropy,
    RawEntropyRequest, SecretRegionInitialization, SecureRandom, SecureRandomConfig,
    SecureRandomError, SecureRandomRequest, SecurityStrength,
};
use brynja_test_support::{DeterministicFault, DeterministicRandom};

fn entropy<'a>(bytes: &'a mut [u8; 32], purpose: EntropyPurpose) -> RawEntropy<'a> {
    let mut initialization = match SecretRegionInitialization::begin(bytes) {
        Ok(value) => value,
        Err(_) => return unreachable_for_test(),
    };
    assert_eq!(initialization.write(&[0x42; 32]), Ok(()));
    let owner = match initialization.finish() {
        Ok(value) => value,
        Err(_) => return unreachable_for_test(),
    };
    let request = match RawEntropyRequest::new(SecurityStrength::Bits256, purpose, 32) {
        Ok(value) => value,
        Err(_) => return unreachable_for_test(),
    };
    match request.bind(owner) {
        Ok(value) => value,
        Err(_) => unreachable_for_test(),
    }
}

fn request() -> SecureRandomRequest {
    match SecureRandomRequest::new(SecurityStrength::Bits256, RandomPurpose::KeyGeneration, 32) {
        Ok(value) => value,
        Err(_) => unreachable_for_test(),
    }
}

fn config() -> SecureRandomConfig {
    match SecureRandomConfig::new(SecurityStrength::Bits256, 4) {
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
fn equal_inputs_produce_equal_output_without_production_randomness() {
    let mut first_seed = [7; 32];
    let mut second_seed = [9; 32];
    let mut first = match SecureRandom::instantiate(
        DeterministicRandom::new(),
        config(),
        RandomRuntimeGeneration::initial(),
        entropy(&mut first_seed, EntropyPurpose::Instantiation),
    ) {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    let mut second = match SecureRandom::instantiate(
        DeterministicRandom::new(),
        config(),
        RandomRuntimeGeneration::initial(),
        entropy(&mut second_seed, EntropyPurpose::Instantiation),
    ) {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    let mut first_output = [0; 32];
    let mut second_output = [0; 32];
    let first_owner = match first.generate(
        RandomRuntimeGeneration::initial(),
        request(),
        &mut first_output,
    ) {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    let second_owner = match second.generate(
        RandomRuntimeGeneration::initial(),
        request(),
        &mut second_output,
    ) {
        Ok(value) => value,
        Err(_) => return assert!(core::hint::black_box(false)),
    };
    assert_eq!(first_owner.expose(), second_owner.expose());
}

#[test]
fn injected_partial_and_terminal_faults_are_fail_closed() {
    for (fault, expected) in [
        (
            DeterministicFault::PartialRetryGenerate,
            SecureRandomError::Retryable(EntropyFailureStage::Generate),
        ),
        (
            DeterministicFault::PermanentGenerate,
            SecureRandomError::Permanent(EntropyFailureStage::Generate),
        ),
        (
            DeterministicFault::UnderfillGenerate,
            SecureRandomError::Permanent(EntropyFailureStage::Generate),
        ),
    ] {
        let mut seed = [7; 32];
        let mut engine = DeterministicRandom::new();
        engine.inject(fault);
        let mut random = match SecureRandom::instantiate(
            engine,
            config(),
            RandomRuntimeGeneration::initial(),
            entropy(&mut seed, EntropyPurpose::Instantiation),
        ) {
            Ok(value) => value,
            Err(_) => return assert!(core::hint::black_box(false)),
        };
        let mut output = [0x55; 32];
        let error =
            match random.generate(RandomRuntimeGeneration::initial(), request(), &mut output) {
                Err(value) => value,
                Ok(owner) => {
                    drop(owner);
                    return assert!(core::hint::black_box(false));
                }
            };
        assert_eq!(error, expected);
        assert_eq!(output, [0; 32]);
    }
}
