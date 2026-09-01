use super::{SecretInitialization, SecretState};
use crate::SecretDestructor;

#[allow(dead_code)]
fn initialization_shape<D: SecretDestructor>(owner: &SecretInitialization<'_, D>) {
    let SecretInitialization {
        expected,
        initialized,
        targets,
        destructor,
    } = owner;
    let _ = (expected, initialized, targets, destructor);
}

#[allow(dead_code)]
fn state_shape<D: SecretDestructor>(owner: &SecretState<'_, D>) {
    let SecretState {
        targets,
        destructor,
    } = owner;
    let _ = (targets, destructor);
}

#[allow(dead_code)]
fn exact_sanitizer<D: SecretDestructor>(destructor: &mut D) {
    let _ = crate::secret_destruction::run_destruction(
        destructor,
        crate::DestructionTargets::local_memory(),
        crate::DestructionCause::Drop,
    );
}

#[test]
fn abstract_secret_owner_contract_is_compiler_checked() {
    assert!(!crate::DestructionTargets::local_memory().is_empty());
}
