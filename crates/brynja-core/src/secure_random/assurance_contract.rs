use super::{SecureRandom, SecureRandomEngine};

#[allow(dead_code)]
fn owner_shape<E: SecureRandomEngine>(owner: &SecureRandom<E>) {
    let SecureRandom {
        engine,
        config,
        runtime,
        requests_since_reseed,
        fork_reseed_required,
        permanent_failure,
    } = owner;
    let _ = (
        engine,
        config,
        runtime,
        requests_since_reseed,
        fork_reseed_required,
        permanent_failure,
    );
}

#[allow(dead_code)]
fn exact_sanitizer<E: SecureRandomEngine>(engine: &mut E) {
    let _ = <E as SecureRandomEngine>::uninstantiate(engine);
}

#[test]
fn secure_random_owner_contract_is_compiler_checked() {
    assert_eq!(core::mem::size_of::<super::RandomStateDestruction>(), 1);
}
