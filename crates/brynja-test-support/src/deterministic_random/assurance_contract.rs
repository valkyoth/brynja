use super::DeterministicRandom;

fn owner_shape(owner: &DeterministicRandom) {
    let DeterministicRandom {
        state,
        counter,
        cursor,
        fault,
        initialized,
        destruction_failure_observed,
    } = owner;
    let _ = (
        state,
        counter,
        cursor,
        fault,
        initialized,
        destruction_failure_observed,
    );
}

#[test]
fn deterministic_random_owner_contract_is_compiler_checked() {
    let _shape: fn(&DeterministicRandom) = owner_shape;
    let _sanitizer = brynja_core::clear_owned_region;
}
