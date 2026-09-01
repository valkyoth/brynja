use super::RawEntropy;

fn owner_shape(owner: &RawEntropy<'_>) {
    let RawEntropy { request, input } = owner;
    let _ = request;
    let _ = input;
}

fn exact_drop(owner: crate::OwnedSecretRegion<'_>) {
    core::mem::drop(owner);
}

#[test]
fn raw_entropy_owner_contract_is_compiler_checked() {
    let _shape = owner_shape;
    let _drop = exact_drop;
}
