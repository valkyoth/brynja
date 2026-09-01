use super::SanitizedSecret;

fn owner_shape<const N: usize>(owner: &SanitizedSecret<N>) {
    let SanitizedSecret { inner } = owner;
    let _ = inner;
}

#[test]
fn sanitized_secret_owner_contract_is_compiler_checked() {
    let _shape: fn(&SanitizedSecret<1>) = owner_shape::<1>;
    let _sanitizer: fn(SanitizedSecret<1>) = SanitizedSecret::<1>::clear;
}
