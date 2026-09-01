use super::{OwnedSecretRegion, SecretRegionInitialization};

fn initialization_shape(owner: &SecretRegionInitialization<'_>) {
    let SecretRegionInitialization {
        region,
        initialized,
    } = owner;
    let _: &Option<&mut [u8]> = region;
    let _: &usize = initialized;
}

fn readable_shape(owner: &OwnedSecretRegion<'_>) {
    let OwnedSecretRegion { region } = owner;
    let _: &Option<&mut [u8]> = region;
}

#[test]
fn secret_memory_owner_contract_is_compiler_checked() {
    let _initialization = initialization_shape;
    let _readable = readable_shape;
    let _sanitizer: fn(&mut [u8]) = crate::secret_memory_volatile::zeroize_region_volatile;
}
