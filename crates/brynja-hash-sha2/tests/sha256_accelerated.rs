//! Compile-time-selected no_std backend differential tests.

#![cfg(feature = "cpu")]

use brynja_hash_sha2::{Sha256, Sha256BackendSession, sha256};

#[test]
fn statically_proven_backend_matches_scalar_when_available() {
    let selected = Sha256BackendSession::for_compiled_target();
    #[cfg(all(target_arch = "riscv64", target_feature = "zknh"))]
    assert!(
        selected.is_some(),
        "Zknh build did not select its exact backend"
    );
    let Some(backend) = selected else {
        return;
    };
    let mut content = [0_u8; 193];
    for (index, byte) in content.iter_mut().enumerate() {
        *byte = u8::try_from(index % 239).unwrap_or(0);
    }
    for length in [0_usize, 1, 55, 56, 63, 64, 65, 127, 128, 192, 193] {
        let Some(input) = content.get(..length) else {
            continue;
        };
        let scalar = sha256(input);
        assert!(scalar.is_ok());
        let Ok(scalar) = scalar else {
            continue;
        };
        for width in 1..=67 {
            let mut state = Sha256::new();
            for chunk in input.chunks(width) {
                assert_eq!(state.update_with_backend(chunk, &backend), Ok(()));
            }
            assert_eq!(state.finalize_with_backend(&backend), Ok(scalar));
        }
    }
}
