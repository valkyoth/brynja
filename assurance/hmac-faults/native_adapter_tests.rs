//! Private native test module nested under execution, never shipped.
extern crate std;

use super::{
    Authority, Kernel,
    adapter::Adapter,
    backends::{Backend, Source},
};
use crate::*;

fn exercise<'a, A: super::Algorithm<'a>>(owner: &'a Authority, bits: A::FinalInput<'_>) -> usize {
    crate::adapter_tests::adapter_with::<Adapter<'a, A>>(bits, || {
        <A as Backend<'a>>::create(Source::Static(owner))
    })
}

#[test]
fn real_native_adapter_handoffs() {
    let route = std::env::var("BRYNJA_HMAC_ADAPTER_KERNEL").expect("explicit native route");
    // Build-feature assertions only: the driver must first run host_probe.rs
    // built separately WITHOUT these features. Detection macros here can fold
    // to true because this crate intentionally enables the required features.
    #[cfg(target_arch = "x86_64")]
    let kernel = match route.as_str() {
        "sha256" => {
            assert!(std::is_x86_feature_detected!("sha") && std::is_x86_feature_detected!("sse2"));
            Kernel::X86Sha256
        }
        "sha512" => {
            assert!(
                std::is_x86_feature_detected!("sha512")
                    && std::is_x86_feature_detected!("avx2")
                    && std::is_x86_feature_detected!("avx")
            );
            Kernel::X86Sha512
        }
        "keccak" => {
            assert!(std::is_x86_feature_detected!("avx2"));
            Kernel::X86Keccak
        }
        _ => panic!("unknown route"),
    };
    #[cfg(target_arch = "aarch64")]
    let kernel = match route.as_str() {
        "sha256" => {
            assert!(
                std::arch::is_aarch64_feature_detected!("sha2")
                    && std::arch::is_aarch64_feature_detected!("neon")
            );
            Kernel::ArmSha256
        }
        "sha512" | "keccak" => {
            assert!(
                std::arch::is_aarch64_feature_detected!("sha3")
                    && std::arch::is_aarch64_feature_detected!("neon")
            );
            if route == "sha512" {
                Kernel::ArmSha512
            } else {
                Kernel::ArmKeccak
            }
        }
        _ => panic!("unknown route"),
    };
    let owner = Authority::new(kernel).expect("required compiled native authority");
    let sha2 = Sha2BitString::new(&[0x80], 1).expect("canonical");
    let sha3 = Fips202BitString::new(&[1], 1).expect("canonical");
    let (cases, expected) = match route.as_str() {
        "sha256" => (
            exercise::<Sha224>(&owner, sha2) + exercise::<Sha256>(&owner, sha2),
            24,
        ),
        "sha512" => (
            exercise::<Sha384>(&owner, sha2)
                + exercise::<Sha512>(&owner, sha2)
                + exercise::<Sha512_224>(&owner, sha2)
                + exercise::<Sha512_256>(&owner, sha2)
                + exercise::<Sha512T<129>>(&owner, sha2)
                + exercise::<Sha512T<511>>(&owner, sha2),
            72,
        ),
        "keccak" => (
            exercise::<Sha3_224>(&owner, sha3)
                + exercise::<Sha3_256>(&owner, sha3)
                + exercise::<Sha3_384>(&owner, sha3)
                + exercise::<Sha3_512>(&owner, sha3),
            48,
        ),
        _ => panic!("unknown route"),
    };
    assert_eq!(cases, expected);
    std::println!("HMAC_NATIVE_ADAPTER_HANDOFF: {route} {cases}");
}
